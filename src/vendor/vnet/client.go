package vnet

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"packet"
	"strings"
	"sync"
	"time"

	"mylog"

	"github.com/juju/ratelimit"
)

const (
	HeadSize = 2

	HBRequest   = 0
	HBReply     = 1
	HearBeatReq = "HeartBeatReq" //len = 12
	HearBeatRpl = "HeartBeatRpl" //len = 12
	HearBeatLen = 12
	HBTimeout   = 90 //second

	KeepAliveIdle = 60
	KeepAliveCnt  = 3
	KeepAliveIntv = 5
)

var (
	tcMap    map[string]*Client
	ChanSize = flag.Int("chanSize", 4096, "chan Size")
	BindTun  = flag.Bool("bindtun", true, " conn bind tun")

	UpRateLimit   = flag.Int64("uprate", 0, "UpRateLimit, 0 means no limit")
	DownRateLimit = flag.Int64("downrate", 0, "DownRateLimit, 0 means no limit")
	DebugEn       = flag.Bool("DebugEn", false, "debug, show ip packet information")
)

type Client struct {
	cio       VnetIO
	pktchan   chan packet.Packet
	reconnect chan bool
	isClosed  bool
	p2p       bool
	peer      *Client
	sync.Mutex
	rx_bytes uint64
	tx_bytes uint64
	hbTimer  *time.Timer
}

type VnetIO interface {
	//Write(b []byte) (n int, err error)
	//Read(b []byte) (n int, err error)
	io.Writer
	io.Reader
	Close() error
	String() string
}

func init() {
	db := &Debug{}
	go http.ListenAndServe("localhost:18181", db)
	tcMap = make(map[string]*Client)
}

func NewClient(cio VnetIO) *Client {
	return &Client{
		cio:       cio,
		pktchan:   make(chan packet.Packet, *ChanSize),
		reconnect: make(chan bool, 1),
		isClosed:  false,
	}
}

func CreateConnClient(conn net.Conn) (*Client, error) {
	vc := NewVnetConn(conn)
	return NewClient(vc), nil
}

func CreateTunClient(auto bool) (*Client, error) {
	tun, err := OpenTun(*Br, *TunName, *TunType, *Ipstr, auto)
	if err != nil {
		return nil, err
	}
	ct := NewClient(tun)
	return ct, nil
}

func bindPairClient(c1, c2 *Client) {
	c1.p2p = true
	c2.p2p = true
	c1.peer = c2
	c2.peer = c1
}

func (c *Client) releasePeer() (peer *Client) {
	if c.peer == nil {
		return nil
	}
	peer = c.peer
	c.peer = nil
	peer.peer = nil
	return peer
}

func (c *Client) peerString() string {
	if c.peer == nil {
		return "nil"
	}
	return c.peer.String()
}

func HandleConn(conn net.Conn, isClient bool) {
	vcc, _ := CreateConnClient(conn)
	if *BindTun {
		//if is socket client, tun dev name should auto generate
		autoGenTunName := !isClient
		vtc, err := CreateTunClient(autoGenTunName)
		if err != nil {
			mylog.Error("%s, so Close %s", err.Error(), vcc.String())
			vcc.Close()
			return
		}
		mylog.Info("binding %s to %s", vtc.String(), vcc.String())
		bindPairClient(vcc, vtc)
		tcMap[vtc.cio.(*mytun).Name()] = vcc
		vtc.Working()
	} else {
		// add client to fdb
	}
	vcc.Working()

	//if is socket client, it means auto reconnect
	if isClient {
		<-vcc.reconnect
		close(vcc.reconnect)
		time.Sleep(time.Second * 2)
		mylog.Info("reconnecting %s\n", vcc.String())
	}
}

func (c *Client) Working() {
	go c.ReadForward()
	go c.WriteFromChan()
	go c.HeartBeat()
}

func (c *Client) PutPktToChan(pkt []byte) {
	if !c.IsClose() {
		c.pktchan <- pkt
	}
}

func (c *Client) String() string {
	if c.cio == nil {
		return fmt.Sprintf("Client cio is unknown")
	}
	return c.cio.String()
}

func (c *Client) IsClose() bool {
	return c.isClosed
}

func (c *Client) Close() error {
	c.Lock()
	if !c.isClosed {
		mylog.Notice("%s  is  closing, peer is %s\n", c.String(), c.peerString())
		c.isClosed = true
		c.Unlock()

		if c.hbTimer != nil {
			c.hbTimer.Reset(time.Millisecond * 10)
		}
		close(c.pktchan)
		c.cio.Close()

		if peer := c.releasePeer(); peer != nil {
			peer.Close()
		}
		mylog.Notice("%s is closed \n", c.String())
		return nil
	}
	c.Unlock()
	return errors.New("close a closed conn")
}

func (c *Client) Reconnect() {
	if err := c.Close(); err != nil {
		return
	}
	c.reconnect <- true
}

func (c *Client) ReadForward() {
	defer c.Reconnect()
	pkt := make(packet.Packet, 2048)

	var cr *bufio.Reader
	if *DownRateLimit != 0 {
		bk := ratelimit.NewBucketWithRate(float64(*DownRateLimit), int64(*DownRateLimit))
		rd := ratelimit.Reader(c.cio, bk)
		cr = bufio.NewReader(rd)
	} else {
		cr = bufio.NewReader(c.cio)
	}

	for {
		rn, err := cr.Read(pkt)
		if err != nil {
			mylog.Error("%s read fail:%s", c.String(), err.Error())
			if err.Error() == "vnetFilter" {
				mylog.Info("=======vnetFilter read again========\n")
				continue
			}
			return
		}
		if rn == HearBeatLen+HeadSize {
			if c.checkHeartBeat(pkt[HeadSize:rn]) {
				continue
			}
		}
		data := make([]byte, rn)
		copy(data, pkt[:rn])
		c.rx_bytes += uint64(rn)
		ForwardPkt(c, data)
	}
}

func (c *Client) WriteFromChan() {
	defer c.Close()
	var wd io.Writer
	if *UpRateLimit != 0 {
		bk := ratelimit.NewBucketWithRate(float64(*UpRateLimit), int64(*UpRateLimit))
		wd = ratelimit.Writer(c.cio, bk)
	} else {
		wd = c.cio
	}
	for pkt := range c.pktchan {
		wn, err := wd.Write(pkt)
		if err != nil {
			mylog.Error(" write to %s len=%d, err=%s\n", c.String(), wn, err.Error())
			return
		}
		c.tx_bytes += uint64(wn)
	}
	mylog.Notice(" %s WriteFromChan quit \n", c.String())
}

func (c *Client) checkHeartBeat(pkt []byte) bool {
	if strings.Compare(string(pkt), HearBeatReq) == 0 {
		mylog.Info("recv a heartbeat request from %s \n", c.String())
		//send heartbeat reply
		c.sendHeartBeat(HBReply)
		return true
	}
	if strings.Compare(string(pkt), HearBeatRpl) == 0 {
		mylog.Info("recv a heartbeat reply from %s\n", c.String())
		c.rx_bytes += uint64(HearBeatLen)
		//c.hbTimer.Reset(time.Second * time.Duration(HBTimeout))
		return true
	}
	return false
}

func (c *Client) HeartBeat() {
	if _, ok := c.cio.(*vnetConn); ok {
		timeout_count := 0
		c.hbTimer = time.NewTimer(time.Second * time.Duration(HBTimeout))
		defer c.Reconnect()
		defer c.hbTimer.Stop()

		for {
			if c.IsClose() {
				mylog.Notice(" %s is closed, HeartBeat quit\n", c.String())
				return
			}
			rx := c.rx_bytes
			mylog.Info("%s HeartBeat wait to timer up timeout_count =%d, c.rx_bytes=%d\n", c.String(), timeout_count, c.rx_bytes)
			<-c.hbTimer.C

			if c.IsClose() {
				mylog.Notice("==== %s is closed, HeartBeat quit ====\n", c.String())
				return
			}

			if rx == c.rx_bytes {
				if timeout_count >= 3 {
					mylog.Warning("=== %s HeartBeat quit:  timeout_count =%d, rx =%d, c.rx_bytes =%d =====\n", c.String(), timeout_count, rx, c.rx_bytes)
					return
				}
				//TODO send heartbeat requst packet
				mylog.Info("%d Second timeout, need to send HeartBeat request to %s, rx =%d, c.rx_bytes =%d\n", HBTimeout, c.String(), rx, c.rx_bytes)
				c.sendHeartBeat(HBRequest)
				c.hbTimer.Reset(time.Second * 5)
				timeout_count++
			} else {
				mylog.Info(" have received some pkt, no need to send HeartBeat to %s, rx =%d, c.rx_bytes =%d\n", c.String(), rx, c.rx_bytes)
				c.hbTimer.Reset(time.Second * time.Duration(HBTimeout))
				timeout_count = 0
			}
		}
	}

	if _, ok := c.cio.(*mytun); ok {
		//TODO
	}
}

func (c *Client) sendHeartBeat(hbType int) {
	hb := make([]byte, HearBeatLen+2)
	var sendstring string
	if hbType == HBRequest {
		//request
		if HearBeatLen != len(HearBeatReq) {
			log.Panicf("HearBeatLen =%d, len(%s) =%d \n", HearBeatLen, HearBeatReq, len(HearBeatReq))
		}
		copy(hb[2:], []byte(HearBeatReq))
		sendstring = "request"
	} else {
		//reply
		if HearBeatLen != len(HearBeatRpl) {
			log.Panicf("HearBeatLen =%d, len(%s) =%d \n", HearBeatLen, HearBeatRpl, len(HearBeatRpl))
		}
		copy(hb[2:], []byte(HearBeatRpl))
		sendstring = "reply"
	}
	binary.BigEndian.PutUint16(hb[:2], uint16(HearBeatLen))

	mylog.Info("put HeartBeat %s to %s pktChan, pktChan len=%d \n", sendstring, c.String(), len(c.pktchan))
	c.PutPktToChan(hb)
	mylog.Info("sending HeartBeat  %s for %s ok \n", sendstring, c.String())
}

func (c *Client) FwdToPeer(pkt []byte) {
	if c.peer != nil {
		c.peer.PutPktToChan(pkt)
	}
}

func ForwardPkt(c *Client, pkt []byte) {
	if c.p2p {
		c.FwdToPeer(pkt)
		return
	}
	//TODO FDB FORWARD
}

type Debug struct {
}

func (db *Debug) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case "/debug":
		*DebugEn = true
		log.Printf("set debug = true, *DebugEn=%v \n", *DebugEn)
		fmt.Fprintf(w, "set debug = true, *DebugEn=%v \n", *DebugEn)
	case "/nodebug":
		*DebugEn = false
		log.Printf("set debug = false, *DebugEn=%v \n", *DebugEn)
		fmt.Fprintf(w, "set debug = false, *DebugEn=%v \n", *DebugEn)
	case "/stat":
		var statstr string
		for devName, v := range tcMap {
			statstr += fmt.Sprintf("dev name %s: conn %s <-> %s, rx %d,tx %d bytes\n", devName, v.String(), v.rx_bytes, v.tx_bytes)
		}
		fmt.Fprintf(w, statstr)
		//fmt.Fprintf(w, "db.tun:rx %d,tx %d bytes\n db.cc:rx %d,tx %d bytes \n", db.tun.rx_bytes, db.tun.tx_bytes, db.cc.rx_bytes, db.cc.tx_bytes)
	default:
		fmt.Fprintf(w, "%s\n", "set /debug or /nodebug , or /stat")
	}
}
