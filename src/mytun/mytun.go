
package main

import (
	"github.com/lab11/go-tuntap/tuntap"
	"log"
	"fmt"
	"os/exec"
	//"encoding/binary"
	"flag"
	"net"
	"time"
	"io/ioutil"
	"packet"
	"mylog"
	"crypto/tls"
	"net/http"
	_"net/http/pprof"
	"reflect"
)

var (
	br = flag.String("br", ""," add tun/tap to bridge")
	tuntype = flag.Int("tuntype", int(tuntap.DevTap)," type, 1 means tap and 0 means tun")
	tunname = flag.String("tundev","tap0"," tun dev name")
	server = flag.String("server",":7878"," server like 203.156.34.98:7878")
	tlsEnable = flag.Bool("tls", false, "enable tls connect")
	pprofEnable = flag.Bool("pprof", false, "enable pprof, true or false")
	ppAddr = flag.String("ppaddr", ":7070", "ppaddr , http://xxxx:7070/debug/pprof/")
	chanSize = flag.Int("chanSize", 4096, "chan Size")
	lnAddr = flag.String("lnAddr",""," server like 203.156.34.98:7878")
	DebugEn = flag.Bool("DebugEn", false, "debug, show ip packet information")
)
/*
go tool pprof http://localhost:7070/debug/pprof/heap
go tool pprof http://localhost:7070/debug/pprof/profile
web
*/

func cmdexec (cmds string, checkErr bool){
	if !checkErr{
		exec.Command("sh", "-c", cmds).Run()
		return
	}
	cmd := exec.Command("sh", "-c", cmds)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Fatal(err)
	}

	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}

	slurp, _ := ioutil.ReadAll(stderr)
	fmt.Printf("%s\n", slurp)

	if err := cmd.Wait(); err != nil {
		log.Fatal(err)
	}
}

type myio interface {
	Open()
	Read()	
	PutPktToChan(pkt packet.Packet)
	WriteFromChan()
	//Write()
	//GetPeer()
	SetPeer( peer myio) bool
	IsClose() bool
}

type mytun struct {
	tund *tuntap.Interface
	pktchan chan packet.Packet
	peer myio	
}

type myconn struct {
	conn net.Conn
	pktchan chan packet.Packet
	writeQuit chan bool
	reconnect chan bool
	isClosed bool
	peer myio	
}

func NewTun() *mytun{
	return &mytun {
		pktchan : make(chan packet.Packet, *chanSize),
	}
}

func (tun *mytun) Open() {	
	var err error
	tun.tund, err = tuntap.Open(*tunname, tuntap.DevKind(*tuntype) , false)
	if err != nil {
		log.Fatal(err)
	}

	confs := fmt.Sprintf("ifconfig %s up\n", *tunname)
	if *br != "" {
		confs += fmt.Sprintf("brctl addif %s %s\n", *br, *tunname)
	}
	exec.Command("sh","-c", confs).Run()
	fmt.Printf("================tun open ==========\n")
}

func (tun *mytun) Read() {
	//go recvsp()
	for {
		inpkt, err := tun.tund.ReadPacket()
		if err != nil{
			log.Println("==============tund.ReadPacket error===", err)
			log.Fatal(err)
			return
		}
		
		if len(inpkt.Packet) < 42 || len(inpkt.Packet) > 1514 {
			log.Printf("====== read len=%d out of range =======\n", len(inpkt.Packet))
			continue
		}

		ether := packet.TranEther(inpkt.Packet)
		if ether.IsBroadcast() && ether.IsArp() {
			mylog.Info("%s","---------arp broadcast from tun/tap ----------")
			mylog.Info("dst mac :%s", ether.DstMac.String())
			mylog.Info("src mac :%s", ether.SrcMac.String())
		}
		if !ether.IsArp() && !ether.IsIpPtk(){
			//mylog.Warning(" not arp ,and not ip packet, ether type =0x%0x%0x ===============\n", ether.Proto[0], ether.Proto[1])
			continue
		}
		if *DebugEn && ether.IsIpPtk() {
			iphdr, err := packet.ParseIPHeader(inpkt.Packet[packet.EtherSize:])
			if err != nil {
				mylog.Warning("ParseIPHeader err: %s\n",err.Error())
			}
			fmt.Println("tun read ",iphdr.String())
		}
		//PutPktToChan(inpkt.Packet, tun.peer)
		//static(len(inpkt.Packet))
		data := make([]byte, len(inpkt.Packet))
		copy(data, inpkt.Packet[:len(inpkt.Packet)]) 
		tun.FwdToPeer(data)
	}
}
var rxsum int64 
func static(len int) {
	//atomic.AddInt64(&rxsum, int64(len))
	rxsum += int64(len)
}

func recvsp() {
	var current int64
	var sp  int64
	for {
		time.Sleep(time.Second * 1)
		sp = rxsum - current
		current = rxsum
		fmt.Printf("%dkb\n", sp/1024)
	}
}

func PutPktToChan (pkt packet.Packet, mi myio) {
	mi.PutPktToChan(pkt)
}

func (tun *mytun) GetPeer() myio {
	return tun.peer
}

func (tun *mytun) FwdToPeer(pkt packet.Packet){
	if tun.peer != nil && !tun.peer.IsClose() {
		tun.peer.PutPktToChan(pkt)
	}	
}

func (tun *mytun) PutPktToChan(pkt packet.Packet) {
	tun.pktchan <- pkt
}

func (tun *mytun) WriteFromChan() {
	for {
		select {
			case pkt := <- tun.pktchan:
				inpkt := &tuntap.Packet{Packet: pkt[:]}
				err := tun.tund.WritePacket(inpkt)
				if err != nil {
					log.Fatal(err)
				}
		}
	}
}

func (tun *mytun) IsClose() bool {
	return false
}

func  NewConn() *myconn{
	return &myconn{
		pktchan : make(chan packet.Packet, *chanSize),
		writeQuit : make(chan bool, 1),
		reconnect : make(chan bool, 1),
		isClosed : false,
	}
}

func (c *myconn) Open() {
		
	if *lnAddr != "" {
		ln, err := net.Listen("tcp4", *lnAddr)
		if err != nil {
			log.Fatalln(err)
		}
		c.conn, err = ln.Accept()
		if err != nil {
			log.Fatalln(err)
		}
		c.conn.(*net.TCPConn).SetNoDelay(true)			
		fmt.Printf("%s have come\n", c.conn.RemoteAddr().String())
		return		
	}
	var err error
	n := 1
	ReConnect:

	if *tlsEnable {
		tlsconf := &tls.Config{
 			InsecureSkipVerify: true,
 		}
 		c.conn, err  = tls.Dial("tcp", *server, tlsconf)
	}else {
		c.conn, err = net.Dial("tcp4", *server)
	}

	if err != nil {
		fmt.Printf("try to connect to  %s time =%d\n", *server, n)
		n += 1
		fmt.Println(err.Error())
		time.Sleep(time.Second * 2)
		goto ReConnect
	}
	c.conn.(*net.TCPConn).SetNoDelay(true)	
	fmt.Println("success ,clinet:", c.conn.LocalAddr().String(),"connect to Server:", c.conn.RemoteAddr())
}

func (c *myconn) Read() {
	pkt := make(packet.Packet, 1514)	
	for {
		len , err := c.conn.Read(pkt)
		if err != nil{
			log.Println("conn.Read error: ",err)
			c.Reconnect()
			break
		}
		if len < 42 {
			mylog.Warning("====== conn.read too small pkt, len=%d===========\n", len)
			continue
		}
		// TODO packet combine
		if *DebugEn && len > 1500 {
			mylog.Warning("====== conn.read too small big %d,maybe tcp packet combine===========\n", len)
		}
		
		ether := packet.TranEther(pkt)
		if ether.IsBroadcast() && ether.IsArp() {
			mylog.Info("%s","---------arp broadcast from server ----------")
			mylog.Info("dst mac :%s", ether.DstMac.String())
			mylog.Info("src mac :%s", ether.SrcMac.String())
		}
		if *DebugEn && ether.IsIpPtk() {
			iphdr, err := packet.ParseIPHeader(pkt[packet.EtherSize:])
			if err != nil {
				mylog.Warning("ParseIPHeader err: %s\n",err.Error())
			}
			fmt.Printf("conn read len =%d:%s", len, iphdr.String())
		}
		//PutPktToChan(pkt, c.peer)
		data := make([]byte, len)
		copy(data, pkt[:len])
		c.FwdToPeer(data)
	}
}

func (c *myconn) GetPeer() myio {
	return c.peer
}
func (c *myconn) FwdToPeer(pkt packet.Packet) {
	if c.peer != nil {
		c.peer.PutPktToChan(pkt)
	}	
}

func (c *myconn) PutPktToChan(pkt packet.Packet) {
	c.pktchan <- pkt
}

func (c *myconn) WriteFromChan() {
	for {
		select {
			case pkt, ok := <- c.pktchan:
				if !ok {
					log.Printf("%s -> %s pktchan closed, quit the writefromchan  goroutine\n",
						 c.conn.LocalAddr().String(), c.conn.RemoteAddr().String())
					log.Printf(" c.pktchan is closed, quit the writefromchan  goroutine\n")		
					return	
				}	
				len, err := c.conn.Write(pkt)
				if err != nil{
					log.Printf(" write len=%d, err=%s\n", len, err.Error())		
					return
				}
				ether := packet.TranEther(pkt)
				if *DebugEn && ether.IsIpPtk() {
					iphdr, err := packet.ParseIPHeader(pkt[packet.EtherSize:])
					if err != nil {
						log.Println(err.Error())
					}
					fmt.Println("send to", c.conn.RemoteAddr().String(), iphdr.String())
				}
			case q, ok := <-c.writeQuit:
				if !ok {
					log.Printf(" c.writeQuit is closed , quit the writefromchan  goroutine\n")		
				} else {
					log.Printf("chan write_quit recive message: quit=%v, ok=%v\n", q, ok)	
				}					
				log.Printf("%s -> %s is closed \n", c.conn.LocalAddr().String(), c.conn.RemoteAddr().String())				
				return
		}
	}
}

func (c *myconn) Close() {
	log.Printf("%s -> %s is  closing \n", c.conn.LocalAddr().String(), c.conn.RemoteAddr().String())
	c.conn.Close()
	c.isClosed = true
	c.writeQuit <- true
	time.Sleep(time.Millisecond * 10)
	close(c.pktchan)
	close(c.writeQuit)
}

func (c *myconn) Reconnect() {
	c.Close()
	c.reconnect <- true
}

func (c *myconn) IsClose() bool {
	return c.isClosed
}
/*
func bind(a, b interface{}) bool {	
	switch t := a.(type) {
		case *myconn:
			a.(*myconn).peer = b.(myio)	
		case *mytun:
			a.(*mytun).peer = b.(myio)		
		default:
			log.Fatal("unknown type about a, %v", t)
			return false
	}
	switch t := b.(type) {
		case *myconn:
			b.(*myconn).peer = a.(myio)		
		case *mytun:
			b.(*mytun).peer = a.(myio)	
		default:
			log.Fatal("unknown type about b, %v", t)
			return false							
	}	
	return true
}
*/
func (c *myconn) SetPeer(peer myio) bool {
	c.peer = peer
	return true
}
func (tun *mytun) SetPeer(peer myio) bool {
	tun.peer = peer
	return true
}
func bind(a, b myio) {
	a.SetPeer(b)
	b.SetPeer(a)
	/*	
	if bindPeer(a, b) == false || bindPeer(b, a) == false {
		log.Fatal("setpeer error")
	}
	*/	
}
func bindPeer(a, b interface{}) bool{
	v := reflect.ValueOf(a)
	t := v.Type()
	if t.Kind() == reflect.Ptr {
		f := v.MethodByName("SetPeer")
		if f.IsValid() {
			res := f.Call([]reflect.Value{reflect.ValueOf(b)})
			if ret, ok := res[0].Interface().(bool); ok {
				return ret
			}
		}
	}
	return false
}

func main () {  
	flag.Parse()
	mylog.InitLog(mylog.LINFO)

	mylog.Notice("tun name =%s, br=%s server=%s, enable pprof %v, ppaddr=%s, chanSize=%d \n", *tunname, *br,
					 *server, *pprofEnable, *ppAddr, *chanSize)
	mylog.Info("tun name =%s, br=%s server=%s, enable pprof %v, ppaddr=%s, chanSize=%d\n", *tunname, *br, *server, 
					*pprofEnable, *ppAddr, *chanSize)
	if *pprofEnable {
		go func() {
			log.Println(http.ListenAndServe(*ppAddr, nil))
		}()
	}	

    tun := NewTun()
	tun.Open()
	go tun.WriteFromChan()
	go tun.Read()
	for {		
		cc := NewConn() 
		cc.Open()
		bind(cc, tun)
		go cc.WriteFromChan()
		go cc.Read()
		<-cc.reconnect
		close(cc.reconnect)
	}
}