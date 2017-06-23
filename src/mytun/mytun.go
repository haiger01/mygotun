
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
		pktchan : make(chan packet.Packet, 4096),
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
	for {
		inpkt, err := tun.tund.ReadPacket()
		if err != nil{
			log.Println("==============tund.ReadPacket error===", err)
			log.Fatal(err)
			return
		}
		
		if len(inpkt.Packet) < 42 {
			log.Printf(" read len=%d\n", len(inpkt.Packet))
			continue
		}

		ether := packet.TranEther(inpkt.Packet)
		if ether.IsBroadcast() && ether.IsArp() {
			log.Println("---------arp broadcast from tun/tap ----------")
			log.Println("dst mac :", ether.DstMac.String())
			log.Println("src mac :", ether.SrcMac.String())
		}
		if !ether.IsArp() && !ether.IsIpPtk(){
			continue
		}
		//PutPktToChan(inpkt.Packet, tun.peer)
		tun.FwdToPeer(inpkt.Packet)
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
		pktchan : make(chan packet.Packet, 4096),
		writeQuit : make(chan bool, 1),
		reconnect : make(chan bool, 1),
		isClosed : false,
	}
}

func (c *myconn) Open() {	
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
	fmt.Println("clinet :", c.conn.LocalAddr().String(),"connect to Server:", c.conn.RemoteAddr())
}

func (c *myconn) Read() {
	pkt := make(packet.Packet, 65536)	
	for {
		len , err := c.conn.Read(pkt)
		if err != nil{
			log.Println("conn.Read error: ",err)
			c.Reconnect()
			break
		}
		if len < 42 {
			log.Printf("====== conn.read too small pkt, len=%d===========\n", len)
			continue
		}

		ether := packet.TranEther(pkt)
		if ether.IsBroadcast() && ether.IsArp() {
			log.Println("---------arp broadcast from server ----------")
			log.Println("dst mac :", ether.DstMac.String())
			log.Println("src mac :", ether.SrcMac.String())
		}
		//PutPktToChan(pkt, c.peer)
		c.FwdToPeer(pkt[:len])
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
					log.Printf("%s -> %s pktchan closed\n", c.conn.LocalAddr().String(), c.conn.RemoteAddr().String())
					log.Printf(" c.pktchan is closed, quit the writefromchan  goroutine\n")		
					return	
				}	
				len, err := c.conn.Write(pkt)
				if err != nil{
					log.Printf(" write len=%d, err=%s\n", len, err.Error())		
					return
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
	mylog.InitLog()

	log.Printf("tun name =%s, br=%s server=%s, enable pprof %v, ppaddr=%s \n", *tunname, *br, *server, *pprofEnable, *ppAddr)
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