package main
import (
	"github.com/lab11/go-tuntap/tuntap"
	"log"
	"fmt"
	"os/exec"
	"encoding/binary"
	"flag"
	"net"
	"time"
	"io/ioutil"
	"packet"
	"mylog"
	"crypto/tls"
	"net/http"
	_"net/http/pprof"
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
func checkError(err error, info string) bool{
	if err != nil{
		fmt.Println(info+": " , err)
		log.Fatal(err)
		return false
	}
	return true
}
func printIp(ip []byte) string{
	return fmt.Sprintf(":%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}
func connectSer(server string, conn_ok chan int) net.Conn{
	var conn net.Conn 
	var err error
	n := 1
	ReConnect:

	if *tlsEnable {
		tlsconf := &tls.Config{
 			InsecureSkipVerify: true,
 		}
 		conn, err  = tls.Dial("tcp", server, tlsconf)
	}else {
		//tcpAddr, err := net.ResolveTCPAddr("tcp4", server)
		//checkError(err, "ResolveTcpAddr")
		//conn, err = net.DialTCP("tcp", nil, tcpAddr)
		conn, err = net.Dial("tcp", server)
	}

	if err != nil{
		fmt.Printf("connecting time =%d\n", n)
		n += 1
		fmt.Println(err.Error())
		time.Sleep(time.Second * 2)
		goto ReConnect
	}
	
	fmt.Println("clinet :", conn.LocalAddr().String(),"connect to Server:", conn.RemoteAddr())
	conn_ok <-1
	return conn
}
func main () {
    var tund *tuntap.Interface
    var err error
    //var inpkt *tuntap.Packet

	flag.Parse()
	mylog.InitLog()

	log.Printf("tun name =%s, br=%s server=%s, enable pprof %v, ppaddr=%s \n", *tunname, *br, *server, *pprofEnable, *ppAddr)
	if *pprofEnable {
		go func() {
			log.Println(http.ListenAndServe(*ppAddr, nil))
		}()
	}	

    tund, err = tuntap.Open(*tunname, tuntap.DevKind(*tuntype) , false)
	if err != nil {
		log.Fatal(err)
	}

	confs := fmt.Sprintf("ifconfig %s up\n", *tunname)
	if *br != "" {
		confs += fmt.Sprintf("brctl addif %s %s\n", *br, *tunname)
	}
	exec.Command("sh","-c", confs).Run()
	conn_ok := make(chan int, 1)
	reconn := make(chan int, 1)
reconnect:
	conn := connectSer(*server, conn_ok)
	go handleSerConn(conn, tund, reconn)
	<-conn_ok 
	go handleTunPkt(conn, tund)
	<-reconn
	
	//tund.Close()
	//time.Sleep(time.Second * 1)
	
	goto reconnect
}
func handleTunPkt(conn net.Conn, tund *tuntap.Interface){
	connChan := make(chan []byte, 10000)
	go WriteToConn(connChan)

	defer conn.Close()
	for {
		inpkt, err := tund.ReadPacket()
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

		/*
		inpkt.Packet = echo_icmp(inpkt.Packet)
		err = tund.WritePacket(inpkt)
		if err != nil{
			log.Fatal(err)
		}
		fmt.Printf(" write len=%d\n", len(inpkt.Packet))
		*/
		/*
		len, err := conn.Write(inpkt.Packet)
		if err != nil{
			log.Printf(" write len=%d, err=%s\n", len, err.Error())
			//checkError(err, "conn.Write error oh shit:")			
			break
		}
		*/
		connChan <- inpkt.Packet
	}
}
func WriteToConn(pktchan chan []byte) {
	for {
		pkt := <- pktchan
		len, err := conn.Write(pkt)
		if err != nil{
			log.Printf(" write len=%d, err=%s\n", len, err.Error())		
			break
		}
	}
}
func handleSerConn(conn net.Conn, tund *tuntap.Interface, reconn chan int){
	tunChan := make(chan []byte, 10000)
	go WriteToTun(tunChan)
	pkt := make(packet.Packet, 65536)
	for {
		len , err := conn.Read(pkt)
		if err != nil{
			log.Println("conn.Read error: ",err)
			//need to reconnect
			reconn <- 1

			break
		}
		if len < 42 {
			log.Printf("====== conn.read too small pkt, len=%d===========\n", len)
			continue
		}
		
		//inpkt := &tuntap.Packet{Packet: pkt[:len]}

		ether := packet.TranEther(pkt)
		if ether.IsBroadcast() && ether.IsArp() {
			log.Println("---------arp broadcast from server ----------")
			log.Println("dst mac :", ether.DstMac.String())
			log.Println("src mac :", ether.SrcMac.String())
		}
		/*
		err = tund.WritePacket(inpkt)
		if err != nil{
			log.Fatal(err)
		}
		*/
		tunChan <- pkt
	}
}

func WriteToTun(pktchan chan []byte) {
	for {
		pkt := <- pktchan
		inpkt := &tuntap.Packet{Packet: pkt[:len]}
		err = tund.WritePacket(inpkt)
		if err != nil{
			log.Fatal(err)
		}
	}
}

func echo_icmp(Packet []byte) []byte{
	ip := make([]byte, 4)
	copy(ip, Packet[12:16])
	fmt.Printf("dst ip :%s\n", printIp(ip))
	fmt.Printf("src ip ::%s\n", printIp(Packet[16:20]))
	copy(Packet[12:],Packet[16:20])
	copy(Packet[16:],ip)
	
	Packet[20]=0
	tmp := binary.BigEndian.Uint16(Packet[22:24])
	binary.BigEndian.PutUint16(Packet[22:24], uint16(tmp+8))
	return Packet
}
