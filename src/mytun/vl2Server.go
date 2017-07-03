package main

import(
	"log"
	"net"
	"flag"
	"container/list"
	"net/http"
	"encoding/json"
	"packet"
	"mylog"
	"crypto/tls"
	"fdb"
	_"net/http/pprof"
	"time"
	"fmt"
	"encoding/binary"
	"io"
	"bufio"
)
/*
1、 生成服务器端的私钥
openssl genrsa -out server.key 2048
2、 生成服务器端证书
openssl req -new -x509 -key server.key -out server.pem -days3650
*/
var (
	listenAddr = flag.String("listenAddr", ":7878", "listenAddr, like 23.33.145.33:7878")
	httpAddr = flag.String("httpAddr", "127.0.0.1:88", "check mactable, localhost:88/clientmac")
	tlsSK = flag.String("server.key", "./config/server.key", "tls server.key")
	tlsSP = flag.String("server.pem", "./config/server.pem", "tls server.pem")
	tlsEnable = flag.Bool("tls", false, "enable tls server")
	pprofEnable = flag.Bool("pprof", false, "enable pprof")
	ppAddr = flag.String("ppaddr", ":6060", "ppaddr , http://xxxx:6060/debug/pprof/")
	serAddr = flag.String("serAddr", "", " the addr connect to ,like 127.0.0.1:9999")
)

func HttpGetMacTable(w http.ResponseWriter, req *http.Request){
	mc := fdb.ShowClientMac()
	mcjson, err := json.MarshalIndent(mc, "","\t")
	if err != nil{
		log.Println(err)
		return
	}
	w.Write([]byte(mcjson))
}
func GetClientList() *list.List {
	return fdb.GetClientList()
}
func Fdb() *fdb.FDB {
	return fdb.Fdb()
}

func flood(c *fdb.Client, pkt packet.Packet, len int) {
	log.Printf("-------------- flooding  ------------\n")
	var n *list.Element
	for e := GetClientList().Front(); e != nil;  e = n {
		n = e.Next()
		ci, ok := e.Value.(*fdb.Client)
		if !ok {
			log.Printf(" can't happend\n")
			GetClientList().Remove(e)
			continue			
		}

		if ci != c {
			log.Println(c.Conn().RemoteAddr(), "write to", ci.Conn().RemoteAddr().Network(), ci.Conn().RemoteAddr().String())
			/*
			_, err := ci.Conn().Write(pkt[:len])
			if err != nil{
				ci.Close()
			}*/
			ci.PutPktToChan(pkt[:len])
		}			
	}
	log.Printf("-------------- flood end  ------------\n")
}

type LastPkt struct {
	buf []byte
	pktLen int
	needMore int
}
var last LastPkt
/*
func Forward(c *fdb.Client) {
	pkt := make(packet.Packet, 65536)
	last := LastPkt{make([]byte, 1514+2), 0, 0}	
	for {				
		len, err := c.Conn().Read(pkt)
		if err != nil{
			log.Println("conn read fail:", err.Error())
			c.Close()
			break
		}
		
		if len < 42 {
			log.Printf(" len =%d\n", len)
			continue
		}
		// TODO tcp packet combine
		// if *DebugEn && len > 1500 {
		// 	mylog.Warning("====== conn.read too small big %d,maybe tcp packet combine===========\n", len)
		// }		
		 
		ParseFwdPkt(c, pkt, len, last)		
	}
}
*/
func Forward(c *fdb.Client) {
	pkt := make(packet.Packet, 65536)
	cr := bufio.NewReader(c.Conn())
	for {
		// if err := binary.Read(cr, binary.BigEndian, &pktLen); err != nil {
		// 	log.Println("conn read fail:", err.Error())
		// 	c.Close()
		// 	break			
		// }
		lenBuf, err := cr.Peek(2)
		if err != nil{
			log.Println("conn read fail:", err.Error())
			c.Close()
			break
		}		
		pktLen := int(binary.BigEndian.Uint16(lenBuf))
		rn, err := io.ReadFull(cr, pkt[:pktLen+2])
		if err != nil{
			log.Println("conn read fail:", err.Error())
			c.Close()
			break
		}
		//if err == nil , means rn == pktLen+2, so don't need to check 
		// if rn != pktLen+2 {
		// 	log.Println(" something wrong, read rn=%d, pktLen+2 =%d \n", rn, pktLen+2)
		// }
		data := make([]byte, rn)
		copy(data, pkt[:rn])
		ForwardPkt(c, data)
	}
}

func ParseFwdPkt(c *fdb.Client, pkt []byte, len int, last LastPkt) {	
	pktStart, pktEnd := 0, 0	
	n := 0
	for i := 0; pktEnd < len; i++ {
		//check the remaining work from last handle packet
		if last.needMore != 0 {
			if last.needMore <= len {		
				//copy data and foward
				data := make([]byte, last.pktLen+last.needMore)
				copy(data, last.buf[:last.pktLen])
				copy(data[last.pktLen:], pkt[:last.needMore])				
				ForwardPkt(c, data)
				//set pktEnd
				pktEnd = last.needMore
				//reset last
				last.needMore = 0
				continue
			}else {
				fmt.Printf("can't be here, last.needMore=%d, totall len=%d\n", last.needMore, len)
				last.needMore = 0
				break;
			}
		}

		if pktEnd + 2 > len {
			fmt.Printf("something wrong: pktEnd=%d, totall len=%d\n", pktEnd, len)
			break;
			//panic("pktEnd + 2 > len")	
		}
		n =	int(binary.BigEndian.Uint16(pkt[pktEnd:]))
		if n < 42 || n > 1514 {
			log.Printf("======i=%d, error parse: pkt len unormal, n=%d, totall len=%d===========\n", i, n, len)
			break;
		}
		pktStart = pktEnd
		pktEnd = pktStart + 2 + n
		if pktEnd > len {
			//log.Printf("====== out of range, pktStart=%d, n=%d, pktEnd=%d, totall len=%d, handle it next read===========\n", 
			//				pktStart, n, pktEnd, len)
			copy(last.buf, pkt[pktStart:len])
			last.pktLen , last.needMore = len - pktStart, pktEnd - len
			break;
		}	
		// ok forwarding now	
		data := make([]byte, n+2)
		copy(data, pkt[pktStart:pktEnd])
		ForwardPkt(c, data)
	}
}

func ForwardPkt(c *fdb.Client, pkt []byte) {
	len := len(pkt)
	ether := packet.TranEther(pkt[2:])
	if !ether.IsArp() && !ether.IsIpPtk(){
		return
	}

	if _, ok := Fdb().Get(ether.SrcMac); !ok {
		Fdb().Add(ether.SrcMac, c)
		//MtShowAll()
	}
	//arp broadcast
	if  ether.IsArp() && ether.IsBroadcast() {
		log.Printf("-------------- IsBroadcast ------------\n")
		log.Printf("src  mac %s\n", ether.SrcMac.String())
		log.Printf("dst  mac %s\n", ether.DstMac.String())
		flood(c, pkt, len)
	} else {
		//it is ip packet or unicast arp
		if i, ok := Fdb().Get(ether.DstMac); ok {
			if fmn, ok := i.(*fdb.FdbMacNode); ok {
				if fmn.GetClient() != c {
					//log.Println("write to", ci.conn.RemoteAddr().Network(), ci.conn.RemoteAddr().String())
					//_, err := fmn.GetClient().Conn().Write(pkt[:len])						
					/*
					if err != nil{
						fmn.GetClient().Close()
					}
					*/
					fmn.GetClient().PutPktToChan(pkt[:len])
				}
			} else {
				log.Printf("-----------oh shit , never happend -------------\n")
				return
			}				
		} else {
			log.Printf("src  mac %s ,dst  mac %s, dst mac is unkown ,so flood\n",
						ether.DstMac.String(), ether.SrcMac.String()/*pkt.GetSrcMac().String(), pkt.GetDstMac().String()*/)
			flood(c, pkt, len)
		}
	}	
}
func checkError(err error, info string) bool{
	if err != nil{
		log.Println(info+": " ,err.Error())
		log.Fatal(err)
		return false
	}
	return true
}
func main(){
	var ln net.Listener
	var err error
	flag.Parse()
	mylog.InitLog(mylog.LDEBUG)

	if *tlsEnable {
		cert, err := tls.LoadX509KeyPair(*tlsSP, *tlsSK)
		if err != nil {
			log.Println(err)
			return
 		}
		tlsconf := &tls.Config {
			Certificates: []tls.Certificate{cert},
		}
		ln, err = tls.Listen("tcp4", *listenAddr, tlsconf)
		checkError(err, "ListenTCP")
	}else {
		//addr, err := net.ResolveTCPAddr("tcp4", *listenAddr)
		//checkError(err, "ResolveTCPAddr")
		//ln, err = net.ListenTCP("tcp4", addr)
		ln, err = net.Listen("tcp4", *listenAddr)
		checkError(err, "ListenTCP")
	}

	http.HandleFunc("/clientmac", HttpGetMacTable)
	go http.ListenAndServe(*httpAddr, nil)

	if *pprofEnable {
		go func() {
			log.Println(http.ListenAndServe(*ppAddr, nil))
		}()
	}

	if *serAddr != "" {
		go connectSer(*serAddr)
	}
	log.Printf("listenAddr=%s, httpAddr =%s for check clientmac, serAddr=%s, tlsEnable =%v\n", *listenAddr,
				*httpAddr, *serAddr, *tlsEnable)
	for {
		conn, err := ln.Accept()
		if err != nil{
			continue
		}
		go handleClient(conn)
	}
}

func connectSer(serAddr string) {
	conn_num := 0
	reconnect:
	conn, err := net.Dial("tcp4", serAddr)
	if err != nil {
		log.Println(err)
		log.Printf("connect to %s time=%d \n", serAddr, conn_num)
		time.Sleep(time.Second * 2)
		conn_num += 1
		goto reconnect
	}	
	conn_num = 0
	handleClient(conn)
	goto reconnect
}

func handleClient(conn net.Conn){
	c := fdb.NewClient(conn)
	go c.WriteFromChan()
	Forward(c)	
}