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
			_, err := ci.Conn().Write(pkt[:len])
			if err != nil{
				ci.Close()
			}
		}			
	}
	log.Printf("-------------- flood end  ------------\n")
}

func Forward(c *fdb.Client) {
	pkt := make(packet.Packet, 65535)
	for {
		len, err := c.Conn().Read(pkt)
		/*
		if err == io.EOF {
			c.Close()
			break
		}
		*/
		if err != nil{
			log.Println("conn read fail:", err.Error())
			c.Close()
			break
		}
		
		if len < 42 {
			log.Printf(" len =%d\n", len)
			continue
		}
		/*
		if !pkt.IsArp() && !pkt.IsIpPtk(){
			continue
		}
		*/
		ether := packet.TranEther(pkt)
		if !ether.IsArp() && !ether.IsIpPtk(){
			continue
		}

		if _, ok := Fdb().Get(ether.SrcMac); !ok {
			Fdb().Add(ether.SrcMac, c)
			//MtShowAll()
		}
		//arp broadcast
		if  ether.IsArp() && ether.IsBroadcast(){
			log.Printf("-------------- IsBroadcast ------------\n")
			log.Printf("src  mac %s\n", ether.SrcMac.String())
			log.Printf("dst  mac %s\n", ether.DstMac.String())
			flood(c, pkt, len)
		}else{
			//it is ip packet or unicast arp
			if i, ok := Fdb().Get(ether.DstMac); ok{
				if fmn, ok := i.(*fdb.FdbMacNode); ok{
					if fmn.GetClient() != c {
						//log.Println("write to", ci.conn.RemoteAddr().Network(), ci.conn.RemoteAddr().String())
						_, err := fmn.GetClient().Conn().Write(pkt[:len])
						if err != nil{
							fmn.GetClient().Close()
						}
					}
				}else{
					log.Printf("-----------oh shit , never happend -------------\n")
					return
				}				
			}else{
				log.Printf("src  mac %s ,dst  mac %s, dst mac is unkown ,so flood\n",
							ether.DstMac.String(), ether.SrcMac.String()/*pkt.GetSrcMac().String(), pkt.GetDstMac().String()*/)
				flood(c, pkt, len)
			}
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
	mylog.InitLog()

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

	for {
		conn, err := ln.Accept()
		if err != nil{
			continue
		}
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn){
	c := fdb.NewClient(conn)
	Forward(c)	
}