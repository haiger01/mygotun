package main

import(
	"log"
	"net"
	"flag"
	"net/http"
	"encoding/json"
	"mylog"
	"crypto/tls"
	"fdb"
	_"net/http/pprof"
	"time"
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
	tlsEnable = flag.Bool("tls", false, "enable tls server, default false")
	pprofEnable = flag.Bool("pprof", false, "enable pprof, default false")
	ppAddr = flag.String("ppaddr", ":6060", "ppaddr , http://xxxx:6060/debug/pprof/")
	serAddr = flag.String("serAddr", "", " the addr connect to ,like 127.0.0.1:9999")
	readFwdMode =  flag.Int("rfm", 1, " readFwdMode, 1 means read one by one and forward, 2 means read big pkt and parase forward")
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
	if *readFwdMode == 1 {
		c.Forward()
	} else {
		c.Forward2()
	}		
}