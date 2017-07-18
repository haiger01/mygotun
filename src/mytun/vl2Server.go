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
	"github.com/BurntSushi/toml"
)
/*
1、 生成服务器端的私钥
openssl genrsa -out server.key 2048
2、 生成服务器端证书
openssl req -new -x509 -key server.key -out server.pem -days3650
*/
var (
	config Vl2Config
	buildTime string
	commitId string
	appVersion = "1.0.0"
	version = flag.Bool("v", true, "show version information")
	listenAddr = flag.String("listenAddr", "", "listenAddr, like 23.33.145.33:7878")
	httpAddr = flag.String("httpAddr", "", "127.0.0.1:88, check mactable, localhost:88/clientmac")
	tlsSK = flag.String("server.key", "./config/server.key", "tls server.key")
	tlsSP = flag.String("server.pem", "./config/server.pem", "tls server.pem")
	tlsEnable = flag.Bool("tls", false, "enable tls server, default false")
	pprofEnable = flag.Bool("pprof", false, "enable pprof, default false")
	ppAddr = flag.String("ppaddr", ":6060", "ppaddr , http://xxxx:6060/debug/pprof/")
	serAddr = flag.String("serAddr", "", " the addr connect to ,like 127.0.0.1:9999")
	readFwdMode =  flag.Int("rfm", 1, " readFwdMode, 1 means read one by one and forward, 2 means read big pkt and parase forward")
	br = flag.String("br", "br0"," add tun/tap to bridge")
	tuntype = flag.Int("tuntype", 1," type, 1 means tap and 0 means tun")
	tundev = flag.String("tundev","tap0"," tun dev name")
	ipstr = flag.String("ipstr", "", "set tun/tap or br ip address")
	configFile = flag.String("c", "", "vl2 config, if use config file , other flags is no longer effective")
)

type Vl2Config struct {
	Version bool	`toml:"version"`
	ListenAddr string `toml:"listenAddr"`
	SerAddr string `toml:"serAddr"`

	//for checking mactable, localhost:88/clientmac
	HttpAddr string `toml:"httpAddr"`

	PprofEnable bool `toml:"pprofEnable"`
	PpAddr string	`toml:"ppAddr"`

	TlsEnable bool `toml:"tlsEnable"`
	TlsSK string  `toml:"tlsSK"`
	TlsSP string  `toml:"tlsSP"`

	Br string `toml:"br"`
	Tundev string `toml:"tundev"`
	Tuntype int	`toml:"tuntype"`
	Ipstr string `toml:"ipstr"`

	ReadFwdMode int `toml:"readFwdMode"`
}

func HttpGetMacTable(w http.ResponseWriter, req *http.Request){
	mc := fdb.ShowClientMac()
	mcjson, err := json.MarshalIndent(mc, "","\t")
	if err != nil{
		log.Println(err)
		return
	}
	//log.Println(string(mcjson))
	w.Write(mcjson)
}

func checkError(err error, info string) bool{
	if err != nil{
		log.Println(info+": " ,err.Error())
		log.Fatal(err)
		return false
	}
	return true
}

func initConfig(config *Vl2Config) {	
	if *configFile != "" {
		if _, err := toml.DecodeFile(*configFile, &config); err != nil {
			log.Println(err)
			return
		}
		if config.Version {
			log.Printf("appVersion=%s, buildTime=%s, commitId=%s\n", appVersion, buildTime, commitId)
		}
	} else {
		config.Version = *version
		config.ListenAddr = *listenAddr
		config.SerAddr = *serAddr
		config.HttpAddr = *httpAddr
		config.PprofEnable = *pprofEnable
		config.PpAddr = *ppAddr
		config.TlsEnable = *tlsEnable
		config.TlsSK = *tlsSK 
		config.TlsSP = *tlsSP
		config.Tundev = *tundev
		config.Tuntype = *tuntype
		config.Br = *br
		config.Ipstr= *ipstr
		config.ReadFwdMode = *readFwdMode
	}

	if config.Version {
		log.Printf("appVersion=%s, buildTime=%s, commitId=%s\n", appVersion, buildTime, commitId)
	}
	log.Printf("listenAddr=%s, httpAddr =%s for check clientmac, serAddr=%s, tlsEnable =%v, br=%s, tundev=%s\n", 
				config.ListenAddr, config.HttpAddr, config.SerAddr, config.TlsEnable, config.Br, config.Tundev)	
}

func main(){
	var ln net.Listener
	var err error

	flag.Parse()
	mylog.InitLog(mylog.LDEBUG)	
	initConfig(&config)

	// for show fdb mactable
	if config.HttpAddr != "" {
		http.HandleFunc("/clientmac", HttpGetMacTable)
		go http.ListenAndServe(config.HttpAddr, nil)
	}

	// for pprof
	if config.PprofEnable {
		go func() {
			log.Println(http.ListenAndServe(config.PpAddr, nil))
		}()
	}

	if config.SerAddr != "" {
		go connectSer(config.SerAddr)
	}
	
	if config.Tundev != "" {
		go createTun()
	}

	if config.ListenAddr == "" {
		for {
			time.Sleep(time.Minute)
		}
	}

	if config.TlsEnable {
		cert, err := tls.LoadX509KeyPair(config.TlsSP, config.TlsSK)
		if err != nil {
			log.Println(err)
			return
 		}
		tlsconf := &tls.Config {
			Certificates: []tls.Certificate{cert},
		}
		ln, err = tls.Listen("tcp4", config.ListenAddr, tlsconf)
		checkError(err, "ListenTCP")
	}else {
		ln, err = net.Listen("tcp4", config.ListenAddr)
		checkError(err, "ListenTCP")
	}

	for {
		conn, err := ln.Accept()
		if err != nil{
			continue
		}
		go handleClient(conn)
	}
}

func connectSer(serAddr string) {
	var conn net.Conn
	var err error
	conn_th, conn_num := 1, 1
	
	reconnect:
	if config.TlsEnable {
		tlsconf := &tls.Config{
 			InsecureSkipVerify: true,
 		}
 		conn, err  = tls.Dial("tcp", serAddr, tlsconf)
	}else {
		conn, err = net.Dial("tcp4", serAddr)		
	}

	if err != nil {
		log.Println(err)
		log.Printf("conn_th=%d, connect to %s time=%d \n", conn_th, serAddr, conn_num)
		time.Sleep(time.Second * 2)
		conn_num += 1
		goto reconnect
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	conn_num = 0
	handleClient(conn)
	conn_th += 1
	goto reconnect
}

func createTun() {
	open_th, open_num := 1, 1
	for {		
		tun, err := fdb.OpenTun(config.Br, config.Tundev, config.Tuntype, config.Ipstr)
		if err != nil {
			log.Println(err)
			log.Printf("open_th=%d, open tun %s fail, time=%d \n", open_th, config.Tundev, open_num)
			open_num += 1
			time.Sleep(time.Second)
			if open_num > 5 {
				log.Printf("quit to open tun %s, fail time =%d \n", config.Tundev, open_num)
				break
			}
			continue
		}
		open_num = 0		
		handleClient(tun)
		open_th += 1
	}
}

func handleClient(cio fdb.Cio) {
	c := fdb.NewClient(cio)
	go c.WriteFromChan()
	if config.ReadFwdMode == 1 {
		c.ReadForward()
	} else {
		c.ReadForward2()
	}		
}