package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"

	"net/http"
	_ "net/http/pprof"
	"sync"
	"time"

	"mylog"
	"vnet"

	toml "git.oceanbluecloud.com/dep/go-toml"
)

const (
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

const (
	DevSlotMax = 100
)

var (
	//tcMap       map[string]*myconn
	obcDevSlot  []int
	DevSlotLock sync.Mutex
	buildTime   string
	goVersion   string
	commitId    string
	appVersion  = "1.0.0"
	version     = flag.Bool("v", true, "show version information")
	lnAddr      = flag.String("lnAddr", "", " listen addr, like 203.156.34.98:7878")
	server      = flag.String("server", "", " server like 203.156.34.98:7878")
	tlsEnable   = flag.Bool("tls", false, "enable tls connect")
	tlsSK       = flag.String("server.key", "./config/server.key", "tls server.key")
	tlsSP       = flag.String("server.pem", "./config/server.pem", "tls server.pem")
	pprofEnable = flag.Bool("pprof", false, "enable pprof, true or false")
	ppAddr      = flag.String("ppaddr", ":7070", "ppaddr , http://xxxx:7070/debug/pprof/")

	configFile = flag.String("c", "", "config file")
)

func newListener() net.Listener {
	var ln net.Listener
	var err error
	if *tlsEnable {
		cert, err := tls.LoadX509KeyPair(*tlsSP, *tlsSK)
		if err != nil {
			log.Fatalln(err, *tlsSP, *tlsSK)
		}
		tlsconf := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		ln, err = tls.Listen("tcp4", *lnAddr, tlsconf)
	} else {
		ln, err = net.Listen("tcp4", *lnAddr)
	}
	//ln, err := net.Listen("tcp4", *lnAddr)
	if err != nil {
		log.Fatalln(err)
	}
	return ln
}

func Connecting() (conn net.Conn) {
	var err error
	serverAddr := *server
	n := 1

ReConnect:
	mylog.Info("now connecting to  %s \n", serverAddr)
	if *tlsEnable {
		tlsconf := &tls.Config{
			InsecureSkipVerify: true,
		}
		conn, err = tls.Dial("tcp", serverAddr, tlsconf)
	} else {
		//c.conn, err = net.Dial("tcp4", serverAddr)
		conn, err = net.DialTimeout("tcp4", serverAddr, time.Second*5)
	}

	if err != nil {
		mylog.Notice("try to connect to  %s time =%d, err=%s\n", serverAddr, n, err.Error())
		n += 1
		time.Sleep(time.Second * 2)
		goto ReConnect
	}

	mylog.Info("success ,client:%s connect to Server:%s \n", conn.LocalAddr().String(), conn.RemoteAddr().String())
	return
}

func main() {
	flag.Parse()
	initConfig()
	mylog.InitLog(mylog.LINFO)

	if *version {
		log.Printf("appVersion=%s, goVersion=%s, buildTime=%s, commitId=%s\n", appVersion, goVersion, buildTime, commitId)
	}

	log.Printf("lnAddr=%s ,server=%s, enable pprof %v, ppaddr=%s\n", *lnAddr, *server, *pprofEnable, *ppAddr)
	log.Printf("Br=%s, TunName=%s, TunType=%d, Ipstr=%s, BindTun=%v, ChanSize=%d, rate up=%d, down=%d\n", *vnet.Br, *vnet.TunName, *vnet.TunType, *vnet.Ipstr,
		*vnet.BindTun, *vnet.ChanSize, *vnet.UpRateLimit, *vnet.DownRateLimit)
	/*	log.Printf("tun name =%s, tun type=%d, ipstr=%s, br=%s ,server=%s, enable pprof %v, ppaddr=%s, chanSize=%d, lnAddr=%s,rate up=%d,down=%d\n",
	*tunname, *tuntype, *ipstr, *br, *server, *pprofEnable, *ppAddr, *chanSize, *lnAddr, *UpRateLimit, *DownRateLimit)
	 */
	if *pprofEnable {
		go func() {
			log.Println(http.ListenAndServe(*ppAddr, nil))
		}()
	}

	if *server != "" {
		go func() {
			for {
				conn := Connecting()
				vnet.HandleConn(conn, true)
			}
		}()
	}

	if *lnAddr != "" {
		ln := newListener()
		for {
			mylog.Info("\n %s listenning .......\n", *lnAddr)
			conn, err := ln.Accept()
			if err != nil {
				log.Fatalln(err)
			}

			mylog.Info("new connect :%s ->  %s\n", conn.RemoteAddr().String(), conn.LocalAddr().String())
			//go vnet.AddToVnet(conn)
			go vnet.HandleConn(conn, false)
		}
	}

	for {
		time.Sleep(time.Minute)
	}
}

func initConfig() {
	if *configFile == "" {
		return
	}

	config, err := toml.LoadFile(*configFile)
	if err != nil {
		fmt.Println("Error ", err.Error())
	}
	if tmp := config.Get("listenAddr"); tmp != nil {
		*lnAddr = tmp.(string)
	}
	if tmp := config.Get("serAddr"); tmp != nil {
		*server = tmp.(string)
	}
	if tmp := config.Get("br"); tmp != nil {
		*vnet.Br = tmp.(string)
	}
	if tmp := config.Get("tundev"); tmp != nil {
		*vnet.TunName = tmp.(string)
	}
	if tmp := config.Get("tuntype"); tmp != nil {
		*vnet.TunType = int(tmp.(int64))
	}
	if tmp := config.Get("ipstr"); tmp != nil {
		*vnet.Ipstr = tmp.(string)
	}
	if tmp := config.Get("logFile"); tmp != nil {
		*mylog.LogFile = tmp.(string)
	}
	// if tmp := config.Get("HQMode"); tmp != nil {
	// 	*HQMode = tmp.(bool)
	// }
	if tmp := config.Get("upRateLimit"); tmp != nil {
		*vnet.UpRateLimit = tmp.(int64)
	}
	if tmp := config.Get("downRateLimit"); tmp != nil {
		*vnet.DownRateLimit = tmp.(int64)
	}
	if tmp := config.Get("bindtun"); tmp != nil {
		*vnet.BindTun = tmp.(bool)
	}
}
