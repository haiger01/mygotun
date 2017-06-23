package main

import(
	//"fmt"
	"time"
	"log"
	"net"
	"sync/atomic"
	"flag"
)

var (
	laddr = flag.String("laddr", ":55555", "listen addr" )	
)

func main(){
	flag.Parse()
	ln, err := net.Listen("tcp4", *laddr)
	if err != nil {
		log.Fatal(err)
	}	
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		log.Printf("a connect have come , %s, local:%s\n",
			 conn.RemoteAddr().String(), conn.LocalAddr().String())
		go handleConn(conn)
	}
}

func handleConn( conn net.Conn){
	var rxsum int64
	var rx int64
	var exit bool

	defer conn.Close()
	buf := make([]byte, 65535)

	go func(){
		for {
			time.Sleep(time.Second * 1)
			log.Printf(" total send bytes :%d, speed: %fKB", rxsum, float64(rx)/1024)
			atomic.StoreInt64(&rx, 0)
			if exit {
				break
			}
		}
	}()

	for {
		rn, err := conn.Read(buf)
		if err != nil {
			log.Println("conn.Read error", err)
			exit = true
			return
		}		
		rxsum += int64(rn)
		atomic.AddInt64(&rx, int64(rn))
	}
}