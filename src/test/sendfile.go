package main

import(
	"fmt"
	//"io/ioutil"
	"sync/atomic"
	"flag"
	"net"
	"log"
	"time"
	"os"
	"os/signal"
	"syscall"
)

/*
const (
    _           = iota                   // ignore first value by assigning to blank identifier
    KB  = 1 << (10 * iota) // 1 << (10*1)
    MB                                   // 1 << (10*2)
    GB                                   // 1 << (10*3)
    TB                                   // 1 << (10*4)
    PB                                   // 1 << (10*5)
    EB                                   // 1 << (10*6)
    ZB                                   // 1 << (10*7)
    YB                                   // 1 << (10*8)
)
*/
const (
	_  = 1 << (10 * iota)
	KB // 1024
	MB // 1048576
	GB // 1073741824
	TB // 1099511627776             (exceeds 1 << 32)
	PB // 1125899906842624
	EB // 1152921504606846976
	ZB // 1180591620717411303424    (exceeds 1 << 64)
	YB // 1208925819614629174706176
)

var (
	file = flag.String("file", "thefile", "the file to be send")
	saddr = flag.String("saddr", "127.0.0.1:55555", "the server addr to connect")
	tp = flag.Bool("tp", false, "just test speed")
)

func PrintSpeed(n float64) string {
	if n < KB {
		return fmt.Sprintf("%fbit/s", n*8)
	}
	if n < MB {
		return fmt.Sprintf("%fKbit/s", float64(n)/float64(KB/8))
	}
	if n < GB {
		return fmt.Sprintf("%fMbit/s", float64(n)/float64(MB/8))
	}
	return fmt.Sprintf("%fGbit/s", float64(n)/float64(GB/8))
}

func connectServer(addr string) net.Conn{
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		log.Fatal("dial fail:", err)
	}
	return conn
}

func openFile(file string) (*os.File, int64){
	//f, err := os.OpenFile(file, os.O_RDONLY, 0)
	f, err := os.Open(file)
	if err != nil {
		log.Fatal(err)
	}
	fi, err := f.Stat()
	if err != nil {
		log.Fatal(err)
	}
	return f, fi.Size()
}

func main(){
	flag.Parse()
	conn := connectServer(*saddr)
	f, len := openFile(*file)
	fmt.Printf("%s len =%d\n", *file, len)
	if *tp {
		testSpeed(f, conn)
	}else{
			sendFile(f, len, conn)
	}	
}
func testSpeed(f *os.File, conn net.Conn){
	var quit bool
	buf := make([]byte, 65535)
	defer conn.Close()
	defer f.Close()
	tx, txsum := int64(0), int64(0)
	go func(){
		for {
			time.Sleep(time.Second * 1)
			log.Printf(" total send bytes :%d, speed: %dKB", txsum, tx/1024)
			atomic.StoreInt64(&tx, 0)
			if quit {
				break
			}
		}
	}()
	go func(){
		quitChan := make(chan os.Signal, 1)
		signal.Notify(quitChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL)
		<- quitChan
		quit = true
	}()
	
	n, err := f.Read(buf)
	if err != nil {
		log.Println("read err:", err)
		quit = true
		return
	}
	start := time.Now()
	for {
		//fmt.Println("f.read ", n)					
		sn, err := conn.Write(buf[:n])
		if err != nil {
			log.Println(err)
			quit = true
			break
		}
		//fmt.Println("conn.Write ", sn)
		txsum += int64(sn)
		atomic.AddInt64(&tx, int64(sn))
		if quit {
			break
		}
	}
	//pass := time.Now().Sub(start)
	pass := time.Since(start)
	fmt.Println("pass:", pass.Seconds())
	log.Println("avg speed: ", PrintSpeed(float64(txsum)/(pass.Seconds())))	
}

func sendFile(f *os.File, len int64, conn net.Conn){
	var quit bool
	buf := make([]byte, 65535)
	//fmt.Println(len)
	defer conn.Close()
	defer f.Close()
	tx, txsum := int64(0), int64(0)
	go func(){
		for {
			time.Sleep(time.Second * 1)
			log.Printf(" total send bytes :%d, speed: %dKB", txsum, tx/1024)
			atomic.StoreInt64(&tx, 0)
			if quit {
				break
			}			
		}		
	}()

	start := time.Now()
	for {
		n, err := f.Read(buf)
		if err != nil {
			log.Println("read err:", err)
			quit = true
			break
		}
		//fmt.Println("f.read ", n)					
		sn, err := conn.Write(buf[:n])
		if err != nil {
			log.Println(err)
			quit = true
			break
		}
		//fmt.Println("conn.Write ", sn)
		txsum += int64(sn)
		atomic.AddInt64(&tx, int64(sn))
	}
	//pass := time.Now().Sub(start)
	pass := time.Since(start)
	fmt.Println("pass:", pass.Seconds())
	log.Println("avg speed: ", PrintSpeed(float64(len)/(pass.Seconds())))
}