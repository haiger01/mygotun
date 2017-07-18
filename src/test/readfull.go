package main

import(
	"fmt"
	"net"
	"flag"
	"encoding/binary"
	"bytes"
	"time"
	"bufio"
	"io"
)

var (
	mode = flag.String("mode", "server", " client or server mode")
	lnAddr = flag.String("lnAddr", "127.0.0.1:4949", "lnaddr")
	serAddr = flag.String("serAddr", "127.0.0.1:4949", "serAddr")
	sleep =	flag.Int("sleep", 3, "sleep Millisecond")
)


func main() {
	flag.Parse()
	check()
	if *mode == "server" {
		server()
	} else {
		client()
	}	
}

func server() {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", *lnAddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	ln, err := net.ListenTCP("tcp4", tcpAddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	for {
		tcpConn, err := ln.AcceptTCP()
		if err != nil {
			fmt.Println(err)
			return
		}
		go handleConn(tcpConn)
	}

}

func handleConn(conn net.Conn) {
	defer conn.Close()
	data := make([]byte, 4096)
	cr := bufio.NewReader(conn)
	for {
		start := time.Now()
		//fmt.Println(start)
		lenBuf, err := cr.Peek(2)//block
		if err != nil {
			fmt.Println("conn read fail:", err.Error())			
			break
		}

		pktLen := int(binary.BigEndian.Uint16(lenBuf))
		fmt.Println("conn read pktLen:", pktLen)

		n, err := io.ReadFull(cr, data[:pktLen+2])//block, if fd close before read full, it will return unexepect EOF,
												//这样有个好处,如果pktLen==0,还能读2字节出来,再继续peek,但是最好当pktLen异常时，断开连接，重新连	
		if err != nil {
			fmt.Printf("io.ReadFull fail:%s, n=%d\n", err.Error(), n)			
			break
		}
		fmt.Printf("ReadFull, n=%d \n", n)
		fmt.Println(time.Now().Sub(start), time.Since(start))	
	}
	fmt.Printf("conn read quit \n")	
}

func client() {
	data := make([]byte, 900)
	//binary.BigEndian.PutUint16(data[:2], uint16(0))//test , server peek and pktLen==0
	binary.BigEndian.PutUint16(data[:2], uint16(298))
	binary.BigEndian.PutUint16(data[300:302], uint16(298))
	binary.BigEndian.PutUint16(data[600:602], uint16(298))

	tcpAddr, err := net.ResolveTCPAddr("tcp4", *serAddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	tcpConn, err := net.DialTCP("tcp4", nil, tcpAddr)
	if err != nil {
		fmt.Println( err)
		return
	}
	tcpConn.SetNoDelay(true)

	// t := *sleep
	// time.Sleep(time.Millisecond * time.Duration(t))
	time.Sleep(time.Second)
	wn, err := tcpConn.Write(data[:500])
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("write one %d\n", wn)
	

	//time.Sleep(time.Millisecond * time.Duration(t))
	time.Sleep(time.Second)
	wn, err = tcpConn.Write(data[500:550])
	if err != nil {
		fmt.Println(wn, err)
		return
	}
	fmt.Printf("write second %d\n", wn)
	time.Sleep(time.Second * 100)
	tcpConn.Close()
	return
	time.Sleep(time.Second * 1)
	wn, err = tcpConn.Write(data[550:900])
	if err != nil {
		fmt.Println(wn, err)
		return
	}
	fmt.Printf("write third %d\n", wn)

	time.Sleep(time.Second * 100)

	fmt.Printf("  quit \n")	
}

func check() {
	var n int
	var err error	
	data := make([]byte, 20)
	buf := bytes.NewBuffer(make([]byte, 20))
	d1 := make([]byte, 8)


	err = binary.Write(buf, binary.BigEndian, uint16(8))
	if err != nil {
		fmt.Println(err)
		return
	}
	d1[0]=1
	n, err = buf.Write(d1)
	if err != nil || n != 8 {
		fmt.Println(n, err)
		return
	}
	
	err = binary.Write(buf, binary.BigEndian, uint16(8))
	if err != nil {
		fmt.Println( err)
		return
	}
	d1[0]=2
	n, err = buf.Write(d1)
	if err != nil || n != 8 {
		fmt.Println(n, err)
		return
	}	
	len1 := binary.BigEndian.Uint16(buf.Bytes()[:2])
	len2 := binary.BigEndian.Uint16(buf.Bytes()[10:12])
	fmt.Println(len(data), len(buf.Bytes()))
	fmt.Println(len1, len2, buf.Bytes())

	dd := []byte{1,2,3}
	bb := bytes.NewBuffer(dd)
	binary.Write(bb, binary.BigEndian, uint16(8))
	binary.Write(bb, binary.BigEndian, uint16(8))
	fmt.Println( bb.Bytes())
}
/* bytes.NewBuffer(data)，会在data上扩展内存啊
20 40
0 0 [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 8 1 0 0 0 0 0 0 0 0 8 2 0 0 0 0 0 0 0]
[1 2 3 0 8 0 8]

*/

/*
func client() {
	var n int
	var err error	
	data := make([]byte, 900)
	buf := bytes.NewBuffer(data)
	d1 := make([]byte, 298)


	err = binary.Write(buf, binary.BigEndian, uint16(298))
	if err != nil {
		fmt.Println(err)
		return
	}
	d1[0]=1
	n, err = buf.Write(d1)
	if err != nil || n != 298 {
		fmt.Println(n, err)
		return
	}

	err = binary.Write(buf, binary.BigEndian, uint16(298))
	if err != nil {
		fmt.Println( err)
		return
	}
	d1[0]=2
	n, err = buf.Write(d1)
	if err != nil || n != 298 {
		fmt.Println(n, err)
		return
	}

	err = binary.Write(buf, binary.BigEndian, uint16(298))
	if err != nil {
		fmt.Println(err)
		return
	}
	d1[0]=3
	n, err = buf.Write(d1)	
	if err != nil || n != 298 {
		fmt.Println(n, err)
		return
	}
	
	tcpAddr, err := net.ResolveTCPAddr("tcp4", *serAddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	tcpConn, err := net.DialTCP("tcp4", nil, tcpAddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	tcpConn.SetNoDelay(true)

	wn, err := tcpConn.Write(buf.Bytes()[:500])
	if err != nil {
		fmt.Println(wn, err)
		return
	}
	fmt.Printf("write one %d\n", wn)
	
	t := *sleep
	time.Sleep(time.Millisecond * time.Duration(t))
	wn, err = tcpConn.Write(buf.Bytes()[500:900])
	if err != nil {
		fmt.Println(wn, err)
		return
	}
	fmt.Printf("write second %d\n", wn)
	time.Sleep(time.Second * 1)

	fmt.Printf("  quit \n")		
}
*/