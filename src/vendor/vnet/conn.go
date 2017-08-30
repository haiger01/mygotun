package vnet

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/felixge/tcpkeepalive"
)

type vnetConn struct {
	conn net.Conn
}

func NewVnetConn(conn net.Conn) *vnetConn {
	setTcpSockOpt(conn)
	return &vnetConn{
		conn: conn,
	}
}

func (vconn *vnetConn) Read(b []byte) (n int, err error) {
	var cr = bufio.NewReader(vconn.conn)
	var lenBuf []byte
	lenBuf, err = cr.Peek(HeadSize)
	if err != nil {
		log.Println("conn read fail:", err.Error())
		return
	}
	pktLen := int(binary.BigEndian.Uint16(lenBuf))
	if pktLen < 28 || pktLen > 1514 {
		if pktLen != HearBeatLen {
			log.Printf("parase pktLen=%d out of range \n", pktLen)
			err = errors.New("invaild pkt of vnetConn")
			return
		}
	}
	n, err = io.ReadFull(cr, b[:pktLen+HeadSize])
	if err != nil {
		log.Println("conn read fail:", err.Error())
		return
	}
	return
}

func (vc *vnetConn) Write(b []byte) (n int, err error) {
	return vc.conn.Write(b)
}

func (vc *vnetConn) Close() error {
	return vc.conn.Close()
}

func (vc *vnetConn) String() string {
	return fmt.Sprintf("%s<->%s", vc.conn.LocalAddr().String(), vc.conn.RemoteAddr().String())
}

func setTcpSockOpt(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		/*
			if err := setTCPUserTimeout(tcpConn, time.Second * TcpUserTimeout); err != nil {
				log.Printf("setTCPUserTimeout fail, err=%s\n", err.Error())
			}
		*/
		kaConn, err := tcpkeepalive.EnableKeepAlive(tcpConn)
		if err != nil {
			log.Println(tcpConn.RemoteAddr(), err)
		} else {
			kaConn.SetKeepAliveIdle(time.Duration(KeepAliveIdle) * time.Second)
			kaConn.SetKeepAliveCount(KeepAliveCnt)
			kaConn.SetKeepAliveInterval(time.Duration(KeepAliveIntv) * time.Second)
		}
	}
}
