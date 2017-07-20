package fdb

import(
	"fmt"
	"log"
	"packet"
	"bufio"
	"io"
	"container/list"
	"encoding/binary"
	"net"
)

const (
	HeadSize = 2 //uint16 size
)

func flood(c *Client, pkt packet.Packet, len int) {
	log.Printf("-------------- flooding  ------------\n")
	var n *list.Element
	for e := GetClientList().Front(); e != nil;  e = n {
		n = e.Next()
		ci, ok := e.Value.(*Client)
		if !ok {
			log.Printf(" can't happend\n")
			GetClientList().Remove(e)
			continue			
		}

		if ci != c {
			//log.Println(c.Conn().RemoteAddr(), "write to", ci.Conn().RemoteAddr().Network(), ci.Conn().RemoteAddr().String())
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
var last *LastPkt

func (c *Client) ReadForward2() {
	defer c.Close()
	pkt := make(packet.Packet, 65536)
	last := &LastPkt{make([]byte, 1514+HeadSize), 0, 0}	
	for {				
		//len, err := c.Conn().Read(pkt)
		len, err := c.cio.Read(pkt)
		if err != nil{
			log.Println("conn read fail:", err.Error())			
			break
		}
		
		if len < 42 {
			log.Printf(" len =%d \n\n", len)
			continue
		}
		// TODO Parse the combine tcp packet 
		ParseFwdPkt(c, pkt, len, last)		
	}
}

func (c *Client) ReadForward() {
	defer c.Close()
	pkt := make(packet.Packet, 65536)
	cr := bufio.NewReader(c.cio)
	if _, ok := c.cio.(net.Conn); ok {
		for {
			// if err := binary.Read(cr, binary.BigEndian, &pktLen); err != nil {
			// 	log.Println("conn read fail:", err.Error())
			// 	c.Close()
			// 	break			
			// }
			lenBuf, err := cr.Peek(HeadSize)
			if err != nil {
				log.Println("conn read fail:", err.Error())			
				break
			}		
			pktLen := int(binary.BigEndian.Uint16(lenBuf))
			if pktLen < 42 || pktLen > 1514 {
				log.Printf("parase pktLen=%d out of range \n", pktLen)
				break
			}
			rn, err := io.ReadFull(cr, pkt[:pktLen+HeadSize])
			if err != nil {
				log.Println("conn read fail:", err.Error())
				break
			}
			//if err == nil , means rn == pktLen+HeadSize, so don't need to check 
			// if rn != pktLen+HeadSize {
			// 	log.Println(" something wrong, read rn=%d, pktLen+HeadSize =%d \n", rn, pktLen+HeadSize)
			// }
			data := make([]byte, rn)
			copy(data, pkt[:rn])
			ForwardPkt(c, data)
		}
	}

	if _, ok := c.cio.(*mytun); ok {
		for {
			rn, err := cr.Read(pkt)
			if err != nil {
				log.Println("conn read fail:", err.Error())			
				break
			}
			data := make([]byte, rn)
			copy(data, pkt[:rn])
			ForwardPkt(c, data)
		}
	}
}

func ParseFwdPkt(c *Client, pkt []byte, len int, last *LastPkt) {	
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()

	pktStart, pktEnd := 0, 0	
	n := 0
	for i := 0; pktEnd < len; i++ {
		//check the remaining work from last handle packet
		if last.needMore != 0 {
			if last.needMore <= len {		
				//copy to data and foward
				data := make([]byte, last.pktLen+last.needMore)
				copy(data, last.buf[:last.pktLen])
				copy(data[last.pktLen:], pkt[:last.needMore])				
				ForwardPkt(c, data)
				//set pktEnd
				pktEnd = last.needMore
				//reset last
				last.needMore = 0
				continue
			} else {
				fmt.Printf("can't be here, last.needMore=%d, totall len=%d\n", last.needMore, len)
				last.needMore = 0
				break;
			}
		}

		if pktEnd + HeadSize > len {
			fmt.Printf("something wrong: pktEnd=%d, totall len=%d\n", pktEnd, len)
			break;
			//panic("pktEnd + HeadSize > len")	
		}
		n =	int(binary.BigEndian.Uint16(pkt[pktEnd:]))
		if n < 42 || n > 1514 {
			log.Printf("======i=%d, error parse: pkt len unormal, n=%d, totall len=%d===========\n", i, n, len)
			break;
		}
		pktStart = pktEnd
		pktEnd = pktStart + HeadSize + n
		if pktEnd > len {
			//log.Printf("====== out of range, pktStart=%d, n=%d, pktEnd=%d, totall len=%d, handle it next read===========\n", 
			//				pktStart, n, pktEnd, len)
			copy(last.buf, pkt[pktStart:len])
			last.pktLen , last.needMore = len - pktStart, pktEnd - len
			break;
		}	
		// ok forwarding now	
		data := make([]byte, n+HeadSize)
		copy(data, pkt[pktStart:pktEnd])
		ForwardPkt(c, data)
	}
}

func ForwardPkt(c *Client, pkt []byte) {
	len := len(pkt)
	ether := packet.TranEther(pkt[HeadSize:])
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
			if fmn, ok := i.(*FdbMacNode); ok {
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