package fdb

import (
	"github.com/lab11/go-tuntap/tuntap"
	"log"
	"fmt"
	"os/exec"
	"flag"
	"packet"
	"encoding/binary"
)

var (	
	DebugEn = flag.Bool("DebugEn", false, "debug, show ip packet information")
)

type mytun struct {
	tund *tuntap.Interface
}

func (tun *mytun) Name() string {
	return tun.tund.Name()
}

func (tun *mytun) Close() error {
	return tun.tund.Close()
}

func OpenTun(br string, tunname string, tuntype int, ipstr string) (tun *mytun, err error) {	
	tun = &mytun{}
	tun.tund, err = tuntap.Open(tunname, tuntap.DevKind(tuntype) , false)
	if err != nil {
		return nil, err
	}

	confs := fmt.Sprintf("ifconfig %s up\n", tunname)	
	if br != "" {
		confs += fmt.Sprintf("brctl addbr %s\n", br)
		confs += fmt.Sprintf("brctl addif %s %s\n", br, tunname)	
		if ipstr != "" {
			confs += fmt.Sprintf("ifconfig %s %s\n", br, ipstr)
		}
	} else if ipstr != "" {
		confs += fmt.Sprintf("ifconfig %s %s\n", tunname, ipstr)
	}

	err = exec.Command("sh","-c", confs).Run()
	if err != nil {
		return nil, err
	}

	fmt.Printf("================tun dev:%s open successfully==========\n", tun.tund.Name())
	return
}

func (tun *mytun) Read(buf []byte) (n int, err error) {
	var inpkt *tuntap.Packet
	n = 0	
	inpkt, err = tun.tund.ReadPacket2(buf[HeadSize:])
	//inpkt, err := tun.tund.ReadPacket()
	if err != nil {
		log.Println("==============tund.ReadPacket error===", err)
		//log.Fatal(err)
		return
	}
	n = len(inpkt.Packet)
	if n < 42 || n > 1514 {
		log.Printf("======tun read len=%d out of range =======\n", n)
		return
	}

	ether := packet.TranEther(inpkt.Packet)
	if ether.IsBroadcast() && ether.IsArp() {
		log.Println("---------arp broadcast from tun/tap ----------")
		log.Printf("dst mac :%s", ether.DstMac.String())
		log.Printf("src mac :%s", ether.SrcMac.String())
	}
	if !ether.IsArp() && !ether.IsIpPtk(){
		//mylog.Warning(" not arp ,and not ip packet, ether type =0x%0x%0x ===============\n", ether.Proto[0], ether.Proto[1])
		return
	}
	if *DebugEn && ether.IsIpPtk() {
		iphdr, err := packet.ParseIPHeader(inpkt.Packet[packet.EtherSize:])
		if err != nil {
			log.Printf("ParseIPHeader err: %s\n",err.Error())
		}
		log.Println("tun read ",iphdr.String())
	}
	binary.BigEndian.PutUint16(buf, uint16(n))
	copy(buf[HeadSize:], inpkt.Packet[:n])
	n += HeadSize
	return
}

func (tun *mytun) Write(pkt []byte) (n int, err error) {
	inpkt := &tuntap.Packet{Packet: pkt[HeadSize:]}
	err = tun.tund.WritePacket(inpkt)
	if err != nil {
		//log.Fatal(err)
		return
	}
	n = len(pkt)
	return
}
