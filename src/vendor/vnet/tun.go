package vnet

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"mylog"
	"os/exec"
	"packet"
	"sync"

	"github.com/lab11/go-tuntap/tuntap"
)

var (
	obcDevSlot  [DevSlotMax]int
	DevSlotLock sync.Mutex
	Br          = flag.String("br", "", " add tun/tap to bridge")
	TunType     = flag.Int("tuntype", int(tuntap.DevTap), " type, 1 means tap and 0 means tun")
	TunName     = flag.String("tundev", "tap0", " tun dev name")
	Ipstr       = flag.String("ipstr", "", "set tun/tap or br ip address")
	//HQMode      = flag.Bool("hq", false, "HQ mode ,default false")
)

const (
	DevSlotMax = 100
)

func getDevId() int {
	DevSlotLock.Lock()
	defer DevSlotLock.Unlock()
	for i := 0; i < DevSlotMax; i++ {
		if obcDevSlot[i] == 0 {
			obcDevSlot[i] = 1
			return i
		}
	}
	log.Fatalln("can not find a vaild DevId\n")
	return -1
}

func putDevId(devId int) {
	if devId >= DevSlotMax || devId < 0 {
		log.Panicf("devId =%d is out range 0-%d\n", DevSlotMax)
	}
	DevSlotLock.Lock()
	obcDevSlot[devId] = 0
	DevSlotLock.Unlock()
}

type mytun struct {
	tund    *tuntap.Interface
	devType int
	devId   int
}

func NewTun(devType int) *mytun {
	return &mytun{
		devType: devType,
		devId:   getDevId(),
	}
}

func (tun *mytun) Name() string {
	return tun.tund.Name()
}

func OpenTun(br string, tunname string, tuntype int, ipstr string, auto bool) (tun *mytun, err error) {
	tun = NewTun(tuntype)
	if auto {
		tunname = tunname + fmt.Sprintf("%d", tun.devId)
	}
	mylog.Info("create dev :%s ,(devId:%d), *tuntype=%d\n", tunname, tun.devId, tuntype)

	tun.tund, err = tuntap.Open(tunname, tuntap.DevKind(tuntype), false)
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
	confs += fmt.Sprintf("ifconfig %s txqueuelen 5000\n", tunname)
	err = exec.Command("sh", "-c", confs).Run()
	if err != nil {
		mylog.Error("open err:%s, confs = %s \n", err.Error(), confs)
		return nil, err
	}

	log.Printf("================tun dev:%s open successfully==========\n", tun.tund.Name())
	return
}

func (tun *mytun) Read(buf []byte) (n int, err error) {
	var inpkt *tuntap.Packet
	n = 0
ReRead:
	inpkt, err = tun.tund.ReadPacket2(buf[HeadSize:])
	//inpkt, err := tun.tund.ReadPacket()
	if err != nil {
		log.Println("==============tund.ReadPacket error===", err)
		//log.Fatal(err)
		return
	}
	n = len(inpkt.Packet)
	if n < 28 || n > 1518 {
		log.Printf("======tun read len=%d out of range =======\n", n)
		err = errors.New("invaild pkt of vnetTun")
		return
	}

	if tun.devType == int(tuntap.DevTap) {
		ether := packet.TranEther(inpkt.Packet)
		if ether.IsBroadcast() && ether.IsArp() {
			log.Println("---------arp broadcast from tun/tap ----------")
			log.Printf("dst mac :%s", ether.DstMac.String())
			log.Printf("src mac :%s", ether.SrcMac.String())
		}
		if !ether.IsArp() && !ether.IsIpPtk() {
			mylog.Warning(" not arp ,and not ip packet, ether type =0x%0x%0x ===============\n", ether.Proto[0], ether.Proto[1])
			goto ReRead
			//err = errors.New("vnetFilter")
			//return
		}
		if *DebugEn && ether.IsIpPtk() {
			iphdr, err := packet.ParseIPHeader(inpkt.Packet[packet.EtherSize:])
			if err != nil {
				log.Printf("ParseIPHeader err: %s\n", err.Error())
			}
			log.Println("tun read ", iphdr.String())
		}
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
	n = len(pkt[HeadSize:])
	return
}

func (tun *mytun) Close() error {
	mylog.Notice("=====close dev =%s \n", tun.Name())
	cmd := fmt.Sprintf(`ip link delete %s`, tun.Name())
	err := exec.Command("sh", "-c", cmd).Run()
	if err != nil {
		mylog.Error("open err:%s, cmd = %s \n", err.Error(), cmd)
		log.Fatal(err)
	}
	mylog.Info("ip link delete %s over\n", tun.Name())

	putDevId(tun.devId)
	delete(tcMap, tun.Name())
	return tun.tund.Close()
}

func (tun *mytun) String() string {
	return fmt.Sprintf("tun dev name=%s,type=%d, id=%d", tun.Name(), tun.devType, tun.devId)
}
