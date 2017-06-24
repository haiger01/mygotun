package packet


import (
	"fmt"
	"unsafe"
)
var(
	IpPtk [2]byte = [...]byte{0x08, 0x00}
	ArpPkt [2]byte = [...]byte{0x08, 0x06}
	BroadcastAddr [6]byte = [...]byte{0xff,0xff,0xff,0xff,0xff,0xff} 
	
)

type MAC [6]byte
type Packet []byte

type Ether struct {
	DstMac MAC
	SrcMac MAC
	Proto	[2]byte
}
func TranEther(b []byte) *Ether{
	/*
	p := Packet(b)
	return &Ether{
		DstMac : p.GetDstMac(),
		SrcMac : p.GetSrcMac(),
		Proto  : p.GetProto(),
	}
	*/
	return (*Ether)(unsafe.Pointer(&b[0]))
}

func (e *Ether) IsBroadcast() bool{
	return e.DstMac == BroadcastAddr
}
func (e *Ether) IsArp() bool{
	return e.Proto == ArpPkt
}
func (e *Ether) IsIpPtk() bool{
	return e.Proto == IpPtk
}

func (p *Packet) GetDstMac() MAC{
	return MAC{(*p)[0],(*p)[1],(*p)[2],(*p)[3],(*p)[4],(*p)[5]}
}
func (p *Packet) GetSrcMac() MAC{
	return MAC{(*p)[6],(*p)[7],(*p)[8],(*p)[9],(*p)[10],(*p)[11]}
}
func (p *Packet) GetProto() [2]byte{
	return [2]byte{(*p)[12], (*p)[13]}
}
func (p *Packet) IsBroadcast() bool{
	return p.GetDstMac() == BroadcastAddr
}
func (p *Packet) IsArp() bool{
	return p.GetProto() == ArpPkt
}
func (p *Packet) IsIpPtk() bool{
	return p.GetProto() == IpPtk
}

func (m MAC) String() string{
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",m[0],m[1],m[2],m[3],m[4],m[5])
}
func PrintMac(m MAC) string{
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",m[0],m[1],m[2],m[3],m[4],m[5])
}
