
package fdb
import(
	"log"
	"sync"
	"container/list"
	"net"
	"packet"
	"fmt"
	"io"
	"time"
)

type Cio interface {
	io.Reader
	io.Writer
	Close() error
}

type Client struct {
	cio Cio
	//conn net.Conn
	pktchan chan packet.Packet 
	write_quit chan bool
	lock *sync.Mutex
	closed bool
	e *list.Element
	//UserMacList *list.List
}

func NewClient(io Cio) *Client{
	c := &Client{
		cio : io,
		pktchan : make(chan packet.Packet, 4096),
		write_quit : make(chan bool, 1),
		lock : new(sync.Mutex),
		closed : false,
		//UserMacList : list.New(),
	}
	e := PushClient(c)
	c.e = e
	log.Println("a conn have come: ", c.String())
	return c
}

func (c *Client) String() string {
	switch t := c.cio.(type) {
		case net.Conn:
			return fmt.Sprintf("local=%s, remote=%s", c.cio.(net.Conn).LocalAddr().String(), c.cio.(net.Conn).RemoteAddr().String())
		case *mytun:
			return fmt.Sprintf("tun name=%s", c.cio.(*mytun).Name())
		default:
			return fmt.Sprintf("unknown type =%v", t)
	}
	return "something wrong?"
}

func (c *Client) LocalString() string {
	switch t := c.cio.(type) {
		case net.Conn:
			return fmt.Sprintf("%s", c.cio.(net.Conn).LocalAddr().String())
		case *mytun:
			return fmt.Sprintf("%s", c.cio.(*mytun).Name())	
		default:
			return fmt.Sprintf("%v", t)
	}
	return "unknownClient"
}

func (c *Client) PutPktToChan(pkt packet.Packet) {
	if !c.closed {
		c.pktchan <- pkt
	}	
}

func (c *Client) WriteFromChan() {
	for {
		select {
			case pkt := <-c.pktchan:							
				_, err := c.cio.Write(pkt)
				if err != nil{
					c.Close()
					log.Printf(" WriteFromChan return, %s \n", c.String())
					return
				}
				// debug
				if *DebugEn && packet.TranEther(pkt[HeadSize:]).IsIpPtk() {
					iphdr, err := packet.ParseIPHeader(pkt[HeadSize + packet.EtherSize:])
					if err != nil {
						log.Println(err.Error())
					}
					fmt.Println("send info:", c.String(), iphdr.String())
				}
			case q, ok := <-c.write_quit:
				if !ok {
					log.Printf(" c.writeQuit is closed , quit the writefromchan  goroutine\n")		
				} else {
					log.Printf("chan write_quit recive message: quit=%v, ok=%v\n", q, ok)	
				}
				log.Printf(" WriteFromChan quit, %s \n", c.String())
				return
		}
	}
}

func (c *Client) Close() {	
	c.lock.Lock()
	if !c.closed {
		c.closed = true
		c.lock.Unlock()

		log.Printf(" %s  Closing  \n", c.String())
		c.cio.Close()	//now , there is nothing can be c.conn read(), 	means fdb can't be add by this conn		
		Fdb().DelFmnByClient(c) 
		RemoveClient(c) 
		c.write_quit <- true
		time.Sleep(time.Millisecond * 10)
		close(c.write_quit)
		close(c.pktchan)		
		log.Printf(" %s  Closed  \n", c.String())
		return	
	} 
	c.lock.Unlock()
}

type ClientList struct {
	Lock *sync.RWMutex
	List *list.List
}
var ClientLists *ClientList

func InitClientList(){
	ClientLists = &ClientList {
		Lock : new(sync.RWMutex),
		List : list.New(),
	}
}
func GetClientList() *list.List{
	return ClientLists.List
}
func PushClient(c *Client) *list.Element{
	ClientLists.Lock.Lock()
	e := GetClientList().PushBack(c)
	ClientLists.Lock.Unlock()
	log.Printf("after push, ClientLists.List.len =%d\n", GetClientList().Len())
	return e	
}
func RemoveClient(c *Client) {
	ClientLists.Lock.Lock()
	GetClientList().Remove(c.e)
	ClientLists.Lock.Unlock()
	log.Printf("after remove, ClientLists.List.len =%d\n", GetClientList().Len())	
}