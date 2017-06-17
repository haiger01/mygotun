
package fdb
import(
	"log"
	"sync"
	"container/list"
	"net"
	"packet"
)
type Client struct {
	conn net.Conn
	pktchan chan packet.Packet 
	write_quit chan bool
	lock *sync.Mutex
	closed bool
	e *list.Element
	//UserMacList *list.List
}

func NewClient(conn net.Conn) *Client{
	c := &Client{
		conn : conn,
		pktchan : make(chan packet.Packet, 4096),
		write_quit : make(chan bool, 1),
		lock : new(sync.Mutex),
		closed : false,
		//UserMacList : list.New(),
	}
	e := PushClient(c)
	c.e = e
	log.Println("a conn have come, remote ", conn.RemoteAddr())
	return c
}
func (c *Client) Conn() net.Conn {
	return c.conn
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
				_, err := c.conn.Write(pkt)
				if err != nil{
					c.Close()
					log.Printf(" WriteFromChan return, %s \n", c.conn.RemoteAddr().String())
					return
				}
			case <-c.write_quit:
				log.Printf(" WriteFromChan quit, %s \n", c.conn.RemoteAddr().String())
				return
		}
	}
}

func (c *Client) Close(){	
	c.lock.Lock()
	if !c.closed {
		c.closed = true
		c.lock.Unlock()

		log.Printf(" %s  Closing  \n", c.conn.RemoteAddr().String())
		c.conn.Close()	//now , there is nothing can be c.conn read(), 	means fdb can't be add by this conn		
		Fdb().DelFmnByClient(c) 
		RemoveClient(c) 
		c.write_quit <- true
		log.Printf(" %s  Closed  \n", c.conn.RemoteAddr().String())
		return	
	} 
	c.lock.Unlock()
}

type ClientList struct{
	Lock *sync.RWMutex
	List *list.List
}
var ClientLists *ClientList

func InitClientList(){
	ClientLists = &ClientList{
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