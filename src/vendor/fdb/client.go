
package fdb
import(
	"log"
	"sync"
	"container/list"
	"net"
)
type Client struct {
	conn net.Conn
	e *list.Element
	//UserMacList *list.List
}

func NewClient(conn net.Conn) *Client{
	c := &Client{
		conn : conn,
		//UserMacList : list.New(),
	}
	e := PushClient(c)
	c.e = e
	log.Println("a conn have come, remote ",conn.RemoteAddr())
	return c
}
func (c *Client) Conn() net.Conn{
	return c.conn
}
func (c *Client) Close(){	
	//TODO: del fdb mac -> Client
	Fdb().DelFmnByClient(c)
	//del mactable fdb macnode first, and then close conn
	c.conn.Close()
	RemoveClient(c)
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
func RemoveClient(c *Client){
	ClientLists.Lock.Lock()
	GetClientList().Remove(c.e)
	ClientLists.Lock.Unlock()	
	log.Printf("after remove, ClientLists.List.len =%d\n", GetClientList().Len())
}