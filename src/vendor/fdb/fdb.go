package fdb

import (
	"packet"
	"log"
	"sync"
	"time"
)
type FdbMac struct {
	mac packet.MAC
	ft uint64
}
type FDB struct{
	lock *sync.RWMutex
	mactable map[packet.MAC]*Client
}
var fdb *FDB
var FdbTick uint64
func Fdb() *FDB {
	return fdb
}
func FdbMacTable() map[packet.MAC]*Client {
	return Fdb().mactable
}
func init() {
	fdb = &FDB{
		lock : new(sync.RWMutex),
		mactable : make(map[packet.MAC]*Client),
	}
	InitClientList()
	go fdbtick()
}
func fdbtick() {
	FdbTick = 0
	tt := time.Tick(time.Second * 3)
	for _ = range tt {
		FdbTick = FdbTick + 1
	}
}
func (f *FDB) Get(m packet.MAC) (*Client, bool) {
	c, ok := f.mactable[m]
	return c, ok
}
func (f *FDB) Add(m packet.MAC, c *Client) {
	
	f.lock.Lock()
	f.mactable[m] = c
	f.lock.Unlock()
}
func (f *FDB) Del(m packet.MAC) {
	f.lock.Lock()
	delete(f.mactable, m)
	f.lock.Unlock()
}
func MtShowAll(){
	for m, c := range FdbMacTable() {
		log.Printf("mac =%s, c =%s\n", m.String(), c.conn.RemoteAddr())
	}
}