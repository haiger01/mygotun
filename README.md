# mygotun
use tunnel (tun/tap) to build a virtual  lan 
使用tun/tap 虚拟网卡实现原始数据报文的读取及注入到协议栈，再用tcp 封装这些原始的数据包，发给服务器，服务器再转发到客户端，
客户端解封闭后，得到原始报文，再通过tap注入到协议栈，这样，可以创建虚拟局域网，类似vpn
