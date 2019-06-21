#探索目标主机是否在线

主机发现的原理与Ping命令类似，发送探测包到目标主机，如果收到回复，那么说明目标主机是开启的。Nmap支持十多种不同的主机探测方式，用户可以在不同的条件下灵活选用不同的方式来探测目标机。主机发现常用参数如下。
```
-sn: Ping Scan 只进行主机发现，不进行端口扫描。
-PE/PP/PM: 使用ICMP echo、 ICMP timestamp、ICMP netmask 请求包发现主机。
-PS/PA/PU/PY[portlist]: 使用TCP SYN/TCP ACK或SCTP INIT/ECHO方式进行发现。 

-sL: List Scan 列表扫描，仅将指定的目标的IP列举出来，不进行主机发现。 
-Pn: 将所有指定的主机视作开启的，跳过主机发现的过程。
-PO[protocollist]: 使用IP协议包探测对方主机是否开启。  
-n/-R: -n表示不进行DNS解析；-R表示总是进行DNS解析。  
--dns-servers <serv1[,serv2],...>: 指定DNS服务器。   
--system-dns: 指定使用系统的DNS服务器   
--traceroute: 追踪每个路由节点 
--------------------- 
```
##当探测公网 ip时
nmap -sn

Nmap会发送四种不同类型的数据包来探测目标主机是否在线。
```
    1.ICMP echo request
    2.a TCP SYN packet to port 443(https)
    3.a TCP ACK packet to port 80(http)
    4.an ICMP timestamp request
```
