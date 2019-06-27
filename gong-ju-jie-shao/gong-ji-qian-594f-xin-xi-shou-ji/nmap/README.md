# Nmap

```text
nmap –iflist : 查看本地主机的接口信息和路由信息 -A ：选项用于使用进攻性方式扫描 -T4： 指定扫描过程使用的时序，总有6个级别（0-5），级别越高，扫描速度越快，但也容易被防火墙或IDS检测并屏蔽掉，在网络通讯状况较好的情况下推荐使用T4 -oX test.xml： 将扫描结果生成 test.xml 文件 -oG test.txt: 将扫描结果生成 test.txt 文件 -sn : 只进行主机发现，不进行端口扫描 -O : 指定Nmap进行系统版本扫描 -sV: 指定让Nmap进行服务版本扫描 -p <port ranges>: 扫描指定的端口 -sS/sT/sA/sW/sM:指定使用 TCP SYN/Connect()/ACK/Window/Maimon scans的方式来对目标主机进行扫描 -sU: 指定使用UDP扫描方式确定目标主机的UDP端口状况 -script <script name> : 指定扫描脚本 -Pn ： 不进行ping扫描 -sP : 用ping扫描判断主机是否存活，只有主机存活，nmap才会继续扫描，一般最好不加，因为有的主机会禁止ping -PI : 设置这个选项，让nmap使用真正的ping(ICMP echo请求)来扫描目标主机是否正在运行。 -iL 1.txt : 批量扫描1.txt中的目标地址 -sL: List Scan 列表扫描，仅将指定的目标的IP列举出来，不进行主机发现 -sY/sZ: 使用SCTP INIT/COOKIE-ECHO来扫描SCTP协议端口的开放的情况 -sO: 使用IP protocol 扫描确定目标机支持的协议类型
-PO : 使用IP协议包探测对方主机是否开启 
-PE/PP/PM : 使用ICMP echo、 ICMP timestamp、ICMP netmask 请求包发现主机
-PS/PA/PU/PY : 使用TCP SYN/TCP ACK或SCTP INIT/ECHO方式进行发现

-sN/sF/sX: 指定使用TCP Null, FIN, and Xmas scans秘密扫描方式来协助探测对方的TCP端口状态
-e eth0：指定使用eth0网卡进行探测
-f : --mtu <val>: 指定使用分片、指定数据包的 MTU.
-b <FTP relay host>: 使用FTP bounce scan扫描方式
-g： 指定发送的端口号
-r: 不进行端口随机打乱的操作（如无该参数，nmap会将要扫描的端口以随机顺序方式扫描，以让nmap的扫描不易被对方防火墙检测到）
-v 表示显示冗余信息，在扫描过程中显示扫描的细节，从而让用户了解当前的扫描状态
-n : 表示不进行DNS解析；
-D  <decoy1,decoy2[,ME],...>: 用一组 IP 地址掩盖真实地址，其中 ME 填入自己的 IP 地址
-R ：表示总是进行DNS解析。 
-F : 快速模式，仅扫描TOP 100的端口 
-S <IP_Address>: 伪装成其他 IP 地址
--ttl <val>: 设置 time-to-live 时间
--badsum: 使用错误的 checksum 来发送数据包（正常情况下，该类数据包被抛弃，如果收到回复，说明回复来自防火墙或 IDS/IPS）
--dns-servers  : 指定DNS服务器
--system-dns : 指定使用系统的DNS服务器   
--traceroute : 追踪每个路由节点 
--scanflags <flags>: 定制TCP包的flags
--top-ports <number> :扫描开放概率最高的number个端口
--port-ratio <ratio>: 扫描指定频率以上的端口。与上述--top-ports类似，这里以概率作为参数
--version-trace: 显示出详细的版本侦测过程信息
--osscan-limit: 限制Nmap只对确定的主机的进行OS探测（至少需确知该主机分别有一个open和closed的端口）
--osscan-guess: 大胆猜测对方的主机的系统类型。由此准确性会下降不少，但会尽可能多为用户提供潜在的操作系统
--data-length <num>: 填充随机数据让数据包长度达到 Num
--ip-options <options>: 使用指定的 IP 选项来发送数据包
--spoof-mac <mac address/prefix/vendor name> : 伪装 MAC 地址
--version-intensity <level>: 指定版本侦测强度（0-9），默认为7。数值越高，探测出的服务越准确，但是运行时间会比较长。
--version-light: 指定使用轻量侦测方式 (intensity 2)
--version-all: 尝试使用所有的probes进行侦测 (intensity 9)
--version-trace: 显示出详细的版本侦测过程信息
---------------------
```

