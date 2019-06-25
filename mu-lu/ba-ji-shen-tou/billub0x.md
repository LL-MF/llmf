# Billu: b0x

[https://www.vulnhub.com/entry/billu-b0x,188/](https://www.vulnhub.com/entry/billu-b0x,188/)

This Virtual machine is using ubuntu \(32 bit\)

Other packages used: -

PHP  
Apache  
MySQL

This virtual machine is having medium difficulty level with tricks.

One need to break into VM using web application and from there escalate privileges to gain root access

For any query ping me at [https://twitter.com/IndiShell1046](https://twitter.com/IndiShell1046)

Enjoy the machine

---

# 信息收集

首先需要找到靶机IP，使用Nmap

`nmap -sn 192.168.1.0/24`

结果如下

```go
Nmap scan report for 192.168.1.7
Host is up (0.00017s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:06:49:A0 (VMware)
```

访问其80端口得到一个登录框，上方提示Show me your SQLI skills

![](/media/TIM截图20190625111411.png)

猜测是SQL注入，逐一尝试，发现均提示Try again  
F12查看了一下元素，发现登录框是假的，无论提交什么信息都会通过js弹窗提示Try again


