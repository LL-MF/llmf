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

# 1.信息收集

## IP及服务发现

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

---

# 2.漏洞挖掘

访问其80端口得到一个登录框，上方提示Show me your SQLI skills

![](/media/TIM截图20190625111411.png)

## 2.1漏洞挖掘思路

```markdown
1.SQL注入：首页提示注入，验证是否存在可利用的SQL注入
2.爆破目录：使用dirb对站点目录进行爆破，寻找其他有价值的信息
3.漏洞扫描：使用AWVS等扫描攻击对站点进行扫描
4.手动挖掘：使用burp对各个页面进行分析，找出新漏洞
5.爆破SSH：目标服务器开放了22端口，可对22端口进行爆破
```

## 2.2尝试使用SQL注入

猜测是SQL注入，使用常用payload逐一尝试，发现js弹窗提示Try again

尝试使用sqlmap进行fuzz，但是没有成功，把他先放一放，先把目光转移到其他地方

## 2.3爆破目录

使用kali自带的目录爆破工具dirb对目录进行枚举

```
dirb http://192.168.1.7/ /usr/share/dirb/wordlists/big.txt 

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Jun 25 11:45:12 2019
URL_BASE: http://192.168.1.7/
WORDLIST_FILES: /usr/share/dirb/wordlists/big.txt

-----------------

GENERATED WORDS: 20458                                                         

---- Scanning URL: http://192.168.1.7/ ----
+ http://192.168.1.7/add (CODE:200|SIZE:307)                                                                          
+ http://192.168.1.7/c (CODE:200|SIZE:1)                                                                              
+ http://192.168.1.7/cgi-bin/ (CODE:403|SIZE:287)                                                                     
+ http://192.168.1.7/head (CODE:200|SIZE:2793)                                                                        
==> DIRECTORY: http://192.168.1.7/images/                                                                             
+ http://192.168.1.7/in (CODE:200|SIZE:47539)                                                                         
+ http://192.168.1.7/index (CODE:200|SIZE:3267)                                                                       
+ http://192.168.1.7/panel (CODE:302|SIZE:2469)                                                                       
==> DIRECTORY: http://192.168.1.7/phpmy/                                                                              
+ http://192.168.1.7/server-status (CODE:403|SIZE:292)                                                                
+ http://192.168.1.7/show (CODE:200|SIZE:1)                                                                           
+ http://192.168.1.7/test (CODE:200|SIZE:72)                                                                          
==> DIRECTORY: http://192.168.1.7/uploaded_images/                                                                    

---- Entering directory: http://192.168.1.7/phpmy/ ----
+ http://192.168.1.7/phpmy/ChangeLog (CODE:200|SIZE:28878)                                                            
+ http://192.168.1.7/phpmy/LICENSE (CODE:200|SIZE:18011)                                                              
+ http://192.168.1.7/phpmy/README (CODE:200|SIZE:2164)                                                                
+ http://192.168.1.7/phpmy/TODO (CODE:200|SIZE:190)                                                                   
+ http://192.168.1.7/phpmy/changelog (CODE:200|SIZE:8367)                                                                                                                                                             
-----------------
END_TIME: Tue Jun 25 11:45:52 2019
DOWNLOADED: 61374 - FOUND: 37
```

得到/add、/c、/in、/panel、/show、/test、/phpmy等目录  
访问192.168.1.7/test得到提示

![](/media/TIM截图20190625153845.png)
分析得到存在一个任意文件下载漏洞

# 3.漏洞利用

