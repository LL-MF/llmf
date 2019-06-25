端口[https://www.vulnhub.com/entry/billu-b0x,188/](https://www.vulnhub.com/entry/billu-b0x,188/)

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

```go
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

---

# 3.任意文件下载漏洞利用

（1）提交URL [http://192.168.1.7/test?file=/etc/passwd,依然提示file参数为空](http://192.168.1.7/test?file=/etc/passwd,依然提示file参数为空)  
（2）尝试将file以post请求提交

![](/media/TIM截图20190625162642.png)

成功下载到/etc/passwd文件  
（3）利用任意文件下载漏洞下载add.php、c.php、in.php、show.php、panel.php等其他文件

## 3.1 审计代码

对已下载的代码进行审计

### 3.1.1审计add.php

add.php是一个上传界面，源码如下

```php
<?php

echo '<form  method="post" enctype="multipart/form-data">
    Select image to upload:
    <input type="file" name=image>
    <input type=text name=name value="name">
    <input type=text name=address value="address">
    <input type=text name=id value=1337 >
    <input type="submit" value="upload" name="upload">
</form>';

?>
```

但是经过对add.php的源码审计发现，这个上传页面并不具有后台处理上传数据的功能，因此是不具有像服务器上传文件的功能的，这里应该是一个烟雾弹

### 3.1.2审计c.php

c.php是数据库连接文件，源码如下

```php
<?php
#header( 'Z-Powered-By:its chutiyapa xD' );
header('X-Frame-Options: SAMEORIGIN');
header( 'Server:testing only' );
header( 'X-Powered-By:testing only' );

ini_set( 'session.cookie_httponly', 1 );

$conn = mysqli_connect("127.0.0.1","billu","b0x_billu","ica_lab");

// Check connection
if (mysqli_connect_errno())
  {
  echo "connection failed ->  " . mysqli_connect_error();
  }
?>
```
从源码可以得到
用户名：billu  
密码：b0x\_billu  
数据库名：ica\_lab
但是这里有一个问题就是对服务器的端口扫描结果中mysql3306并未打开
### 3.1.3审计/etc/passwd
```go
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
mysql:x:102:105:MySQL Server,,,:/nonexistent:/bin/false
messagebus:x:103:106::/var/run/dbus:/bin/false
whoopsie:x:104:107::/nonexistent:/bin/false
landscape:x:105:110::/var/lib/landscape:/bin/false
sshd:x:106:65534::/var/run/sshd:/usr/sbin/nologin
ica:x:1000:1000:ica,,,:/home/ica:/bin/bash
```
从/etc/passwd中可以得到可用于SSH登陆的用户名
root
ica
该线索可用于爆破
### 3.1.4审计