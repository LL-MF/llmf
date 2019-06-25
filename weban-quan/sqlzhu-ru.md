# 1.什么是SQL注入

SQL注入是指由于开发者未经安全处理或处理不完善，导致恶意攻击者可以通过Web提交的表单输入域或页面查询请求，将恶意构造的SQL语句带入到程序原有的SQL语句中，导致预期的SQL语句发生改变，从而执行攻击者所期望的SQL语句。SQL注入攻击一般是针对Web应用数据库的攻击，从而达到窃取或者修改数据库信息甚至是获取服务器权限的目的。
#2.SQL注入分类
注入的分类：数字型和字符型。攻击者目的只有一点，那就是绕过程序的限制，使用户输入的数据带入数据库执行，利用数据库的特殊性获取更多的信息或者更大的权限。
##2.1数字型注入
输入的参数为整形时，如果存在注入漏洞，可以认为是数字型注入。

测试步骤：

（1） 加单引号，URL：www.text.com/text.php?id=3’

对应的sql：select * from table where id=3’ 这时sql语句出错，程序无法正常从数据库中查询出数据，就会抛出异常；

（2） 加and 1=1 ,URL：www.text.com/text.php?id=3 and 1=1

对应的sql：select * from table where id=3’ and 1=1 语句执行正常，与原始页面如任何差异；

（3） 加and 1=2，URL：www.text.com/text.php?id=3 and 1=2

对应的sql：select * from table where id=3 and 1=2 语句可以正常执行，但是无法查询出结果，所以返回数据与原始网页存在差异

如果满足以上三点，则可以判断该URL存在数字型注入。
##2.2字符型注入
输入的参数为字符串时，称为字符型。字符型和数字型最大的一个区别在于，数字型不需要单引号来闭合，而字符串一般需要通过单引号来闭合的。

例如数字型语句：`select * from table where id =3`

则字符型如下：`select * from table where name='admin'`

因此，在构造payload时通过闭合单引号可以成功执行语句：

测试步骤：

（1） 加单引号：`select * from table where name='admin''`

由于加单引号后变成三个单引号，则无法执行，程序会报错；

（2） 加 `'and 1=1` 此时sql 语句为：`select * from table where name='admin' and 1=1'` ,也无法进行注入，还需要通过注释符号将其绕过；

Mysql 有三种常用注释符：

-- 注意，这种注释符后边有一个空格

\# 通过\#进行注释

/\* \*/ 注释掉符号内的内容

因此，构造语句为：`select * from table where name ='admin' and 1=1-- '` 可成功执行返回结果正确；

（3） 加and 1=2-- 此时sql语句为：`select * from table where name='admin' and 1=2-- '`则会报错

如果满足以上三点，可以判断该url为字符型注入。



