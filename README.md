# README
<h1>🍅GoRottenTomato🍅</h1>

![go](https://img.shields.io/badge/Go-1.17-blue)

## 简介
GoRottenTomato是为了深入学习AD域安全细节而进行的。闻之而不见，虽博必谬。这部分工具帮助我深入理解并学到了很多之前了解但是却不曾深入学习的技术细节。
使用格式：
```
./tomato [模块] [参数...]
./tomato //查看已有模块
./tomato asktgt //查看asktgt模块所需参数
```

## 模块介绍👽
### asktgt
<details>
<summary>👉asktgt详细参数</summary>

```
┌──(root💀kali)-[~/Desktop]
└─# ./tomato asktgt

 _____                      _        
/__   \___  _ __ ___   __ _| |_ ___  
  / /\/ _ \| '_ ` _ \ / _` | __/ _ \ 
 / / | (_) | | | | | | (_| | || (_) |
 \/   \___/|_| |_| |_|\__,_|\__\___/ 

  -dcIP string
        Target KDC's IP address
  -domain string
        Target domain name
  -etype string
        Kind of encryption key (rc4, aes128, aes256) (default "rc4")
  -hash string
        User's password hash
  -nopac
        Whether to include pac, default false
  -password string
        User's password
  -path string
        File save path
  -user string
        Username
``` 

</details>

![](README/7AFACBE8-0B4A-4508-BD7C-B926C8A40E67%202.png)

asktgt模块可以使用用户密码、哈希请求TGT（默认加密方式为rc4，也可以选择aes128和aes256），并且生成**Rubeus格式的Base64加密的TGT**，也可以指定path参数保存为.kirbi格式。还可以设置nopac参数决定是否包含pac（因为nopac参数是bool类型，需要等号连接）。


### asktgs
<details>
<summary>👉asktgs详细参数</summary>

```
                                                                                                                                                                     
┌──(root💀kali)-[~/Desktop]
└─# ./tomato asktgs

 _____                      _        
/__   \___  _ __ ___   __ _| |_ ___  
  / /\/ _ \| '_ ` _ \ / _` | __/ _ \ 
 / / | (_) | | | | | | (_| | || (_) |
 \/   \___/|_| |_| |_|\__,_|\__\___/ 

  -dcIP string
        Target KDC's IP address
  -domain string
        Target domain name
  -etype string
        Kind of encryption key (rc4, aes128, aes256) (default "rc4")
  -hash string
        User's password hash
  -nopac
        Whether to include pac, default false
  -password string
        User's password
  -path
        File save path, default false
  -service string
        services must be specified, comma separated
  -tgt string
        request TGS using the specified TGT (Base64TGT or .kirbi)
  -user string
        Username
```

</details>

![](README/4A1D5386-DBA1-411C-9FE9-289F4E136DD3%202.png)

asktgs模块允许使用Base64编码的TGT或者是.kirbi文件请求TGS，也可以提供账户信息先请求TGT再请求TGS，同时service参数可指定多个SPN分别请求TGS，例如**-service CIFS_DC1.test.com,host_DC1.test.com**。因为可能请求多个TGS，指定path参数为true时，将会按照固定名称格式保存TGS。

### describe
<details>
<summary>👉describe详细参数</summary>

```
┌──(root💀kali)-[~/Desktop]
└─# ./tomato describe

 _____                      _        
/__   \___  _ __ ___   __ _| |_ ___  
  / /\/ _ \| '_ ` _ \ / _` | __/ _ \ 
 / / | (_) | | | | | | (_| | || (_) |
 \/   \___/|_| |_| |_|\__,_|\__\___/ 

  -ticket string
        Ticket that needs to be decrypted (Base64TGT or .kirbi)
```

</details>

![](README/654526B1-5A82-43F8-BDE1-9F050C5DA323%202.png)

describe模块可以解析Base64编码的票据，也可以解析.kirbi文件

### renew
<details>
<summary>👉renew详细参数</summary>

```
┌──(root💀kali)-[~/Desktop]
└─# ./tomato renew 

 _____                      _        
/__   \___  _ __ ___   __ _| |_ ___  
  / /\/ _ \| '_ ` _ \ / _` | __/ _ \ 
 / / | (_) | | | | | | (_| | || (_) |
 \/   \___/|_| |_| |_|\__,_|\__\___/ 

  -dcIP string
        Target KDC's IP address
  -path string
        File save path
  -tgt string
        Tickets that need to be renew (Base64TGT or .kirbi)
  -till duration
        Ticket expiration date, default 7 days (default 168h0m0s)
```

</details>

![](README/76845782-DCCA-45D3-8FB7-81F8C062372D%202.png)
为指定的票据进行续订操作。

### asreproast
<details>
<summary>👉asreproast详细参数</summary>

```
┌──(root💀kali)-[~/Desktop]
└─# ./tomato asreproast

 _____                      _        
/__   \___  _ __ ___   __ _| |_ ___  
  / /\/ _ \| '_ ` _ \ / _` | __/ _ \ 
 / / | (_) | | | | | | (_| | || (_) |
 \/   \___/|_| |_| |_|\__,_|\__\___/ 

  -dcIP string
        Target KDC's IP address
  -domain string
        Target domain name
  -etype string
        Kind of encryption key (rc4, aes128, aes256) (default "rc4")
  -format string
        output format (john, hashcat) (default "john")
  -path string
        File save path
  -user string
        Username

```
</details>

![](README/15DE4525-15D7-4052-81CC-A4CBDC423BAB%202.png)

当发现用户设置为不需要预身份认证时，可使用asreproast获得john和hashcat格式的tgt进行爆破，指定path参数将会同时保存john和hashcat格式。

### s4u
<details>
<summary>👉s4u详细参数</summary>

```
┌──(root💀kali)-[~/Desktop]
└─# ./tomato s4u       

 _____                      _        
/__   \___  _ __ ___   __ _| |_ ___  
  / /\/ _ \| '_ ` _ \ / _` | __/ _ \ 
 / / | (_) | | | | | | (_| | || (_) |
 \/   \___/|_| |_| |_|\__,_|\__\___/ 

  -alter string
        Substitute in any service name
  -dcIP string
        Target KDC's IP address
  -domain string
        Target domain name
  -etype string
        Kind of encryption key (rc4, aes128, aes256) (default "rc4")
  -hash string
        User's password hash
  -impersonate string
        Account to be impersonated
  -nopac
        Whether to include pac, default false
  -password string
        User's password
  -save
        Whether to save the TGS, default false
  -service string
        target rbcd service
  -tgs string
        Base64 encoded TGS (Base64TGT or .kirbi)
  -tgt string
        Base64 encoded TGT (Base64TGT or .kirbi)
  -user string
        Username
```
</details>

![](README/6A16F06F-5CB4-44F7-A649-78051EE58920%202.png)
![](README/CB7898B3-AE3A-441F-9ED4-6AA9B3BE4D94%202.png)

s4u模块可以执行完整的ServiceForUser请求，此过程中，可以指定用户的TGT用于S4U2Self阶段的身份验证，也可以指定S4U2Proxy阶段所需要的票据（tgs参数），如果没有TGT，也可以凭借账户密码、哈希请求TGT并用于后续认证。

alter参数也可以指定多个需要修改的服务名称，需要注意的是，此参数与asktgs模块的稍有不同，例如**-alter cifs,host**等。

需要注意，impersonate参数是必须的，因为需要指定impersonate以获得ticket。

## TODO😬
* 支持ccache和kirbi文件的转换
* 支持ptt功能
* 支持LDAP查询

## 致谢🙏
asn1 && crypto
> https://github.com/jcmturner/gokrb5  

> https://github.com/GhostPack/Rubeus  

> https://github.com/gentilkiwi/kekeo  

## 免责声明🤝
本工具仅用于AD域安全**学习**，如您需要测试本工具请自行搭建靶场环境。如您使用此工具，请确保您的行为符合当地**法律法规**的要求，或已获得**合法授权**。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。
