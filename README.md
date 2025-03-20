# rerun_frp
本项目fork自 https://github.com/allanpk716/rerun_frp ，感谢 @allanpk716

检测某一个域名的 IP 是否变动，然后重启 frp 以重新连接。如果目标断开，系统会在3分钟后自动重连，同时会检测目标域名IP是否变化

同时开启本地的 http、socks5 代理，本地代理支持用户认证，需要用户名/密码

## How to use

本程序运行在服务器上，由外网的服务器主动连接家里NAS上的frps

NAS上的frps可以使用docker部署 ，docker 的设置如下

设置网络位 Host

| Host/volume                 | Path in container |
|:----------------------------|:------------------|
| /your/rerun_frp/config.yaml | /app/config.yaml  |
| /your/rerun_frp/frpClient   | /app/frpClient    |

下面的配置为服务器上运行rerun_frp程序的配置文件
### config.yaml 

内容如下

```yaml
CheckDomainName : google.com #NAS的DDNS域名
DnsAddress: 8.8.8.8 #DNS服务器
LocalProxyPort: 5269 # 本地代理的端口
LocalSocks5Port: 5270 # 本地socks5代理的端口
ProxyUser: username # 本地代理的用户名，删除这二行，则代理不需要认证
ProxyPass: password # 本地代理的密码，删除这二行，则代理不需要认证
```

### frpClient

这个是文件夹，里面有至少两个文件(**注意他们的命名**)

* frpc
* frpc.ini

```
[common]
server_addr = 你的NAS的外网IP或域名
server_port = 7000 # frps的端口
token = # frps的token
tls_enable = true

[HTTP]
type = tcp
local_ip = 127.0.0.1
local_port = 5269 # 本地代理的端口
remote_port = 5271 # frps的端口

[SOCKS5]
type = tcp
local_ip = 127.0.0.1
local_port = 5270 # 本地代理的端口
remote_port = 5272 # frps的端口
```
frpc 是 frp 客户端程序
frpc.ini 是frpc的配置文件，具体参数建议看 frp 官网
