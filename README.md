# rerun_frp
本项目fork自github.com/allanpk716/rerun_frp，感谢所有的贡献者

本项目的目标是检测某一个域名的 IP 是否标动，然后重启 frp 以重新连接。如果目标断开，系统会在3分钟后自动重连，同时会检测目标域名IP是否变化

同时开启本地的 http、socks5 代理，本地代理支持用户认证，需要用户名/密码

## How to use

docker 的设置如下

设置网络位 Host

| Host/volume                 | Path in container |
| :-------------------------- | :---------------- |
| /your/rerun_frp/config.yaml | /app/config.yaml  |
| /your/rerun_frp/frpThings   | /app/frpThings    |

### config.yaml 

内容如下

```yaml
CheckDomainName : google.com
DnsAddress: 8.8.8.8
LocalProxyPort: 5269
LocalSocks5Port: 5270
ProxyUser: username
ProxyPass: password
```

### frpThings

这个是文件夹，里面有至少两个文件(**注意他们的命名**)

* frp
* frp.ini

一个是 frpc 主程序，一个是它的配置文件，怎么用建议看 frp 官网。
