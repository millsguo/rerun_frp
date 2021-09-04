# rerun_frp

本项目的目标是检测某一个域名的 IP 是否标动，然后重启 frp 以重新连接。

默认是 10 分钟进行一次检测域名对应的 IP 变了没有。

同时开启本地的 http 代理

## Why

最近看了一个分享 [CreditTone/FuckingWallOfChina](https://github.com/CreditTone/FuckingWallOfChina)

然后根据这个，就打算把外面的一个服务器连接家里的 frps，当然是有动态外网 IP 的，参考个人魔改的 [allanpk716/ddns-go](https://github.com/allanpk716/ddns-go) 来使用。

具体这么做干嘛，需要你自己去摸索。任何风险请自行承担！

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
LocalProxyPort: 5269
LocalSocks5Port: 5270
```

### frpThings

这个是文件夹，里面有至少两个文件(**注意他们的命名**)

* frp
* frp.ini

一个是 frpc 主程序，一个是它的配置文件，怎么用建议看 frp 官网。
