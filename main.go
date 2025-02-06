package main

import (
	"encoding/base64"
	"fmt"
	"github.com/armon/go-socks5"
	"github.com/elazarl/goproxy"
	"github.com/spf13/viper"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	ipCache string
	oneJob  = &OneJob{}
)

// 添加认证中间件函数
func authMiddleware(proxyUser, proxyPass string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 获取代理认证头
		auth := r.Header.Get("Proxy-Authorization")
		if auth == "" {
			askForAuth(w)
			return
		}

		// 验证认证信息
		if !validateAuth(auth, proxyUser, proxyPass) {
			askForAuth(w)
			return
		}

		// 认证通过，继续处理
		next.ServeHTTP(w, r)
	})
}

func askForAuth(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy Authorization Required\"")
	w.WriteHeader(http.StatusProxyAuthRequired)

	_, err := w.Write([]byte("Proxy authentication required\n"))
	if err != nil {
		return
	}
}

func validateAuth(authHeader, user, pass string) bool {
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(authHeader[len(prefix):])
	if err != nil {
		return false
	}

	authString := strings.SplitN(string(decoded), ":", 2)
	if len(authString) != 2 {
		return false
	}

	return authString[0] == user && authString[1] == pass
}

// 修改SOCKS5配置部分
func createSocks5Server(user, pass string) (*socks5.Server, error) {
	authString := socks5.StaticCredentials{
		user: pass,
	}
	authenticator := socks5.UserPassAuthenticator{Credentials: authString}

	conf := &socks5.Config{
		AuthMethods: []socks5.Authenticator{authenticator},
	}

	return socks5.New(conf)
}

func RunOnce(vipConfig *viper.Viper) {
	domainName := vipConfig.GetString("CheckDomainName")
	dnsAddress := vipConfig.GetString("DnsAddress")
	ipTmp, err := GetIP(domainName, dnsAddress)
	if err != nil {
		fmt.Println("GetIP Error:", err)
		return
	}
	nowDir, _ := os.Getwd()
	if initOk := InitFrpArgs(nowDir, oneJob); initOk == false {
		fmt.Println("InitFrpArgs Error.")
		return
	}
	// 第一次
	if ipCache == "" {
		ipCache = ipTmp
		StartFrpThings(oneJob)
	} else {
		// 非第一次
		fmt.Println("Org IP:", ipCache)
		fmt.Println("New IP:", ipTmp)

		if ipTmp != ipCache {
			// 重新启动 Frp
			log.Printf("Close frp ...")
			closeFrp(oneJob)
			log.Printf("Close frp Done.")

			ipCache = ipTmp

			StartFrpThings(oneJob)
		}
	}
}

func RunTimer(vipConfig *viper.Viper) {
	defer func() {
		if oneJob.Running == true {
			closeFrp(oneJob)
		}

		if err := recover(); err != nil {
			fmt.Println(err)
		}

		log.Printf("Close Frp Done.")
	}()

	for {
		RunOnce(vipConfig)

		time.Sleep(time.Minute * time.Duration(5))
	}
}

func main() {
	vipConfig, err := InitConfigure()
	if err != nil {
		log.Fatalln("InitConfigure:", err)
		return
	}

	ipCache = ""

	go RunTimer(vipConfig)

	localProxyPort := vipConfig.GetInt("LocalProxyPort")
	localSocks5Port := vipConfig.GetInt("LocalSocks5Port")
	proxyUser := vipConfig.GetString("ProxyUser")
	proxyPass := vipConfig.GetString("ProxyPass")

	// 检查是否配置了认证信息
	if proxyUser == "" || proxyPass == "" {
		log.Fatal("Proxy authentication credentials are required")
	}

	// 开启 socks5 代理（带认证）
	go func() {
		server, err := createSocks5Server(proxyUser, proxyPass)
		if err != nil {
			panic(err)
		}

		log.Printf("SOCKS5 proxy with authentication enabled on :%d", localSocks5Port)
		if err := server.ListenAndServe("tcp", fmt.Sprintf("0.0.0.0:%d", localSocks5Port)); err != nil {
			panic(err)
		}
	}()

	// 开启 http 代理（带认证）
	go func() {
		proxy := goproxy.NewProxyHttpServer()
		proxy.Verbose = true

		// 包装原始handler加入认证
		authHandler := authMiddleware(proxyUser, proxyPass, proxy)

		log.Printf("HTTP proxy with authentication enabled on :%d", localProxyPort)
		log.Fatal(http.ListenAndServe(
			fmt.Sprintf("0.0.0.0:%d", localProxyPort),
			authHandler,
		))
	}()

	select {}
}

//func main() {
//
//	// -------------------------------------------------------------
//	// 加载配置
//	vipConfig, err := InitConfigure()
//	if err != nil {
//		log.Fatalln("InitConfigure:", err)
//		return
//	}
//
//	ipCache = ""
//
//	go RunTimer(vipConfig)
//
//	localProxyPort := vipConfig.GetInt("LocalProxyPort")
//	localSocks5Port := vipConfig.GetInt("LocalSocks5Port")
//	// 开启 socks5 代理
//	go func() {
//		// Create a SOCKS5 server
//		conf := &socks5.Config{}
//		server, err := socks5.New(conf)
//		if err != nil {
//			panic(err)
//		}
//		println("Open socks5 Port At:", localSocks5Port)
//		// Create SOCKS5 proxy on localhost port 8000
//		if err = server.ListenAndServe("tcp", fmt.Sprintf("0.0.0.0:%d", localSocks5Port)); err != nil {
//			panic(err)
//		}
//	}()
//	// 开启 http 代理
//	go func() {
//		proxy := goproxy.NewProxyHttpServer()
//		proxy.Verbose = true
//		println("Open http Port At:", localProxyPort)
//		//为了防止阿里云检测海外主机是否有翻墙行为我们把服务开在127.0.0.1,这样外网是检测不到你开了 httpproxy 的
//		log.Fatal(http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", localProxyPort), proxy))
//	}()
//
//	select {}
//}
