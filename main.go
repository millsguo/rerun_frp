package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/armon/go-socks5"
	"github.com/elazarl/goproxy"
	"github.com/spf13/viper"
)

// 新增端口检查函数
func isPortAvailable(port int) bool {
	address := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return false
	}
	defer func(listener net.Listener) {
		err := listener.Close()
		if err != nil {
			return
		}
	}(listener)
	return true
}

// 全局日志变量
var (
	logMu          sync.Mutex
	logFile        *os.File
	currentLogDate string
)

// 初始化日志系统
func init() {
	if err := os.MkdirAll("./log", 0755); err != nil {
		panic(fmt.Sprintf("创建日志目录失败: %v", err))
	}
	updateLogFile()
}

func updateLogFile() {
	now := time.Now()
	today := now.Format("20060102")

	logMu.Lock()
	defer logMu.Unlock()

	if currentLogDate == today && logFile != nil {
		return
	}

	// 关闭旧文件
	if logFile != nil {
		err := logFile.Close()
		if err != nil {
			return
		}
	}

	// 创建新文件
	filename := fmt.Sprintf("./log/log-%s.log", today)
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		panic(fmt.Sprintf("打开日志文件失败: %v", err))
	}

	logFile = file
	currentLogDate = today
}

func logMessage(msg string) {
	logMu.Lock()
	defer logMu.Unlock()

	// 再次检查日期防止其他goroutine已经更新
	now := time.Now()
	today := now.Format("20060102")
	if currentLogDate != today {
		updateLogFile()
	}

	// 格式化日志条目
	logEntry := fmt.Sprintf("%s %s\n", now.Format("2006-01-02 15:04:05"), msg)

	// 写入文件
	if _, err := logFile.WriteString(logEntry); err != nil {
		_, err := fmt.Fprintf(os.Stderr, "写入日志失败: %v\n", err)
		if err != nil {
			return
		}
	}

	// 同时输出到控制台
	fmt.Print(logEntry)
}

func logf(format string, args ...interface{}) {
	logMessage(fmt.Sprintf(format, args...))
}

var (
	ipCache    string
	ipCacheMu  sync.RWMutex
	oneJob     = &OneJob{}
	oneJobMu   sync.RWMutex
	shutdownCh = make(chan struct{})
)

func authMiddleware(proxyUser, proxyPass string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Proxy-Authorization")
		if auth == "" {
			askForAuth(w)
			return
		}

		if !validateAuth(auth, proxyUser, proxyPass) {
			askForAuth(w)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func askForAuth(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy Authorization Required"`)
	http.Error(w, "Proxy authentication required\n", http.StatusProxyAuthRequired)
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

	authParts := strings.SplitN(string(decoded), ":", 2)
	if len(authParts) != 2 {
		return false
	}

	return authParts[0] == user && authParts[1] == pass
}

func createSocks5Server(user, pass string) (*socks5.Server, error) {
	authData := make(socks5.StaticCredentials)
	authData[user] = pass

	authenticator := socks5.UserPassAuthenticator{Credentials: authData}
	return socks5.New(&socks5.Config{
		AuthMethods: []socks5.Authenticator{authenticator},
	})
}

func RunOnce(vipConfig *viper.Viper) {
	domainName := vipConfig.GetString("CheckDomainName")
	dnsAddress := vipConfig.GetString("DnsAddress")

	ipTmp, err := GetIP(domainName, dnsAddress)
	if err != nil {
		logf("获取远程IP失败，错误信息: %v", err)
		return
	}

	nowDir, _ := os.Getwd()
	if ok := InitFrpArgs(nowDir, oneJob); !ok {
		logf("Frp初始化失败")
		return
	}

	ipCacheMu.Lock()
	defer ipCacheMu.Unlock()

	if ipCache == "" {
		ipCache = ipTmp
		StartFrpThings(oneJob)
		return
	}

	logf("IP 检查 - 原IP: %s, 新IP: %s", ipCache, ipTmp)
	if ipTmp != ipCache {
		logf("IP 已改变, 重启FRP服务中...")

		oneJobMu.Lock()
		closeFrp(oneJob)
		ipCache = ipTmp
		StartFrpThings(oneJob)
		oneJobMu.Unlock()
	}
}

func RunTimer(vipConfig *viper.Viper) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			RunOnce(vipConfig)
		case <-shutdownCh:
			done := make(chan struct{})
			go func() {
				oneJobMu.Lock()
				defer oneJobMu.Unlock()
				if oneJob.Running {
					closeFrp(oneJob)
				}
				close(done)
			}()

			select {
			case <-done:
				logf("正常退出程序")
			case <-time.After(30 * time.Second):
				logf("警告：30秒后强制退出")
			}
			return
		}
	}
}

func startProxyServers(socksPort, httpPort int, user, pass string) {
	if user == "" || pass == "" {
		logf("启动无认证代理服务")
		startUnsecuredProxies(socksPort, httpPort)
	} else {
		logf("启动认证代理服务")
		startSecuredProxies(socksPort, httpPort, user, pass)
	}
}

func startUnsecuredProxies(socksPort, httpPort int) {
	go func() {
		if !isPortAvailable(socksPort) {
			logf("SOCKS5端口 %d 已被占用，跳过启动", socksPort)
			return
		}
		server, err := socks5.New(&socks5.Config{})
		if err != nil {
			log.Fatalf("SOCKS5 代理服务启动失败: %v", err)
		}
		logf("SOCKS5 简单代理服务启动成功，监听端口 :%d", socksPort)
		log.Fatal(server.ListenAndServe("tcp", fmt.Sprintf("0.0.0.0:%d", socksPort)))
	}()

	go func() {
		if !isPortAvailable(httpPort) {
			logf("HTTP端口 %d 已被占用，跳过启动", httpPort)
			return
		}
		proxy := goproxy.NewProxyHttpServer()
		proxy.Verbose = true
		logf("HTTP 简单代理服务启动成功，监听端口 :%d", httpPort)
		log.Fatal(http.ListenAndServe(
			fmt.Sprintf("0.0.0.0:%d", httpPort),
			proxy,
		))
	}()
}

func startSecuredProxies(socksPort, httpPort int, user, pass string) {
	go func() {
		if !isPortAvailable(socksPort) {
			logf("SOCKS5端口 %d 已被占用，跳过启动", socksPort)
			return
		}
		server, err := createSocks5Server(user, pass)
		if err != nil {
			log.Fatalf("SOCKS5 认证代理服务启动失败: %v", err)
		}
		logf("认证 SOCKS5 代理服务启动成功，监听端口 :%d", socksPort)
		log.Fatal(server.ListenAndServe("tcp", fmt.Sprintf("0.0.0.0:%d", socksPort)))
	}()

	go func() {
		if !isPortAvailable(httpPort) {
			logf("HTTP端口 %d 已被占用，跳过启动", httpPort)
			return
		}
		proxy := goproxy.NewProxyHttpServer()
		proxy.Verbose = true
		authHandler := authMiddleware(user, pass, proxy)

		logf("认证 HTTP 代理服务启动成功，监听端口 :%d", httpPort)
		log.Fatal(http.ListenAndServe(
			fmt.Sprintf("0.0.0.0:%d", httpPort),
			authHandler,
		))
	}()
}

func main() {
	vipConfig, err := InitConfigure()
	if err != nil {
		log.Fatalf("配置文件初始化失败: %v", err)
	}

	go RunTimer(vipConfig)

	localProxyPort := vipConfig.GetInt("LocalProxyPort")
	localSocks5Port := vipConfig.GetInt("LocalSocks5Port")
	proxyUser := vipConfig.GetString("ProxyUser")
	proxyPass := vipConfig.GetString("ProxyPass")

	startProxyServers(localSocks5Port, localProxyPort, proxyUser, proxyPass)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	<-sigCh
	logf("退出程序...")
	close(shutdownCh)
	time.Sleep(1 * time.Second) // 等待资源清理
}
