package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"

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
	logBuffer      = make(chan string, 1000) // 增加日志缓冲区容量
	logClosed      = false                   // 标记日志是否已关闭
)

// 初始化日志系统
func init() {
	if err := os.MkdirAll("./log", 0755); err != nil {
		panic(fmt.Sprintf("创建日志目录失败: %v", err))
	}

	// 启动日志写入协程
	go logWriter()

	logMu.Lock() // 新增锁
	updateLogFile()
	logMu.Unlock()

	// 添加定时器（在初始化最后添加）
	go func() {
		// 设置UTC+8时区
		location, err := time.LoadLocation("Asia/Shanghai")
		if err != nil {
			location = time.FixedZone("UTC+8", 8*60*60)
		}

		for {
			now := time.Now().In(location)
			// 计算下一个UTC+8时区的零点
			next := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, location).Add(24 * time.Hour)
			time.Sleep(next.Sub(now))

			logMu.Lock()
			if !logClosed {
				updateLogFile() // 确保该函数已移除锁操作
			}
			logMu.Unlock()

			// 添加容错机制
			logf("已执行每日日志文件切换")
		}
	}()
}

// 日志写入协程
func logWriter() {
	for {
		select {
		case msg, ok := <-logBuffer:
			if !ok {
				// 通道已关闭，退出写入循环
				return
			}

			logMu.Lock()
			// 检查日志是否已关闭
			if logClosed || logFile == nil {
				logMu.Unlock()
				// 如果日志文件已关闭，直接输出到控制台
				fmt.Print(msg)
				continue
			}

			// 写入文件
			_, err := logFile.WriteString(msg)
			if err != nil {
				logf("写入日志失败: %v", err)
				logMu.Unlock()
				fmt.Print(msg)
				continue
			}
			// 立即刷新到磁盘
			err = logFile.Sync()
			if err != nil {
				logf("刷新日志到磁盘失败: %v", err)
			}
			logMu.Unlock()

			// 同时输出到控制台
			_, err = fmt.Print(msg)
			if err != nil {
				// 即使输出到控制台失败，也不应该影响日志写入
				// 这里我们只记录错误但不中断程序
			}
		}
	}
}

func updateLogFile() {
	// 创建日志目录
	if _, err := os.Stat("./log"); os.IsNotExist(err) {
		if err := os.MkdirAll("./log", 0755); err != nil {
			panic(fmt.Sprintf("紧急创建日志目录失败: %v", err))
		}
	}

	now := time.Now()
	today := now.Format("20060102")

	if currentLogDate == today && logFile != nil {
		return
	}

	// 关闭旧文件
	if logFile != nil {
		err := logFile.Close()
		if err != nil {
			// 即使关闭失败也继续执行
		}
	}

	// 创建新文件
	filename := fmt.Sprintf("./log/log-%s.log", today)
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		// 如果无法创建日志文件，继续运行但标记为已关闭
		logFile = nil
		logClosed = true
		logf("打开日志文件失败: %v", err)
		return
	}

	logFile = file
	logClosed = false
	currentLogDate = today
}

func logMessage(msg string) {
	logMu.Lock()
	defer logMu.Unlock()

	// 如果日志已关闭，直接输出到控制台
	if logClosed {
		fmt.Print(msg)
		return
	}

	// 再次检查日期防止其他goroutine已经更新
	now := time.Now()
	today := now.Format("20060102")
	if currentLogDate != today {
		updateLogFile()
	}

	// 格式化日志条目
	logEntry := fmt.Sprintf("%s.%03d %s\n",
		now.Format("2006-01-02 15:04:05"),
		now.Nanosecond()/1e6,
		msg)

	// 发送到缓冲区
	select {
	case logBuffer <- logEntry:
	default:
		// 如果缓冲区满了，直接写入
		if logFile != nil {
			_, err := logFile.WriteString(logEntry)
			if err != nil {
				logf("写入日志失败: %v", err)
			}
			err = logFile.Sync() // 确保写入磁盘
			if err != nil {
				logf("刷新日志到磁盘失败: %v", err)
			}
		}
		_, err := fmt.Print(logEntry)
		if err != nil {
			// 即使输出到控制台失败，也不应该影响程序运行
		}
	}
}

func logf(format string, args ...interface{}) {
	logMessage(fmt.Sprintf(format, args...))
	// 更新最后一次活动时间
	// 使用非阻塞方式更新活动时间，避免日志系统与FRP服务管理之间的死锁
	go func() {
		oneJobMu.Lock()
		defer oneJobMu.Unlock()
		if oneJob != nil {
			oneJob.LastActive = time.Now()
		}
	}()
}

// 优雅关闭日志系统
func closeLogger() {
	logMu.Lock()
	defer logMu.Unlock()

	// 标记日志系统为已关闭
	logClosed = true

	// 关闭日志文件
	if logFile != nil {
		err := logFile.Close()
		if err != nil {
			fmt.Printf("关闭日志文件失败: %v\n", err)
		}
		logFile = nil
	}

	// 关闭日志缓冲区通道
	close(logBuffer)
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
	//logf("开始执行FRP服务检查流程")

	domainName := vipConfig.GetString("CheckDomainName")
	dnsAddress := vipConfig.GetString("DnsAddress")
	//logf("配置参数 - Domain: %s, DNS: %s", domainName, dnsAddress)

	ipTmp, err := GetIP(domainName, dnsAddress)
	if err != nil {
		logf("获取远程IP失败，错误信息: %v", err)
		return
	}
	//logf("成功获取IP: %s", ipTmp)

	nowDir, _ := os.Getwd()
	//logf("当前工作目录: %s", nowDir)
	if ok := InitFrpArgs(nowDir, oneJob); !ok {
		logf("Frp初始化失败，请检查以下内容：")
		logf("1. frpc/frps可执行文件是否存在")
		logf("2. 配置文件模板是否完整")
		logf("3. 文件权限是否正确")
		return
	}

	ipCacheMu.Lock()
	defer ipCacheMu.Unlock()

	if ipCache == "" {
		ipCache = ipTmp
		logf("首次启动FRP服务，IP: %s", ipTmp)
		StartFrpThings(oneJob, vipConfig)
		return
	}

	if ipTmp != ipCache {
		// 检查FRPS服务器是否可达
		if !isFRPSAvailable(ipTmp, 7000) {
			logf("FRPS服务器 %s:7000 不可达，5分钟后再次检查", ipTmp)
			// 安排5分钟后再次检查
			time.AfterFunc(5*time.Minute, func() {
				oneJobMu.Lock()
				defer oneJobMu.Unlock()
				RunOnce(vipConfig)
			})
			return
		}

		logf("IP 已改变, 原IP: %s, 新IP: %s，重启FRP服务中...", ipCache, ipTmp)

		// 不再在锁内调用closeFrp，避免死锁
		logf("开始关闭当前FRP服务...")
		// 设置超时时间，避免无限等待
		closeDone := make(chan bool, 1)
		go func() {
			result := closeFrp(oneJob)
			closeDone <- result
		}()

		// 等待关闭完成，最多等待30秒
		select {
		case result := <-closeDone:
			if !result {
				logf("关闭FRP服务失败，尝试强制关闭...")
				oneJob.ForceClose()
			}
		case <-time.After(30 * time.Second):
			logf("关闭FRP服务超时，尝试强制关闭...")
			oneJob.ForceClose()
		}
		logf("FRP服务关闭完成")

		ipCache = ipTmp

		// 确保资源释放完成，增加等待时间
		logf("等待资源释放...")
		time.Sleep(5 * time.Second)

		// 更新FRPC配置文件中的服务器地址
		if err := updateFRPCConfig(nowDir, ipTmp); err != nil {
			logf("更新FRPC配置文件失败: %v", err)
			return
		}

		// 新增初始化检查
		nowDir, _ = os.Getwd()
		logf("重新初始化FRP参数...")
		if !InitFrpArgs(nowDir, oneJob) {
			logf("重启时初始化失败！")
			return
		}

		// 再次检查是否已经有运行中的进程，使用安全方法检查运行状态
		if oneJob.GetRunningState() {
			logf("检测到FRP服务仍在运行，强制关闭...")
			oneJob.ForceClose()
			logf("等待强制关闭完成...")
			time.Sleep(5 * time.Second)
		}

		logf("开始启动新的FRP服务...")
		StartFrpThings(oneJob, vipConfig)
		logf("FRP服务重启流程执行完成")
	} else {
		logf("IP未发生变化: %s", ipTmp)
	}
}

func RunTimer(vipConfig *viper.Viper) {
	// 立即执行第一次检查
	RunOnce(vipConfig) // 新增立即执行

	// 新增静默检测定时器
	monitorTicker := time.NewTicker(1 * time.Minute)
	defer monitorTicker.Stop()

	go func() {
		for {
			select {
			case <-monitorTicker.C:
				oneJobMu.Lock()
				// defer oneJobMu.Unlock()  // 移除在循环中使用defer

				if oneJob.Running && time.Since(oneJob.LastActive) > 5*time.Minute {
					logf("检测到FRP服务静默超时，可能处于STOP状态，触发重启")
					closeFrp(oneJob)
					ipCacheMu.Lock()
					ipCache = "" // 清空缓存强制重新获取IP
					ipCacheMu.Unlock()
					oneJob.LastActive = time.Now()
					oneJobMu.Unlock()     // 手动释放锁
					go RunOnce(vipConfig) // 异步执行避免持有锁时间过长
				} else {
					oneJobMu.Unlock() // 正常释放锁
				}
			case <-shutdownCh:
				return
			}
		}
	}()

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
	// 获取调用者的信息
	pc, file, line, ok := runtime.Caller(1)
	if ok {
		funcDetails := runtime.FuncForPC(pc)
		logf("Called from %s in file %s at line %d\n", funcDetails.Name(), file, line)
	} else {
		logf("Could not retrieve caller information")
	}
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
			logf("SOCKS5 代理服务启动失败: %v", err)
			os.Exit(1)
		}
		logf("SOCKS5 简单代理服务启动成功，监听端口 :%d", socksPort)
		if err := server.ListenAndServe("tcp", fmt.Sprintf("0.0.0.0:%d", socksPort)); err != nil {
			logf("SOCKS5 代理服务启动失败: %v", err)
			os.Exit(1)
		}
	}()

	go func() {
		if !isPortAvailable(httpPort) {
			logf("HTTP端口 %d 已被占用，跳过启动", httpPort)
			return
		}
		proxy := goproxy.NewProxyHttpServer()
		proxy.Verbose = true
		logf("HTTP 简单代理服务启动成功，监听端口 :%d", httpPort)
		if err := http.ListenAndServe(
			fmt.Sprintf("0.0.0.0:%d", httpPort),
			proxy,
		); err != nil {
			logf("HTTP 代理服务启动失败: %v", err)
			os.Exit(1)
		}
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
			logf("SOCKS5 认证代理服务启动失败: %v", err)
			os.Exit(1)
		}
		logf("认证 SOCKS5 代理服务启动成功，监听端口 :%d", socksPort)
		if err := server.ListenAndServe("tcp", fmt.Sprintf("0.0.0.0:%d", socksPort)); err != nil {
			logf("SOCKS5 认证代理服务启动失败: %v", err)
			os.Exit(1)
		}
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
		if err := http.ListenAndServe(
			fmt.Sprintf("0.0.0.0:%d", httpPort),
			authHandler,
		); err != nil {
			logf("认证 HTTP 代理服务启动失败: %v", err)
			os.Exit(1)
		}
	}()
}

func main() {
	logf("程序启动中...")

	vipConfig, err := InitConfigure()
	if err != nil {
		logf("配置文件初始化失败: %v", err)
		os.Exit(1)
	}

	logf("配置文件加载成功")

	vipConfig.WatchConfig()
	vipConfig.OnConfigChange(func(e fsnotify.Event) {
		oneJob.mu.Lock()
		defer oneJob.mu.Unlock()
		oneJob.maxAllowedRetries = vipConfig.GetInt("MaxRetries")
		logf("配置已热更新，当前最大重试次数：%d", oneJob.maxAllowedRetries)
	})

	go RunTimer(vipConfig)

	localProxyPort := vipConfig.GetInt("LocalProxyPort")
	localSocks5Port := vipConfig.GetInt("LocalSocks5Port")
	proxyUser := vipConfig.GetString("ProxyUser")
	proxyPass := vipConfig.GetString("ProxyPass")

	startProxyServers(localSocks5Port, localProxyPort, proxyUser, proxyPass)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh,
		os.Interrupt,
		syscall.SIGTERM,
		syscall.SIGHUP, // 增加hangup信号
		syscall.SIGQUIT,
	)

	logf("程序已启动，等待信号...")

	// 等待信号
	sig := <-sigCh
	logf("收到系统信号: %v，准备退出程序...", sig)

	// 关闭程序
	close(shutdownCh)
	logf("正在关闭FRP服务...")

	// 等待FRP服务关闭
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
		logf("FRP服务已关闭")
	case <-time.After(30 * time.Second):
		logf("警告：FRP服务关闭超时")
	}

	logf("正在关闭日志系统...")
	closeLogger()
	logf("程序已正常退出")
}
