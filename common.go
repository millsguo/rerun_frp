package main

import (
	"bufio"
	"context"
	"errors"
	"github.com/spf13/viper"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type OneJob struct {
	Ctx               context.Context
	Cmder             *exec.Cmd
	Cancel            func()
	Err               error
	CmdLine           string
	CmdArgs           []string
	Running           bool
	mu                sync.Mutex         // 保护所有字段
	retryTimer        *time.Timer        // 重试定时器
	retryCancel       context.CancelFunc // 取消重试
	vipConfig         *viper.Viper       // 新增配置引用
	lastActive        time.Time
	retryCount        int
	maxAllowedRetries int // 记录当前最大允许值
}

// 新增方法：安全设置运行状态
func (j *OneJob) setRunning(running bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Running = running
}

// 新增方法：安全获取运行状态
func (j *OneJob) isRunning() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Running
}

// 新增方法：调度重试
func (j *OneJob) scheduleRetry() {
	j.mu.Lock()
	defer j.mu.Unlock()

	// 获取配置值并设置默认
	configuredMax := j.vipConfig.GetInt("MaxRetries")
	if configuredMax < 0 { // 处理非法配置
		configuredMax = 0
	}
	j.maxAllowedRetries = configuredMax // 存储当前允许值

	// 自动设置默认策略
	if j.maxAllowedRetries == 0 {
		j.maxAllowedRetries = 3 // 默认重试3次
	} else if j.maxAllowedRetries > 100 {
		j.maxAllowedRetries = 100 // 安全上限
	}

	// 提前检查重试资格
	if j.retryCount >= j.maxAllowedRetries {
		logf("已达到硬性重试上限 %d 次，停止重试", j.maxAllowedRetries)
		j.cleanupRetryResources()
		return
	}

	// 标准指数退避算法（含随机因子）
	baseDelay := 3 * time.Minute
	maxDelay := 60 * time.Minute
	delay := baseDelay * time.Duration(1<<uint(j.retryCount))
	delay = time.Duration(float64(delay) * (1 + 0.2*rand.Float64())) // 增加20%随机抖动

	if delay > maxDelay {
		delay = maxDelay
	}

	// 更新计数器前检查
	if j.retryTimer != nil {
		j.retryTimer.Stop()
	}
	j.retryCount++

	logf("第 %d 次重试将在 %.1f 分钟后触发 (配置上限:%d)",
		j.retryCount, delay.Minutes(), j.maxAllowedRetries)

	// 创建带取消机制的重试上下文
	ctx, cancel := context.WithCancel(context.Background())
	j.retryCancel = cancel

	j.retryTimer = time.AfterFunc(delay, func() {
		oneJobMu.Lock()
		defer oneJobMu.Unlock()

		// 双重检查运行状态
		if j.isRunning() || j.retryCount > j.maxAllowedRetries {
			logf("重试条件已失效，放弃执行")
			return
		}

		// 执行前清空IP缓存
		ipCacheMu.Lock()
		ipCache = ""
		ipCacheMu.Unlock()

		RunOnce(j.vipConfig)
	})

	// 上下文清理协程
	go func() {
		<-ctx.Done()
		j.mu.Lock()
		j.retryTimer = nil
		j.mu.Unlock()
	}()
}

// 新增资源清理方法
func (j *OneJob) cleanupRetryResources() {
	if j.retryCancel != nil {
		j.retryCancel()
		j.retryCancel = nil
	}
	j.retryCount = 0 // 重置计数器
	j.maxAllowedRetries = 0
}

func FileExist(path string) bool {
	_, err := os.Lstat(path)
	return !os.IsNotExist(err)
}

func InitFrpArgs(nowDir string, oneJob *OneJob) bool {
	// 添加路径验证
	frpBinPath := filepath.Join(nowDir, "/frpClient/frpc") // 或 frps
	if _, err := os.Stat(frpBinPath); os.IsNotExist(err) {
		logf("FRP可执行文件不存在于: %s", frpBinPath)
		return false
	}
	//logf("FRP可执行文件路径: %s", frpBinPath)

	// 验证配置文件生成逻辑
	configPath := filepath.Join(nowDir, "/frpClient/frpc.ini")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		logf("配置文件生成失败，路径: %s", configPath)
		return false
	}
	//logf("配置文件路径: %s", configPath)

	nowDir = nowDir + string(os.PathSeparator) + "frpClient" + string(os.PathSeparator)
	absPathFrp := nowDir + "frpc"
	absPathFrpIni := nowDir + "frpc.ini"

	if runtime.GOOS == "windows" {
		absPathFrp += ".exe"
	}

	if !FileExist(absPathFrp) {
		logf(absPathFrp, "不存在")
		return false
	}
	if !FileExist(absPathFrpIni) {
		logf(absPathFrpIni, "不存在")
		return false
	}

	oneJob.CmdLine = absPathFrp
	oneJob.CmdArgs = []string{"-c", absPathFrpIni}
	//logf("FRP可执行文件路径: %s", absPathFrp)
	//logf("命令执行成功：%s", oneJob.CmdLine)
	return true
}

func StartFrpThings(oneJob *OneJob, vipConfig *viper.Viper) bool {
	oneJob.vipConfig = vipConfig // 注入配置

	if oneJob.isRunning() {
		return false
	}

	logf("启动FRP服务...")
	startFrp(oneJob)
	if oneJob.Err != nil {
		logf("启动失败:%v", oneJob.Err)
		oneJob.scheduleRetry()
		return false
	}
	logf("FRP服务启动成功")
	return true
}

func closeFrp(oneJob *OneJob) bool {
	logf("关闭FRP服务...")

	// 清理重试机制
	oneJob.mu.Lock()
	if oneJob.retryCancel != nil {
		oneJob.retryCancel()
		oneJob.retryCancel = nil
	}
	if oneJob.retryTimer != nil {
		oneJob.retryTimer.Stop()
		oneJob.retryTimer = nil
	}

	// 获取当前状态
	var cmder *exec.Cmd
	var cancelFunc func()
	if oneJob.Cmder != nil {
		cmder = oneJob.Cmder
	}
	if oneJob.Cancel != nil {
		cancelFunc = oneJob.Cancel
	}
	oneJob.mu.Unlock()

	// 执行关闭操作
	if cancelFunc != nil {
		cancelFunc()
	}

	if cmder != nil && cmder.Process != nil {
		logf("终止进程 PID:%d\n", cmder.Process.Pid)
		if err := cmder.Process.Signal(os.Interrupt); err != nil {
			logf("发送中断信号失败:%v", err)
		}

		// 异步等待终止
		// 优化异步等待逻辑
		done := make(chan struct{})
		go func() {
			defer close(done)
			select {
			case <-time.After(5 * time.Second):
				if err := cmder.Process.Kill(); err != nil {
					logf("强制终止失败:%v", err)
				}
			case <-oneJob.Ctx.Done(): // 新增上下文监听
				return
			}
		}()

		// 新增同步等待
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			logf("警告：进程终止超时")
		}
	} else {
		logf("无运行中的进程")
	}

	killFrpProcesses()
	oneJob.setRunning(false)
	logf("FRP服务关闭完成")
	return true
}

func killFrpProcesses() {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin", "linux":
		cmd = exec.Command("pkill", "-f", "frp")
	case "windows":
		cmd = exec.Command("taskkill", "/F", "/IM", "frp.exe")
	default:
		logf("不支持的操作系统")
		return
	}

	if err := cmd.Run(); err != nil {
		logf("清理残留进程失败:%v", err)
	}
}

func startFrp(oneJob *OneJob) {
	oneJob.mu.Lock()
	oneJob.retryCount = 0
	oneJob.maxAllowedRetries = 0
	oneJob.Ctx, oneJob.Cancel = context.WithCancel(context.Background())
	oneJob.mu.Unlock()

	defer func() {
		if oneJob.Err != nil {
			oneJob.mu.Lock()
			if oneJob.Cancel != nil {
				oneJob.Cancel()
			}
			oneJob.mu.Unlock()
		}
	}()

	oneJob.mu.Lock()
	oneJob.Cmder = exec.CommandContext(oneJob.Ctx, oneJob.CmdLine, oneJob.CmdArgs...)
	cmder := oneJob.Cmder
	oneJob.mu.Unlock()

	stdout, err := cmder.StdoutPipe()
	if err != nil {
		oneJob.Err = err
		logf("标准输出管道错误:%v", err)
		return
	}

	stderr, err := cmder.StderrPipe()
	if err != nil {
		oneJob.Err = err
		logf("标准错误管道错误:%v", err)
		return
	}

	// 添加启动时间记录
	startTime := time.Now()
	if err := cmder.Start(); err != nil {
		oneJob.Err = err
		logf("启动失败 (耗时%s): %v\n", time.Since(startTime), err)
		return
	}
	oneJob.lastActive = startTime

	oneJob.setRunning(true)
	logf("进程已启动 PID:%d (耗时%s)\n", cmder.Process.Pid, time.Since(startTime))

	//启动健康检查
	go oneJob.healthCheck()

	// 日志处理
	scanOutput := func(input io.Reader, name string) {
		scanner := bufio.NewScanner(input)
		for scanner.Scan() {
			line := scanner.Text()
			logf("[FRP-%s] %s\n", name, line)
			// 修改日志扫描逻辑，增加特定错误检测
			if strings.Contains(line, "i/o timeout") ||
				strings.Contains(line, "connection refused") ||
				strings.Contains(line, "no such host") {
				logf("检测到连接错误，触发强制IP检查")
				go func() {
					oneJobMu.Lock()
					defer oneJobMu.Unlock()
					closeFrp(oneJob)
					ipCache = ""              // 清空缓存强制重新获取IP
					RunOnce(oneJob.vipConfig) // 需要将vipConfig传递到OneJob结构体中
				}()
			}
			if strings.Contains(line, "retry") || strings.Contains(line, "error") {
				logf("检测到错误关键词，准备重试...")
				oneJob.scheduleRetry()
			}
		}
	}

	go scanOutput(stdout, "stdout")
	go scanOutput(stderr, "stderr")

	// 进程监控
	// 修改进程监控部分
	go func() {
		err := cmder.Wait()
		duration := time.Since(startTime)

		oneJob.mu.Lock()
		defer oneJob.mu.Unlock()

		oneJob.Running = false
		oneJob.Cmder = nil

		// 新增统一异常处理
		handleProcessExit := func() {
			if err != nil {
				exitCode := 0
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					exitCode = exitErr.ExitCode()
				}
				logf("进程异常退出 (code:%d 时长%s): %v", exitCode, duration, err)

				// 新增统一重试策略
				if duration < 30*time.Second || exitCode != 0 {
					logf("触发自动重试机制")
					oneJob.scheduleRetry()
				}
			} else {
				logf("进程正常退出 (运行时长%s)", duration)
				// 新增正常退出后的保活机制
				if oneJob.vipConfig.GetBool("AutoRestart") {
					oneJob.scheduleRetry()
				}
			}
		}

		handleProcessExit()
	}()
}

// 新增健康检查方法
func (j *OneJob) healthCheck() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	logf("当前重试状态: %d/%d", j.retryCount, j.maxAllowedRetries)
	for {
		select {
		case <-ticker.C:
			j.mu.Lock()
			if time.Since(j.lastActive) > 5*time.Minute {
				logf("检测到进程僵死，触发重启")
				j.mu.Unlock()
				closeFrp(j)
				j.scheduleRetry()
				return
			}
			j.mu.Unlock()
		case <-j.Ctx.Done():
			return
		}
	}
}

// GetIP 函数保持不变
func GetIP(domainName string, dnsAddress string) (string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			return d.DialContext(ctx, "udp", dnsAddress+":53")
		},
	}

	// 获取所有类型的IP地址
	addr, err := resolver.LookupHost(context.Background(), domainName)
	if err != nil {
		return "", err
	}

	// 过滤IPv4地址
	var ipv4Address []string
	for _, a := range addr {
		ip := net.ParseIP(a)
		if ip != nil && ip.To4() != nil {
			ipv4Address = append(ipv4Address, a)
		}
	}

	// 处理过滤后的结果
	var result string
	switch len(ipv4Address) {
	case 0:
		result = ""
	case 1:
		result = ipv4Address[0]
	default:
		result = ipv4Address[0] // 多个IPv4时返回第一个
	}

	// 增强调试信息
	if len(ipv4Address) > 1 {
		logf("发现多个IP地址: %v\n", ipv4Address)
	}
	//logf("解析地址 IPv4: [%s]\n", result)

	return result, nil
}
