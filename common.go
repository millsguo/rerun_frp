package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/viper"
)

// 添加 fmt 包导入
import "fmt"

type OneJob struct {
	Ctx                  context.Context
	Cmder                *exec.Cmd
	Cancel               func()
	Err                  error
	CmdLine              string
	CmdArgs              []string
	Running              bool
	LastActive           time.Time
	mu                   sync.Mutex         // 保护所有字段
	retryTimer           *time.Timer        // 重试定时器
	retryCancel          context.CancelFunc // 取消重试
	vipConfig            *viper.Viper       // 新增配置引用
	retryCount           int
	maxAllowedRetries    int         // 记录当前最大允许值
	connectionFailure    bool        // 标记是否因连接失败触发的重试
	connectionRetryTimer *time.Timer // 连接失败重试定时器
}

// 新增方法：安全设置运行状态
func (j *OneJob) setRunning(running bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Running = running
	if running {
		logf("FRP服务状态已设置为运行中")
	} else {
		logf("FRP服务状态已设置为已停止")
	}
}

// 新增方法：安全获取运行状态
// 使用原子操作检查运行状态，避免在启动过程中出现误判
func (j *OneJob) isRunning() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Running
}

// 新增方法：安全获取运行状态（公开方法）
func (j *OneJob) GetRunningState() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Running
}

// 新增方法：安全设置运行状态（公开方法）
func (j *OneJob) UpdateRunningState(running bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Running = running
	if running {
		logf("FRP服务状态已设置为运行中")
	} else {
		logf("FRP服务状态已设置为已停止")
	}
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

	// 如果是连接失败，使用5分钟固定间隔重试
	var delay time.Duration
	if j.connectionFailure {
		delay = 5 * time.Minute
		logf("连接失败重试将在 %.1f 分钟后触发 (配置上限:%d)",
			delay.Minutes(), j.maxAllowedRetries)
	} else {
		// 标准指数退避算法（含随机因子）
		baseDelay := 3 * time.Minute
		maxDelay := 60 * time.Minute
		delay = baseDelay * time.Duration(1<<uint(j.retryCount))
		delay = time.Duration(float64(delay) * (1 + 0.2*rand.Float64())) // 增加20%随机抖动

		if delay > maxDelay {
			delay = maxDelay
		}

		logf("第 %d 次重试将在 %.1f 分钟后触发 (配置上限:%d)",
			j.retryCount+1, delay.Minutes(), j.maxAllowedRetries)
	}

	// 更新计数器前检查
	if j.retryTimer != nil {
		j.retryTimer.Stop()
	}
	j.retryCount++

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

		// 如果是连接失败触发的重试，检查IP是否变更
		if j.connectionFailure {
			domainName := j.vipConfig.GetString("CheckDomainName")
			dnsAddress := j.vipConfig.GetString("DnsAddress")

			ipTmp, err := GetIP(domainName, dnsAddress)
			if err != nil {
				logf("连接失败重试时获取远程IP失败，错误信息: %v", err)
				// 继续重试
				j.scheduleRetry()
				return
			}

			// 检查FRPS服务器是否可达
			if !isFRPSAvailable(ipTmp, 7000) {
				logf("FRPS服务器 %s:7000 不可达，5分钟后再次检查", ipTmp)
				j.scheduleRetry()
				return
			}

			ipCacheMu.Lock()
			oldIP := ipCache
			ipChanged := (oldIP != ipTmp)
			if ipChanged {
				logf("检测到IP变更，原IP: %s, 新IP: %s", oldIP, ipTmp)
				ipCache = ipTmp
			}
			ipCacheMu.Unlock()

			// 如果IP变更了，需要重启FRP服务
			if ipChanged {
				logf("IP已变更，重启FRP服务中...")
				// 关闭当前FRP服务
				closeFrp(j)

				// 确保资源释放完成
				logf("等待资源释放...")
				time.Sleep(5 * time.Second)

				// 初始化FRP参数
				nowDir, _ := os.Getwd()
				// 更新FRPC配置文件中的服务器地址
				if err := updateFRPCConfig(nowDir, ipTmp); err != nil {
					logf("更新FRPC配置文件失败: %v", err)
					j.scheduleRetry()
					return
				}
				if !InitFrpArgs(nowDir, j) {
					logf("重启时初始化失败！")
					j.scheduleRetry()
					return
				}

				// 启动新的FRP服务
				logf("开始启动新的FRP服务...")
				StartFrpThings(j, j.vipConfig)
				logf("FRP服务重启流程执行完成")

				// 重置连接失败标记
				j.mu.Lock()
				j.connectionFailure = false
				j.retryCount = 0
				j.mu.Unlock()
				return
			} else {
				logf("IP未变更 (%s)，尝试重新连接", ipTmp)
				// IP未变更，尝试重新连接
				closeFrp(j)

				// 等待资源释放
				time.Sleep(3 * time.Second)

				// 初始化FRP参数
				nowDir, _ := os.Getwd()
				if !InitFrpArgs(nowDir, j) {
					logf("重启时初始化失败！")
					j.scheduleRetry()
					return
				}

				// 启动FRP服务
				StartFrpThings(j, j.vipConfig)
				return
			}
		} else {
			// 执行前清空IP缓存
			ipCacheMu.Lock()
			ipCache = ""
			ipCacheMu.Unlock()

			logf("开始执行第 %d 次重试", j.retryCount)
			// 在重试前增加更长的等待时间，确保资源完全释放
			logf("等待更长时间以确保资源完全释放...")
			time.Sleep(5 * time.Second) // 增加等待时间从2秒到5秒
			RunOnce(j.vipConfig)
		}
	})

	// 上下文清理协程
	go func() {
		<-ctx.Done()
		j.mu.Lock()
		j.retryTimer = nil
		j.mu.Unlock()
	}()
}

// 新增方法：标记连接失败并调度重试
func (j *OneJob) scheduleConnectionFailureRetry() {
	j.mu.Lock()
	defer j.mu.Unlock()

	// 停止现有的连接重试定时器
	if j.connectionRetryTimer != nil {
		j.connectionRetryTimer.Stop()
	}

	// 设置连接失败标记
	j.connectionFailure = true

	// 创建新的5分钟定时器
	j.connectionRetryTimer = time.AfterFunc(5*time.Minute, func() {
		oneJobMu.Lock()
		defer oneJobMu.Unlock()

		// 检查运行状态
		if !j.isRunning() {
			logf("FRP服务未运行，放弃连接失败重试")
			return
		}

		// 获取配置
		j.mu.Lock()
		vipConfig := j.vipConfig
		j.mu.Unlock()

		if vipConfig == nil {
			logf("配置为空，无法执行连接失败重试")
			return
		}

		domainName := vipConfig.GetString("CheckDomainName")
		dnsAddress := vipConfig.GetString("DnsAddress")

		ipTmp, err := GetIP(domainName, dnsAddress)
		if err != nil {
			logf("连接失败重试时获取远程IP失败，错误信息: %v", err)
			// 继续安排下一次重试
			j.scheduleConnectionFailureRetry()
			return
		}

		// 检查FRPS服务器是否可达
		if !isFRPSAvailable(ipTmp, 7000) {
			logf("FRPS服务器 %s:7000 不可达，5分钟后再次检查", ipTmp)
			j.scheduleConnectionFailureRetry()
			return
		}

		ipCacheMu.Lock()
		oldIP := ipCache
		ipChanged := (oldIP != ipTmp)
		if ipChanged {
			logf("检测到IP变更，原IP: %s, 新IP: %s", oldIP, ipTmp)
			ipCache = ipTmp
		} else {
			// 即使IP未变更，也需要更新缓存以确保下次比较正确
			ipCache = ipTmp
			logf("即使IP未变更，也更新缓存: %s", ipTmp)
		}
		ipCacheMu.Unlock()

		// 如果IP发生了变更，则需要重启FRP服务
		if ipChanged {
			logf("IP已变更，重启FRP服务中...")
			// 关闭当前FRP服务
			closeFrp(j)

			// 确保资源释放完成
			logf("等待资源释放...")
			time.Sleep(5 * time.Second)

			// 初始化FRP参数
			nowDir, _ := os.Getwd()
			// 更新FRPC配置文件中的服务器地址
			if err := updateFRPCConfig(nowDir, ipTmp); err != nil {
				logf("更新FRPC配置文件失败: %v", err)
				// 继续安排下一次重试
				j.scheduleConnectionFailureRetry()
				return
			}
			if !InitFrpArgs(nowDir, j) {
				logf("重启时初始化失败！")
				// 继续安排下一次重试
				j.scheduleConnectionFailureRetry()
				return
			}

			// 启动新的FRP服务
			logf("开始启动新的FRP服务...")
			StartFrpThings(j, vipConfig)
			logf("FRP服务重启流程执行完成")
		} else {
			logf("IP未变更，FRPC客户端应能自行重新连接")
		}

		// 重置连接失败标记
		j.mu.Lock()
		j.connectionFailure = false
		j.mu.Unlock()
		return
	})

	logf("连接失败，将在5分钟后检查并重试")
}

// 新增资源清理方法
func (j *OneJob) cleanupRetryResources() {
	if j.retryCancel != nil {
		j.retryCancel()
		j.retryCancel = nil
	}
	if j.retryTimer != nil {
		j.retryTimer.Stop()
		j.retryTimer = nil
	}
	if j.connectionRetryTimer != nil {
		j.connectionRetryTimer.Stop()
		j.connectionRetryTimer = nil
	}
	j.retryCount = 0 // 重置计数器
	j.maxAllowedRetries = 0
	j.connectionFailure = false // 重置连接失败标记
	logf("重试资源已清理")
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
	configPath := filepath.Join(nowDir, "/frpClient/frpc.toml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		logf("配置文件生成失败，路径: %s", configPath)
		return false
	}

	if runtime.GOOS == "windows" {
		frpBinPath += ".exe"
	}

	if !FileExist(frpBinPath) {
		logf(frpBinPath, "不存在")
		return false
	}
	if !FileExist(configPath) {
		logf(configPath, "不存在")
		return false
	}

	oneJob.CmdLine = frpBinPath
	oneJob.CmdArgs = []string{"-c", configPath}

	// 返回前添加权限检查
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(frpBinPath); err == nil {
			logf("文件权限: %#o", fi.Mode().Perm())
		}
	}
	logf("FRP参数初始化完成: %s %v", oneJob.CmdLine, oneJob.CmdArgs)
	return true
}

// 新增函数：更新FRPC配置文件中的服务器地址
func updateFRPCConfig(nowDir string, newIP string) error {
	configPath := filepath.Join(nowDir, "/frpClient/frpc.toml")

	// 读取配置文件
	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取FRPC配置文件失败: %v", err)
	}

	// 将内容按行分割
	lines := strings.Split(string(content), "\n")

	// 查找并替换 server_addr 行
	for i, line := range lines {
		// 查找 server_addr 配置行
		if strings.HasPrefix(strings.TrimSpace(line), "server_addr") {
			// 替换IP地址部分
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				// 保留等号前的部分和等号，只替换IP地址
				lines[i] = strings.TrimSpace(parts[0]) + " = " + newIP
				logf("已更新FRPC配置文件中的服务器地址: %s", newIP)
				break
			}
		}
	}

	// 将修改后的内容写回文件
	newContent := strings.Join(lines, "\n")
	err = os.WriteFile(configPath, []byte(newContent), 0644)
	if err != nil {
		return fmt.Errorf("写入FRPC配置文件失败: %v", err)
	}

	return nil
}

func StartFrpThings(oneJob *OneJob, vipConfig *viper.Viper) bool {
	oneJob.vipConfig = vipConfig // 注入配置

	logf("检查FRP服务运行状态...")
	// 使用安全方法检查运行状态
	if oneJob.isRunning() {
		logf("FRP服务已在运行中，无需重复启动")
		return false
	}

	logf("启动FRP服务...")
	startFrp(oneJob)
	if oneJob.Err != nil {
		logf("启动失败:%v", oneJob.Err)
		// 增加重试前的短暂等待，确保资源释放
		logf("等待资源释放后重试...")
		time.Sleep(2 * time.Second) // 增加等待时间确保资源完全释放
		oneJob.scheduleRetry()
		return false
	}
	oneJob.LastActive = time.Now() // 设置初始活动时间
	oneJob.setRunning(true)
	logf("FRP服务启动成功")
	return true
}

func closeFrp(oneJob *OneJob) bool {
	logf("关闭FRP服务...")

	// 使用通道来同步关闭操作，避免阻塞
	done := make(chan bool, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logf("关闭FRP服务时发生异常: %v", r)
				done <- false
			}
		}()

		// 清理重试机制
		oneJob.mu.Lock()
		logf("清理重试定时器和上下文...")
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
			logf("获取到正在运行的命令进程 PID:%d", cmder.Process.Pid)
		}
		if oneJob.Cancel != nil {
			cancelFunc = oneJob.Cancel
		}
		oneJob.mu.Unlock()

		// 执行关闭操作
		if cancelFunc != nil {
			logf("发送取消信号...")
			cancelFunc()
		}

		if cmder != nil && cmder.Process != nil {
			logf("终止进程 PID:%d", cmder.Process.Pid)
			if err := cmder.Process.Signal(os.Interrupt); err != nil {
				logf("发送中断信号失败:%v", err)
			}

			// 异步等待终止
			// 优化异步等待逻辑
			processDone := make(chan struct{})
			go func() {
				defer close(processDone)
				select {
				case <-time.After(5 * time.Second):
					logf("进程未在5秒内正常退出，尝试强制终止...")
					if err := cmder.Process.Kill(); err != nil {
						logf("强制终止失败:%v", err)
					}
				case <-oneJob.Ctx.Done(): // 新增上下文监听
					logf("接收到上下文完成信号")
					return
				}
			}()

			// 新增同步等待
			select {
			case <-processDone:
				if _, err := cmder.Process.Wait(); err != nil {
					logf("进程回收失败:%v", err)
				} else {
					logf("进程已成功终止 PID:%d", cmder.Process.Pid)
				}
			case <-time.After(10 * time.Second):
				logf("警告：进程终止超时")
			}
		} else {
			logf("无运行中的进程")
		}

		logf("开始清理残留FRP进程...")
		killFrpProcesses()
		// 等待一段时间确保进程完全终止，增加等待时间
		logf("等待进程完全终止...")
		time.Sleep(5 * time.Second)

		// 使用原子操作更新运行状态，避免锁竞争
		oneJob.UpdateRunningState(false)
		logf("FRP服务关闭完成")

		// 确保日志系统正常工作
		logMu.Lock()
		if logClosed {
			logf("检测到日志系统已关闭，重新初始化日志系统")
			logClosed = false
			updateLogFile()
		}
		logMu.Unlock()

		done <- true
	}()

	// 等待关闭操作完成，设置超时时间
	select {
	case result := <-done:
		return result
	case <-time.After(30 * time.Second):
		logf("关闭FRP服务超时")
		return false
	}
}

func killFrpProcesses() {
	logf("清理残留FRP进程...")
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin", "linux":
		cmd = exec.Command("pkill", "-f", "frp")
		logf("执行命令: pkill -f frp")
	case "windows":
		cmd = exec.Command("taskkill", "/F", "/IM", "frp.exe")
		logf("执行命令: taskkill /F /IM frp.exe")
	default:
		logf("清理进程时，发现不支持的操作系统: %s", runtime.GOOS)
		return
	}

	// 为清理进程命令设置超时
	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case err := <-done:
		if err != nil {
			logf("清理残留进程失败:%v", err)
		} else {
			logf("清理frp主进程命令执行完成")
		}
	case <-time.After(10 * time.Second):
		logf("清理frp主进程命令执行超时")
	}

	// 增加额外的清理步骤
	logf("开始清理frpc残留进程...")
	for i := 0; i < 5; i++ {
		var err error
		if runtime.GOOS == "windows" {
			err = exec.Command("taskkill", "/F", "/IM", "frpc.exe").Run()
		} else {
			err = exec.Command("pkill", "-9", "-f", "frpc").Run()
		}

		if err != nil {
			if i == 0 {
				logf("清理残留frpc进程失败:%v", err)
			}
		} else {
			logf("frpc进程已清理")
			break
		}
		time.Sleep(1 * time.Second)
	}

	// 添加额外的等待时间确保进程完全终止
	time.Sleep(3 * time.Second)
	logf("残留FRP进程清理完成")
}

func startFrp(oneJob *OneJob) {
	logf("开始启动FRP服务...")
	//logf("启动参数验证: %s %v", oneJob.CmdLine, oneJob.CmdArgs)
	oneJob.mu.Lock()
	oneJob.retryCount = 0
	oneJob.maxAllowedRetries = 0
	oneJob.connectionFailure = false // 重置连接失败标记
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
	logf("创建命令上下文: %s %v", oneJob.CmdLine, oneJob.CmdArgs)
	oneJob.Cmder = exec.CommandContext(oneJob.Ctx, oneJob.CmdLine, oneJob.CmdArgs...)
	cmder := oneJob.Cmder
	logf("完整执行命令: %s", cmder.String())
	oneJob.mu.Unlock()

	// 在启动前增加延迟，确保之前的进程完全终止
	time.Sleep(3 * time.Second) // 增加延迟时间确保之前的进程完全终止

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
	logf("开始启动FRP进程...")
	if err := cmder.Start(); err != nil {
		oneJob.Err = err
		if oneJob.Err != nil {
			logf("详细错误信息: %+v", oneJob.Err) // 打印完整错误堆栈
			logf("文件是否存在: %v", FileExist(oneJob.CmdLine))
		}
		logf("启动失败 (耗时%s): %v\n", time.Since(startTime), err)
		return
	}

	// 使用安全方法更新运行状态
	oneJob.UpdateRunningState(true)
	logf("进程已启动 PID:%d (耗时%s)\n", cmder.Process.Pid, time.Since(startTime))

	//启动健康检查
	logf("启动健康检查协程...")
	go oneJob.healthCheck()

	// 日志处理
	scanOutput := func(input io.Reader, name string) {
		scanner := bufio.NewScanner(input)
		for scanner.Scan() {
			line := scanner.Text()
			logf("[FRP-%s] %s\n", name, line)
			oneJob.UpdateLastActive()
			// 修改日志扫描逻辑，增加特定错误检测
			if strings.Contains(line, "i/o timeout") ||
				strings.Contains(line, "connection refused") ||
				strings.Contains(line, "no such host") ||
				strings.Contains(line, "connect: network is unreachable") ||
				strings.Contains(line, "failed to connect to server") {
				logf("检测到连接错误，等待FRPC客户端重新连接...")
				// 不再立即触发IP检查和重启，因为FRPC客户端有自己的重连机制
				// 我们只需要更新缓存中的IP地址，并等待FRPC客户端自行重新连接
				oneJobMu.Lock()
				if oneJob != nil && oneJob.vipConfig != nil {
					domainName := oneJob.vipConfig.GetString("CheckDomainName")
					dnsAddress := oneJob.vipConfig.GetString("DnsAddress")

					// 获取当前最新的IP
					ipTmp, err := GetIP(domainName, dnsAddress)
					if err == nil {
						// 更新IP缓存，但不立即重启服务
						ipCacheMu.Lock()
						oldIP := ipCache
						if oldIP != ipTmp {
							logf("检测到IP变更，原IP: %s, 新IP: %s", oldIP, ipTmp)
						} else {
							logf("IP未变更: %s", ipTmp)
						}
						ipCache = ipTmp
						ipCacheMu.Unlock()

						// 更新FRPC配置文件中的服务器地址
						nowDir, _ := os.Getwd()
						if err := updateFRPCConfig(nowDir, ipTmp); err != nil {
							logf("更新FRPC配置文件失败: %v", err)
						} else {
							logf("已更新FRPC配置文件中的服务器地址为: %s", ipTmp)
						}
					}
				}
				oneJobMu.Unlock()

				// 调度连接失败重试而不是立即执行
				oneJob.scheduleConnectionFailureRetry()
			} else if strings.Contains(line, "retry") || strings.Contains(line, "error") {
				logf("检测到错误关键词，准备重试...")
				// 检查是否为连接错误
				isConnectionError := strings.Contains(line, "i/o timeout") ||
					strings.Contains(line, "connection refused") ||
					strings.Contains(line, "no such host") ||
					strings.Contains(line, "connect: network is unreachable") ||
					strings.Contains(line, "failed to connect to server")

				if isConnectionError {
					// 对于连接错误，使用专门的连接失败重试机制
					oneJob.scheduleConnectionFailureRetry()
				} else {
					// 其他错误使用通用重试机制
					oneJob.scheduleRetry()
				}
			}
		}
	}

	logf("启动标准输出和错误日志扫描器...")
	go scanOutput(stdout, "stdout")
	go scanOutput(stderr, "stderr")

	// 进程监控
	// 修改进程监控部分
	go func() {
		logf("启动进程监控协程...")
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

				// 检查是否是连接错误导致的退出
				isConnectionError := (exitCode == 1) && (duration > 5*time.Second && duration < 30*time.Second)

				// 新增统一重试策略
				if duration < 30*time.Second || exitCode != 0 {
					logf("触发自动重试机制")
					// 在重试之前增加等待时间，确保资源完全释放
					time.Sleep(3 * time.Second)
					if isConnectionError {
						// 对于连接错误，使用连接失败重试机制
						oneJob.scheduleConnectionFailureRetry()
					} else {
						// 其他错误使用通用重试机制
						oneJob.scheduleRetry()
					}
				}
			} else {
				logf("进程正常退出 (运行时长%s)", duration)
				// 新增正常退出后的保活机制
				if oneJob.vipConfig != nil && oneJob.vipConfig.GetBool("AutoRestart") {
					oneJob.scheduleRetry()
				}
			}
		}

		handleProcessExit()
	}()
}

// 新增健康检查方法
func (j *OneJob) healthCheck() {
	logf("启动FRP服务健康检查")
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			oneJobMu.Lock()
			// 双重检查运行状态
			if !j.isRunning() {
				logf("FRP服务未运行，停止健康检查")
				oneJobMu.Unlock()
				return
			}

			// 检查进程状态
			logf("执行健康检查...")
			alive := j.isProcessAlive()
			if !alive {
				logf("健康检查：进程已停止，触发重启")
				// 在新的goroutine中执行重试，避免死锁
				go func() {
					closeFrp(j)
					ipCacheMu.Lock()
					ipCache = ""
					ipCacheMu.Unlock()
					oneJobMu.Lock()
					defer oneJobMu.Unlock()
					logf("因健康检查失败触发重试")
					RunOnce(j.vipConfig)
				}()
				oneJobMu.Unlock()
				return
			}

			// 检查FRP服务是否处于STOP状态
			// 如果服务长时间没有活动（超过5分钟），可能处于STOP状态
			if time.Since(j.LastActive) > 5*time.Minute {
				logf("健康检查：FRP服务长时间无活动，可能处于STOP状态，触发重启")
				// 在新的goroutine中执行重试，避免死锁
				go func() {
					closeFrp(j)
					ipCacheMu.Lock()
					ipCache = ""
					ipCacheMu.Unlock()
					oneJobMu.Lock()
					defer oneJobMu.Unlock()
					logf("因FRP服务STOP状态触发重试")
					RunOnce(j.vipConfig)
				}()
				oneJobMu.Unlock()
				return
			}

			logf("健康检查完成，进程运行正常")
			oneJobMu.Unlock()

		case <-j.Ctx.Done():
			logf("健康检查已取消")
			return
		}
	}
}

// 新增进程状态检查方法
func (j *OneJob) isProcessAlive() bool {
	j.mu.Lock()
	defer j.mu.Unlock()

	// 如果没有命令或进程，直接返回false
	if j.Cmder == nil || j.Cmder.Process == nil {
		return false
	}

	// 跨平台的进程状态检查
	if runtime.GOOS == "windows" {
		process, err := os.FindProcess(j.Cmder.Process.Pid)
		if err != nil {
			return false
		}
		// 使用任务列表检测进程
		out, _ := exec.Command("tasklist", "/fi", "PID eq "+strconv.Itoa(process.Pid)).Output()
		return strings.Contains(string(out), strconv.Itoa(process.Pid))
	}

	// Unix系统使用信号0检测
	err := j.Cmder.Process.Signal(syscall.Signal(0))
	if err != nil {
		// 处理僵尸进程
		if strings.Contains(err.Error(), "os: process already finished") {
			return false
		}
		// 其他错误也认为进程不存在
		return false
	}
	return true
}

// ForceClose 强制关闭FRP服务，用于紧急情况
func (j *OneJob) ForceClose() bool {
	logf("强制关闭FRP服务...")

	// 先尝试正常关闭
	result := closeFrp(j)
	if result {
		logf("正常关闭FRP服务成功")
		return true
	}

	// 如果正常关闭失败，执行强制清理
	logf("正常关闭失败，执行强制清理...")

	// 直接清理进程
	killFrpProcesses()

	// 更新状态
	j.UpdateRunningState(false)

	// 等待一段时间确保进程完全终止
	time.Sleep(3 * time.Second)

	logf("强制关闭FRP服务完成")
	return true
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

func (j *OneJob) UpdateLastActive() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.LastActive = time.Now()
	// 同时更新全局oneJob的活动时间，确保一致性
	oneJobMu.Lock()
	defer oneJobMu.Unlock()
	if oneJob != nil {
		oneJob.LastActive = time.Now()
	}
}

// 新增函数：检测FRPS的IP地址和端口是否可用
func isFRPSAvailable(ip string, port int) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		logf("FRPS服务器 %s 不可达: %v", address, err)
		return false
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			logf("关闭FRPS服务器 %s 连接时出错: %v", address, err)
		}
	}(conn)
	logf("FRPS服务器 %s 可达", address)
	return true
}
