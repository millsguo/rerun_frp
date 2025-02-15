package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

type OneJob struct {
	Ctx         context.Context
	Cmder       *exec.Cmd
	Cancel      func()
	Err         error
	CmdLine     string
	CmdArgs     []string
	Running     bool
	mu          sync.Mutex         // 保护所有字段
	retryTimer  *time.Timer        // 重试定时器
	retryCancel context.CancelFunc // 取消重试
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

	// 防止重复调度
	if j.retryTimer != nil {
		logf("取消现有重试任务")
		j.retryCancel()
	}

	ctx, cancel := context.WithCancel(context.Background())
	j.retryCancel = cancel

	logf("计划3分钟后重试...")
	j.retryTimer = time.AfterFunc(3*time.Minute, func() {
		if ctx.Err() != nil {
			logf("重试已取消")
			return
		}

		j.mu.Lock()
		defer j.mu.Unlock()

		if !j.Running && FileExist(j.CmdLine) {
			logf("执行重试启动...")
			StartFrpThings(j)
		} else {
			logf("跳过重试：进程正在运行或文件缺失")
		}
	})
}

func FileExist(path string) bool {
	_, err := os.Lstat(path)
	return !os.IsNotExist(err)
}

func InitFrpArgs(nowDir string, oneJob *OneJob) bool {
	nowDir = nowDir + string(os.PathSeparator) + "frpThings" + string(os.PathSeparator)
	absPathFrp := nowDir + "frp"
	absPathFrpIni := nowDir + "frp.ini"

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
	return true
}

func StartFrpThings(oneJob *OneJob) bool {
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
		go func() {
			select {
			case <-time.After(5 * time.Second):
				if err := cmder.Process.Kill(); err != nil {
					logf("强制终止失败:%v", err)
				}
			}
		}()
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

	oneJob.setRunning(true)
	logf("进程已启动 PID:%d (耗时%s)\n", cmder.Process.Pid, time.Since(startTime))

	// 日志处理
	scanOutput := func(input io.Reader, name string) {
		scanner := bufio.NewScanner(input)
		for scanner.Scan() {
			line := scanner.Text()
			logf("[FRP-%s] %s\n", name, line)
			if strings.Contains(line, "retry") || strings.Contains(line, "error") {
				logf("检测到错误关键词，准备重试...")
				oneJob.scheduleRetry()
			}
		}
	}

	go scanOutput(stdout, "stdout")
	go scanOutput(stderr, "stderr")

	// 进程监控
	go func() {
		err := cmder.Wait()
		duration := time.Since(startTime)

		oneJob.mu.Lock()
		defer oneJob.mu.Unlock()

		oneJob.Running = false
		oneJob.Cmder = nil // 清除已完成的命令

		if err != nil {
			exitCode := 0
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				exitCode = exitErr.ExitCode()
			}
			logf("进程异常退出 (code:%d 时长%s): %v\n", exitCode, duration, err)
			if duration < 5*time.Second {
				logf("短期异常退出，触发重试")
				oneJob.scheduleRetry()
			}
		} else {
			logf("进程正常退出 (运行时长%s)\n", duration)
		}
	}()
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
		logf("Resolved multiple IPv4 addresses: %v\n", ipv4Address)
	}
	logf("Final selected IPv4: [%s]\n", result)

	return result, nil
}
