package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
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
	mu          sync.Mutex         // 保护状态字段
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
		fmt.Println("已存在待处理的重试任务，取消原计划")
		j.retryCancel()
	}

	ctx, cancel := context.WithCancel(context.Background())
	j.retryCancel = cancel

	fmt.Println("调度新的重试任务，3分钟后执行...")
	j.retryTimer = time.AfterFunc(3*time.Minute, func() {
		select {
		case <-ctx.Done():
			fmt.Println("重试任务已被取消")
			return
		default:
		}

		// 添加预检锁
		j.mu.Lock()
		defer j.mu.Unlock()

		if !j.Running {
			fmt.Println("执行预启动检查...")
			if !FileExist(j.CmdLine) {
				fmt.Printf("可执行文件不存在: %s\n", j.CmdLine)
				return
			}
			fmt.Println("开始重试启动流程...")
			StartFrpThings(j)
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

	switch runtime.GOOS {
	case "darwin":
		break
	case "linux":
		break
	case "windows":
		absPathFrp += ".exe"
	}

	if !FileExist(absPathFrp) {
		fmt.Println(absPathFrp, " not exist.")
		return false
	}
	if !FileExist(absPathFrpIni) {
		fmt.Println(absPathFrpIni, " not exist.")
		return false
	}

	oneJob.CmdLine = absPathFrp
	oneJob.CmdArgs = []string{
		"-c",
		absPathFrpIni,
	}

	return true
}

func StartFrpThings(oneJob *OneJob) bool {
	if oneJob.isRunning() {
		return false
	}

	fmt.Println("Start frp ...")
	startFrp(oneJob)
	if oneJob.Err != nil {
		fmt.Println("Start frp Error")
		fmt.Println(oneJob.Err.Error())
		oneJob.scheduleRetry() // 新增：启动失败时调度重试
		return false
	}
	fmt.Println("Start frpc Done.")
	return true
}

func closeFrp(oneJob *OneJob) bool {
	fmt.Println("Close frpc ...")

	// 取消重试调度
	oneJob.mu.Lock()
	if oneJob.retryCancel != nil {
		oneJob.retryCancel()
		oneJob.retryCancel = nil
	}
	if oneJob.retryTimer != nil {
		oneJob.retryTimer.Stop()
		oneJob.retryTimer = nil
	}
	oneJob.mu.Unlock()

	if oneJob.Cancel != nil {
		oneJob.Cancel()
	}

	if oneJob.Cmder != nil && oneJob.Cmder.Process != nil {
		if err := oneJob.Cmder.Process.Signal(os.Interrupt); err != nil {
			fmt.Println("Failed to send interrupt signal:", err)
		}

		waitChan := make(chan error, 1)
		go func() {
			waitChan <- oneJob.Cmder.Wait()
		}()

		select {
		case <-time.After(5 * time.Second):
			if err := oneJob.Cmder.Process.Kill(); err != nil {
				fmt.Println("Failed to kill process:", err)
			}
		case err := <-waitChan:
			if err != nil {
				fmt.Println("Process exited with error:", err)
			}
		}
	} else {
		fmt.Println("No process to close")
	}

	killFrpProcesses()
	oneJob.setRunning(false)
	fmt.Println("Close frpc Done.")
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
		fmt.Println("Unsupported OS")
		return
	}

	if err := cmd.Run(); err != nil {
		fmt.Println("Cleanup error:", err)
	} else {
		fmt.Println("Cleanup completed")
	}
}

// 修改startFrp函数中的命令执行部分
func startFrp(oneJob *OneJob) {
	oneJob.Ctx, oneJob.Cancel = context.WithCancel(context.Background())
	defer func() {
		if oneJob.Err != nil {
			oneJob.Cancel()
		}
	}()

	// 添加详细日志
	fmt.Printf("Executing command: %s %v\n", oneJob.CmdLine, oneJob.CmdArgs)

	oneJob.Cmder = exec.CommandContext(oneJob.Ctx, oneJob.CmdLine, oneJob.CmdArgs...)

	// 同时捕获标准错误
	stdoutPipe, err := oneJob.Cmder.StdoutPipe()
	if err != nil {
		fmt.Println("Stdout pipe error:", err)
		oneJob.Err = err
		oneJob.scheduleRetry()
		return
	}
	stderrPipe, err := oneJob.Cmder.StderrPipe()
	if err != nil {
		fmt.Println("Stderr pipe error:", err)
		oneJob.Err = err
		oneJob.scheduleRetry()
		return
	}

	// 添加启动时间记录
	startTime := time.Now()

	if err := oneJob.Cmder.Start(); err != nil {
		fmt.Printf("启动失败 (耗时%s): %v\n", time.Since(startTime), err)
		oneJob.Err = err
		oneJob.scheduleRetry()
		return
	}

	oneJob.setRunning(true)
	fmt.Printf("进程已启动 PID:%d (耗时%s)\n", oneJob.Cmder.Process.Pid, time.Since(startTime))

	// 统一输出处理
	outputScanner := func(input io.Reader, name string) {
		scanner := bufio.NewScanner(input)
		for scanner.Scan() {
			output := scanner.Text()
			fmt.Printf("[frp %s] %s\n", name, output)
			if strings.Contains(output, "retry") {
				fmt.Println("检测到重试关键字，启动重置流程...")
				oneJob.scheduleRetry()
			} else if strings.Contains(output, "refused") {
				fmt.Println("检测到拒绝关键字，启动重置流程...")
				oneJob.scheduleRetry()
			} else if strings.Contains(output, "error") {
				fmt.Println("检测到重试关键字，启动重置流程...")
				oneJob.scheduleRetry()
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("%s扫描错误: %v\n", name, err)
		}
	}

	// 并行处理输出流
	go outputScanner(stdoutPipe, "stdout")
	go outputScanner(stderrPipe, "stderr")

	// 优化等待逻辑
	go func() {
		err := oneJob.Cmder.Wait()
		runDuration := time.Since(startTime)

		oneJob.mu.Lock()
		defer oneJob.mu.Unlock()

		// 状态转换前检查
		if !oneJob.Running {
			fmt.Printf("进程状态不一致，已处于停止状态 (运行时长%s)\n", runDuration)
			return
		}

		// 记录退出信息
		exitCode := 0
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				exitCode = exitErr.ExitCode()
			}
			fmt.Printf("进程异常退出 (code:%d 时长%s): %v\n", exitCode, runDuration, err)
		} else {
			fmt.Printf("进程正常退出 (运行时长%s)\n", runDuration)
		}

		// 状态重置和重试调度
		oneJob.Running = false
		oneJob.Cmder = nil

		// 仅当运行时间小于5秒时视为异常退出需要重试
		if runDuration < 5*time.Second {
			fmt.Println("检测到短期异常退出，触发重试机制")
			oneJob.scheduleRetry()
		} else {
			fmt.Println("进程已完成正常生命周期，无需重试")
		}
	}()
}

// GetIP 函数保持原样
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

	addr, err := resolver.LookupHost(context.Background(), domainName)
	//addr, err := net.ResolveIPAddr("ip", domainName)
	if err != nil {
		return "", err
	}

	//处理解析结果，只有一个IP时，直接返回，有多个时，只返回第一个
	var result string
	switch len(addr) {
	case 0:
		result = ""
	case 1:
		result = addr[0]
	default:
		result = addr[0]
	}
	//fmt.Println("Resolved address is", addr.String())
	//fmt.Println("Resolved address is ", result)
	fmt.Println("Resolved address is [", result, "]")
	return result, nil
}
