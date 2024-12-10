package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type OneJob struct {
	Ctx     context.Context
	Cmder   *exec.Cmd
	Cancel  func()
	Err     error
	CmdLine string
	CmdArgs []string
	Running bool
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

	if FileExist(absPathFrp) == false {
		fmt.Println(absPathFrp, " not exist.")
		return false
	}
	if FileExist(absPathFrpIni) == false {
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

	if oneJob.Running == true {
		return false
	}

	fmt.Println("Start frp ...")
	startFrp(oneJob)
	if oneJob.Err != nil {
		fmt.Println("Start frp Error")
		fmt.Println(oneJob.Err.Error())
		return false
	}
	fmt.Println("Start frpc Done.")

	oneJob.Running = true

	return true
}

func closeFrp(oneJob *OneJob) bool {
	fmt.Println("Close frpc ...")
	// 取消上下文
	if oneJob.Cancel != nil {
		oneJob.Cancel()
	}

	// 确保进程存在
	if oneJob.Cmder != nil && oneJob.Cmder.Process != nil {
		// 尝试优雅地终止进程
		if err := oneJob.Cmder.Process.Signal(os.Interrupt); err != nil {
			fmt.Println("Failed to send interrupt signal to frpc process:", err)
		}

		// 创建一个通道来接收 Wait 的结果
		waitChan := make(chan error, 1)
		go func() {
			waitChan <- oneJob.Cmder.Wait()
		}()

		// 等待一段时间让进程优雅退出
		select {
		case <-time.After(5 * time.Second):
			// 如果进程还未退出，则强制终止
			if err := oneJob.Cmder.Process.Kill(); err != nil {
				fmt.Println("Failed to kill frpc process:", err)
			}
		case err := <-waitChan:
			if err != nil {
				fmt.Println("frpc exited with error:", err)
			}
		}
	} else {
		fmt.Println("No frpc process to close.")
	}

	// 检查系统中是否有其他 frp 进程并强制关闭
	killFrpProcesses()

	// 标记为未运行
	oneJob.Running = false
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
		fmt.Println("Unsupported OS for killing frp processes.")
		return
	}

	err := cmd.Run()
	if err != nil {
		fmt.Println("Failed to kill frp processes:", err)
	} else {
		fmt.Println("Successfully killed all frp processes.")
	}
}

func startFrp(oneJob *OneJob) {
	fmt.Println("Start frpc ...")
	// 创建一个带有超时的子上下文
	oneJob.Ctx, oneJob.Cancel = context.WithCancel(context.Background())
	defer func() {
		if oneJob.Err != nil {
			oneJob.Cancel()
		}
	}()

	// 创建命令
	oneJob.Cmder = exec.CommandContext(oneJob.Ctx, oneJob.CmdLine, oneJob.CmdArgs...)

	// 创建一个管道来读取标准输出
	stdoutPipe, err := oneJob.Cmder.StdoutPipe()
	if err != nil {
		fmt.Println("Failed to create stdout pipe:", err)
		oneJob.Err = err
		return
	}

	// 设置输出
	//oneJob.Cmder.Stdout = os.Stdout

	// 启动命令
	err = oneJob.Cmder.Start()
	if err != nil {
		fmt.Println("Failed to start frpc: ", err)
		oneJob.Err = err
		return
	}

	// 标记为运行中
	oneJob.Running = true

	// 读取标准输出并检查是否包含"retry"
	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			output := scanner.Text()
			fmt.Println(output) // 打印输出
			if strings.Contains(output, "retry") {
				fmt.Println("Detected 'retry' in output. Restarting frpc...")
				closeFrp(oneJob) // 假设 closeFrp 是一个已经存在的函数
				startFrp(oneJob) // 重新启动 frpc
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Println("Error reading stdout:", err)
		}
	}()

	// 等待命令完成
	err = oneJob.Cmder.Wait()
	if err != nil {
		fmt.Println("frpc exited with error:", err)
		oneJob.Err = err
	}
}

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
