package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
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

func CloseFrp(oneJob *OneJob) bool {
	fmt.Println("Close frpc ...")
	// 取消上下文
	oneJob.Cancel()

	// 等待命令完成
	done := make(chan error, 1)
	go func() {
		done <- oneJob.Cmder.Wait()
	}()

	if err := oneJob.Cmder.Process.Kill(); err != nil {
		fmt.Println("Failed to kill frpc process:", err)
	}

	// 标记为未运行
	oneJob.Running = false
	fmt.Println("Close frpc Done.")
	return true
	//oneJob.Cancel()
	//_ = oneJob.Cmder.Wait()
	//oneJob.Running = false
	//fmt.Println("Close frpc Done.")
	//return true
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

	// 设置输出
	oneJob.Cmder.Stdout = os.Stdout

	// 启动命令
	err := oneJob.Cmder.Start()
	if err != nil {
		fmt.Println("Failed to start frpc: ", err)
		oneJob.Err = err
		return
	}

	// 标记为运行中
	oneJob.Running = true

	//// 等待命令完成或被取消
	//done := make(chan error, 1)
	//go func() {
	//	done <- oneJob.Cmder.Wait()
	//}()
	//
	//select {
	//case err := <-done:
	//	if err != nil {
	//		fmt.Println("frpc exited with error: %v", err)
	//		oneJob.Err = err
	//	}
	//	oneJob.Running = false
	//case <-oneJob.Ctx.Done():
	//	fmt.Println("frpc canceled: %v", oneJob.Ctx.Err())
	//	if err := oneJob.Cmder.Process.Kill(); err != nil {
	//		fmt.Println("Failed to kill frpc process: %v", err)
	//		oneJob.Err = err
	//	}
	//	oneJob.Running = false
	//}

	/* 弃用
	oneJob.Ctx, oneJob.Cancel = context.WithCancel(context.Background())
	oneJob.Cmder = exec.CommandContext(oneJob.Ctx, oneJob.CmdLine, oneJob.CmdArgs...)
	// oneJob.Cmder.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	oneJob.Cmder.Stdout = os.Stdout
	err := oneJob.Cmder.Start()
	if err != nil {
		oneJob.Err = err
	}
	*/
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
