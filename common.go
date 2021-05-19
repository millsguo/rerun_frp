package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
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

func InitFrpArgs(nowdir string, oneJob *OneJob) bool {
	nowdir = nowdir + string(os.PathSeparator) + "frpThings" + string(os.PathSeparator)
	absPath_Frp := nowdir + "frp"
	absPath_Frp_ini := nowdir + "frp.ini"

	switch runtime.GOOS {
	case "darwin":
		break
	case "linux":
		break
	case "windows":
		absPath_Frp += ".exe"
	}

	if FileExist(absPath_Frp) == false {
		log.Panicln(absPath_Frp + " not exist.")
		return false
	}
	if FileExist(absPath_Frp_ini) == false {
		log.Panicln(absPath_Frp_ini + " not exist.")
		return false
	}

	oneJob.CmdLine = absPath_Frp
	oneJob.CmdArgs = []string{
		"-c",
		absPath_Frp_ini,
	}

	return true
}

func StartFrpThings(oneJob *OneJob) bool {

	if oneJob.Running == true {
		return false
	}

	log.Printf("Start frp ...")
	startFrp(oneJob)
	if oneJob.Err != nil {
		log.Printf("Start frp Error")
		log.Panicln(oneJob.Err.Error())
		return false
	}
	log.Printf("Start frpc Done.")

	oneJob.Running = true

	return true
}

func CloseFrp(oneJob *OneJob) bool {
	oneJob.Cancel()
	_ = oneJob.Cmder.Wait()
	oneJob.Running = false
	return true
}

func startFrp(oneJob *OneJob) {
	oneJob.Ctx, oneJob.Cancel = context.WithCancel(context.Background())
	oneJob.Cmder = exec.CommandContext(oneJob.Ctx, oneJob.CmdLine, oneJob.CmdArgs...)
	// oneJob.Cmder.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	oneJob.Cmder.Stdout = os.Stdout
	err := oneJob.Cmder.Start()
	if err != nil {
		oneJob.Err = err
	}
}

func GetIP(domainName string) (string, error) {
	addr, err := net.ResolveIPAddr("ip", domainName)
	if err != nil {
		return "", err
	}
	fmt.Println("Resolved address is", addr.String())

	return addr.String(), nil
}