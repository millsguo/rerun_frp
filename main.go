package main

import (
	"fmt"
	"github.com/elazarl/goproxy"
	"github.com/spf13/viper"
	"log"
	"net/http"
	"os"
	"time"
)

var (
	ipCache		  string
	oneJob = &OneJob{}
)

func RunOnce(vipConfig *viper.Viper) {
	domainName := vipConfig.GetString("CheckDomainName")
	ipTmp, err := GetIP(domainName)
	if err != nil {
		log.Println("GetIP Error:", err)
		return
	}
	nowDir, _ := os.Getwd()
	if initOk := InitFrpArgs(nowDir, oneJob); initOk == false {
		log.Println("InitFrpArgs Error.")
		return
	}
	// 第一次
	if ipCache == "" {
		ipCache = ipTmp
		StartFrpThings(oneJob)
	} else {
		// 非第一次
		log.Println("Org IP:", ipCache)
		log.Println("New IP:", ipTmp)

		if ipTmp != ipCache {
			// 重新启动 Frp
			log.Printf("Close frp ...")
			CloseFrp(oneJob)
			log.Printf("Close frp Done.")

			ipCache = ipTmp

			StartFrpThings(oneJob)
		}
	}
}

func RunTimer(vipConfig *viper.Viper) {
	defer func() {
		if oneJob.Running == true {
			CloseFrp(oneJob)
		}

		if err := recover(); err != nil {
			fmt.Println(err)
		}

		log.Printf("Close Frp Done.")
	}()

	for {
		RunOnce(vipConfig)

		time.Sleep(time.Minute * time.Duration(10))
	}
}

func main() {

	// -------------------------------------------------------------
	// 加载配置
	vipConfig, err := InitConfigure()
	if err != nil {
		log.Fatalln("InitConfigure:", err)
		return
	}

	ipCache = ""

	go RunTimer(vipConfig)

	localProxyPort := vipConfig.GetInt("LocalProxyPort")
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	//为了防止阿里云检测海外主机是否有翻墙行为我们把服务开在127.0.0.1,这样外网是检测不到你开了 httpproxy 的
	log.Fatal(http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", localProxyPort) , proxy))
}