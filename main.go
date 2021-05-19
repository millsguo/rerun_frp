package main

import (
	"fmt"
	"github.com/spf13/viper"
	"log"
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

	RunTimer(vipConfig)
}