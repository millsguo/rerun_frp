package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/armon/go-socks5"
	"github.com/elazarl/goproxy"
	"github.com/spf13/viper"
)

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
	domainName := vipConfig.GetString("CheckDomainName")
	dnsAddress := vipConfig.GetString("DnsAddress")

	ipTmp, err := GetIP(domainName, dnsAddress)
	if err != nil {
		log.Printf("GetIP error: %v", err)
		return
	}

	nowDir, _ := os.Getwd()
	if ok := InitFrpArgs(nowDir, oneJob); !ok {
		log.Println("InitFrpArgs error")
		return
	}

	ipCacheMu.Lock()
	defer ipCacheMu.Unlock()

	if ipCache == "" {
		ipCache = ipTmp
		StartFrpThings(oneJob)
		return
	}

	log.Printf("IP check - Original: %s, New: %s", ipCache, ipTmp)
	if ipTmp != ipCache {
		log.Println("IP changed, restarting frp...")

		oneJobMu.Lock()
		closeFrp(oneJob)
		ipCache = ipTmp
		StartFrpThings(oneJob)
		oneJobMu.Unlock()
	}
}

func RunTimer(vipConfig *viper.Viper) {
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
				log.Println("Graceful shutdown completed")
			case <-time.After(30 * time.Second):
				log.Println("WARNING: Force shutdown after timeout")
			}
			return
		}
	}
}

func startProxyServers(socksPort, httpPort int, user, pass string) {
	if user == "" || pass == "" {
		log.Println("Starting proxies without authentication")
		startUnsecuredProxies(socksPort, httpPort)
	} else {
		log.Println("Starting proxies with authentication")
		startSecuredProxies(socksPort, httpPort, user, pass)
	}
}

func startUnsecuredProxies(socksPort, httpPort int) {
	go func() {
		server, err := socks5.New(&socks5.Config{})
		if err != nil {
			log.Fatalf("SOCKS5 server creation failed: %v", err)
		}
		log.Printf("SOCKS5 proxy listening on :%d", socksPort)
		log.Fatal(server.ListenAndServe("tcp", fmt.Sprintf("0.0.0.0:%d", socksPort)))
	}()

	go func() {
		proxy := goproxy.NewProxyHttpServer()
		proxy.Verbose = true
		log.Printf("HTTP proxy listening on :%d", httpPort)
		log.Fatal(http.ListenAndServe(
			fmt.Sprintf("0.0.0.0:%d", httpPort),
			proxy,
		))
	}()
}

func startSecuredProxies(socksPort, httpPort int, user, pass string) {
	go func() {
		server, err := createSocks5Server(user, pass)
		if err != nil {
			log.Fatalf("SOCKS5 server creation failed: %v", err)
		}
		log.Printf("Authenticated SOCKS5 listening on :%d", socksPort)
		log.Fatal(server.ListenAndServe("tcp", fmt.Sprintf("0.0.0.0:%d", socksPort)))
	}()

	go func() {
		proxy := goproxy.NewProxyHttpServer()
		proxy.Verbose = true
		authHandler := authMiddleware(user, pass, proxy)

		log.Printf("Authenticated HTTP proxy listening on :%d", httpPort)
		log.Fatal(http.ListenAndServe(
			fmt.Sprintf("0.0.0.0:%d", httpPort),
			authHandler,
		))
	}()
}

func main() {
	vipConfig, err := InitConfigure()
	if err != nil {
		log.Fatalf("Configuration initialization failed: %v", err)
	}

	go RunTimer(vipConfig)

	localProxyPort := vipConfig.GetInt("LocalProxyPort")
	localSocks5Port := vipConfig.GetInt("LocalSocks5Port")
	proxyUser := vipConfig.GetString("ProxyUser")
	proxyPass := vipConfig.GetString("ProxyPass")

	startProxyServers(localSocks5Port, localProxyPort, proxyUser, proxyPass)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	<-sigCh
	log.Println("Shutting down...")
	close(shutdownCh)
	time.Sleep(1 * time.Second) // 等待资源清理
}
