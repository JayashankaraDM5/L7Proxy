package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/your-username/go-l7-proxy/pkg/proxy"
)

func main() {
	// Create connection manager and filter instances
	connManager := proxy.NewConnManager()
	filter := proxy.NewRequestFilter()

	// HAProxy TLS termination loopback address
	haproxyAddr := "127.0.0.1:8443"

	startHTTPProxy(connManager, filter)
	startHTTPSProxy(connManager, filter, haproxyAddr, true) // TLS termination enabled
	startHAProxyForwardedListener(connManager, filter)
	startMetricsEndpoint()
	startFileWatcher(connManager)

	// Setup graceful shutdown on SIGINT/SIGTERM
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	<-stop
	log.Println("Shutdown signal received, stopping servers gracefully...")
	// Add graceful shutdown handling in future...

	log.Println("Proxy shutdown complete.")
}

func startHTTPProxy(cm *proxy.ConnManager, filter *proxy.RequestFilter) {
	go func() {
		if err := proxy.StartHTTPServer(":80", cm, filter); err != nil {
			log.Fatalf("HTTP proxy failed: %v", err)
		}
	}()
}

func startHTTPSProxy(cm *proxy.ConnManager, filter *proxy.RequestFilter, haproxyAddr string, tlsTermination bool) {
	go func() {
		if err := proxy.StartHTTPSServer(":443", cm, filter, haproxyAddr, tlsTermination); err != nil {
			log.Fatalf("HTTPS proxy failed: %v", err)
		}
	}()
}

func startHAProxyForwardedListener(cm *proxy.ConnManager, filter *proxy.RequestFilter) {
	go func() {
		if err := proxy.StartHAProxyListener(":8080", cm, filter); err != nil {
			log.Fatalf("HAProxy forwarded listener failed: %v", err)
		}
	}()
}

func startMetricsEndpoint() {
	go func() {
		if err := proxy.StartMetricsServer(":9090"); err != nil {
			log.Fatalf("Metrics server failed: %v", err)
		}
	}()
}

func startFileWatcher(cm *proxy.ConnManager) {
	go proxy.StartFileWatcher("/tmp/proxy-trigger.txt", cm)
}
