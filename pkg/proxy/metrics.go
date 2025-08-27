package proxy

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ProxyMetrics defines Prometheus counters and gauges for proxy connections
type ProxyMetrics struct {
	ClientProxyConns  prometheus.Gauge
	ProxyServerConns  prometheus.Gauge
	ProxyHAProxyConns prometheus.Gauge
	HTTPConnCount     prometheus.Gauge
	HTTPSConnCount    prometheus.Gauge
}

// global metrics instance
var proxyMetrics = &ProxyMetrics{
	ClientProxyConns: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "proxy_client_proxy_connections",
		Help: "Number of active client-to-proxy TCP connections",
	}),
	ProxyServerConns: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "proxy_proxy_server_connections",
		Help: "Number of active proxy-to-server TCP connections",
	}),
	ProxyHAProxyConns: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "proxy_proxy_haproxy_connections",
		Help: "Number of active proxy-to-haproxy TCP connections (TLS termination)",
	}),
	HTTPConnCount: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "proxy_http_connections",
		Help: "Number of active HTTP connections",
	}),
	HTTPSConnCount: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "proxy_https_connections",
		Help: "Number of active HTTPS connections",
	}),
}

// RegisterMetrics registers all proxy metrics to Prometheus default registry
func RegisterMetrics() {
	prometheus.MustRegister(proxyMetrics.ClientProxyConns)
	prometheus.MustRegister(proxyMetrics.ProxyServerConns)
	prometheus.MustRegister(proxyMetrics.ProxyHAProxyConns)
	prometheus.MustRegister(proxyMetrics.HTTPConnCount)
	prometheus.MustRegister(proxyMetrics.HTTPSConnCount)
}

// UpdateMetrics updates current metrics from atomic counters (thread-safe)
func UpdateMetrics(clientProxy, proxyServer, proxyHA, httpConns, httpsConns int64) {
	proxyMetrics.ClientProxyConns.Set(float64(clientProxy))
	proxyMetrics.ProxyServerConns.Set(float64(proxyServer))
	proxyMetrics.ProxyHAProxyConns.Set(float64(proxyHA))
	proxyMetrics.HTTPConnCount.Set(float64(httpConns))
	proxyMetrics.HTTPSConnCount.Set(float64(httpsConns))
}

// StartMetricsServer exposes the /metrics HTTP endpoint on given addr
func StartMetricsServer(addr string) error {
	RegisterMetrics()
	http.Handle("/metrics", promhttp.Handler())

	log.Printf("Starting metrics HTTP server on %s", addr)
	return http.ListenAndServe(addr, nil)
}

