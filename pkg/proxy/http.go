package proxy

import (
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// StartHTTPServer starts an HTTP server for proxying on the given address
func StartHTTPServer(addr string, cm *ConnManager, filter *RequestFilter) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleHTTPProxy(w, r, cm, filter)
	})

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	log.Printf("Starting HTTP proxy server on %s", addr)
	return server.ListenAndServe()
}
func StartHAProxyListener(addr string, cm *ConnManager, filter *RequestFilter) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleHTTPProxy(w, r, cm, filter)
	})

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	log.Printf("Starting HTTP proxy server on %s", addr)
	return server.ListenAndServe()
}

func handleHTTPProxy(w http.ResponseWriter, r *http.Request, cm *ConnManager, filter *RequestFilter) {
	log.Printf("HTTP request from %s for host %s", r.RemoteAddr, r.Host)

	if !filter.AllowHTTP(r.Host, r.URL.Path) {
		http.Error(w, "Blocked by proxy filter", http.StatusForbidden)
		log.Printf("Request blocked by filter host=%s path=%s", r.Host, r.URL.Path)
		return
	}

	// Hijack the client connection to control both sides as raw TCP streams
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		http.Error(w, "Hijacking failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientBuf.Flush()

	// Dial upstream HTTP server on default port 80
	serverConn, err := net.DialTimeout("tcp", r.Host+":80", 10*time.Second)
	if err != nil {
		http.Error(w, "Failed to dial upstream server "+r.Host, http.StatusBadGateway)
		clientConn.Close()
		return
	}

	meta := ConnMeta{
		ClientAddr: clientConn.RemoteAddr().String(),
		ServerAddr: serverConn.RemoteAddr().String(),
		Hostname:   r.Host,
		Protocol:   "http",
		CreatedAt:  time.Now(),
	}

	id := cm.Add(clientConn, serverConn, meta)
	log.Printf("Tracking HTTP connection id=%s client=%s server=%s", id, meta.ClientAddr, meta.ServerAddr)

	// Write original request bytes to upstream server
	if err := r.Write(serverConn); err != nil {
		log.Printf("Error forwarding request to server: %v", err)
		closeConnPair(cm, id)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go proxyCopy(&wg, serverConn, clientBuf)
	go proxyCopy(&wg, clientConn, serverConn)

	wg.Wait()

	closeConnPair(cm, id)
}

func proxyCopy(wg *sync.WaitGroup, dst net.Conn, src io.Reader) {
	defer wg.Done()
	_, err := io.Copy(dst, src)
	if err != nil {
		log.Printf("Proxy copy error: %v", err)
	}
}

func closeConnPair(cm *ConnManager, id string) {
	value, ok := cm.conns.Load(id)
	if !ok {
		return
	}
	pc := value.(*ProxyConnection)
	pc.Client.Close()
	pc.Server.Close()
	cm.Remove(id)
	log.Printf("Closed HTTP connection %s", id)
}
