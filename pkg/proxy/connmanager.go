package proxy

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ConnMeta stores metadata for tracked TCP connection pairs
type ConnMeta struct {
	ID          string
	ClientAddr  string
	ServerAddr  string
	Hostname    string
	SNI         string
	Protocol    string // e.g. "http", "https_tls_passthrough" etc.
	HAProxyAddr string // Loopback HAProxy address if TLS termination mode
	CreatedAt   time.Time
}

// ProxyConnection couples client and server connections with metadata
type ProxyConnection struct {
	Client net.Conn
	Server net.Conn
	Meta   ConnMeta
}

// ConnManager tracks live connections and metrics
type ConnManager struct {
	conns sync.Map
	idSeq uint64
}

// Constructor for connection manager
func NewConnManager() *ConnManager {
	return &ConnManager{}
}

// NextID generates unique connection IDs with atomic increment
func (m *ConnManager) NextID() string {
	id := atomic.AddUint64(&m.idSeq, 1)
	return fmt.Sprintf("conn-%d", id)
}

// Add stores a new tracked connection pair and updates metrics
func (m *ConnManager) Add(client, server net.Conn, meta ConnMeta) string {
	meta.ID = m.NextID()
	m.conns.Store(meta.ID, &ProxyConnection{Client: client, Server: server, Meta: meta})

	atomic.AddInt64(&metrics.ClientProxyConns, 1)
	atomic.AddInt64(&metrics.ProxyServerConns, 1)

	if strings.HasPrefix(meta.Protocol, "https") {
		atomic.AddInt64(&metrics.HTTPSConnCount, 1)
	} else {
		atomic.AddInt64(&metrics.HTTPConnCount, 1)
	}

	if meta.HAProxyAddr != "" {
		atomic.AddInt64(&metrics.ProxyHAProxyConns, 1)
	}

	log.Printf("Added connection %s: client %s - server %s - protocol %s", meta.ID, meta.ClientAddr, meta.ServerAddr, meta.Protocol)

	return meta.ID
}

// Remove deletes a tracked connection and updates metrics
func (m *ConnManager) Remove(id string) {
	value, ok := m.conns.Load(id)
	if !ok {
		return
	}
	pc := value.(*ProxyConnection)
	m.conns.Delete(id)

	atomic.AddInt64(&metrics.ClientProxyConns, -1)
	atomic.AddInt64(&metrics.ProxyServerConns, -1)

	if strings.HasPrefix(pc.Meta.Protocol, "https") {
		atomic.AddInt64(&metrics.HTTPSConnCount, -1)
	} else {
		atomic.AddInt64(&metrics.HTTPConnCount, -1)
	}

	if pc.Meta.HAProxyAddr != "" {
		atomic.AddInt64(&metrics.ProxyHAProxyConns, -1)
	}

	log.Printf("Removed connection %s: client %s - server %s", id, pc.Meta.ClientAddr, pc.Meta.ServerAddr)
}

// CloseByFilter closes connections matching a filter function
func (m *ConnManager) CloseByFilter(filter func(meta *ConnMeta) bool) {
	m.conns.Range(func(key, value interface{}) bool {
		pc := value.(*ProxyConnection)
		if filter(&pc.Meta) {
			log.Printf("Closing connection %s client %s server %s", pc.Meta.ID, pc.Meta.ClientAddr, pc.Meta.ServerAddr)
			sendHTTPConnectionClose(pc.Client)
			sendHTTPConnectionClose(pc.Server)
			pc.Client.Close()
			pc.Server.Close()
			m.conns.Delete(key)
		}
		return true
	})
}

// Stats returns a snapshot of current connections
func (m *ConnManager) Stats() []ConnMeta {
	conns := make([]ConnMeta, 0)
	m.conns.Range(func(key, value interface{}) bool {
		pc := value.(*ProxyConnection)
		conns = append(conns, pc.Meta)
		return true
	})
	return conns
}

// Global metrics counters used for Prometheus-style metrics (atomic)
var metrics = struct {
	ClientProxyConns  int64
	ProxyServerConns  int64
	ProxyHAProxyConns int64
	HTTPConnCount     int64
	HTTPSConnCount    int64
}{}

// sendHTTPConnectionClose sends minimal HTTP/1.1 Connection: close to peer
func sendHTTPConnectionClose(conn net.Conn) {
	if conn == nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err := conn.Write([]byte("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"))
	if err != nil {
		log.Printf("Error sending HTTP close: %v", err)
	}
	_ = conn.SetWriteDeadline(time.Time{})
}

