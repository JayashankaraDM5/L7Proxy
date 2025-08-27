package proxy

import (
	"bufio"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// StartHTTPSServer starts a TCP listener on the given address to handle HTTPS traffic
// with TLS termination mode or passthrough, depending on tlsTermination flag.
// haproxyAddress specifies where to forward traffic for TLS termination (loopback).
func StartHTTPSServer(addr string, cm *ConnManager, filter *RequestFilter, haproxyAddress string, tlsTermination bool) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("HTTPS proxy server started on %s, TLS termination: %v", addr, tlsTermination)

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go func(c net.Conn) {
			if tlsTermination {
				handleTLSWithTermination(c, cm, filter, haproxyAddress)
			} else {
				handleTLSPassthrough(c, cm, filter)
			}
		}(clientConn)
	}
}

// handleTLSWithTermination forwards raw TLS connection to HAProxy for termination after validating SNI.
func handleTLSWithTermination(clientConn net.Conn, cm *ConnManager, filter *RequestFilter, haproxyAddress string) {
	defer clientConn.Close()
	log.Printf("Handling HTTPS (TLS termination) from %v", clientConn.RemoteAddr())

	valid, sni := parseClientHelloSNI(clientConn)
	if !valid || sni == "" {
		log.Printf("Invalid or missing SNI from client %v; closing connection", clientConn.RemoteAddr())
		return
	}

	if !filter.AllowSNI(sni) {
		log.Printf("Blocked HTTPS SNI %s by filter", sni)
		return
	}

	haproxyConn, err := net.Dial("tcp", haproxyAddress)
	if err != nil {
		log.Printf("Failed to connect to HAProxy at %s: %v", haproxyAddress, err)
		return
	}
	defer haproxyConn.Close()

	meta := ConnMeta{
		ClientAddr:  clientConn.RemoteAddr().String(),
		ServerAddr:  haproxyConn.RemoteAddr().String(),
		SNI:         sni,
		Protocol:    "https_tls_termination",
		HAProxyAddr: haproxyAddress,
		CreatedAt:   time.Now(),
	}
	id := cm.Add(clientConn, haproxyConn, meta)
	log.Printf("Tracking TLS termination connections id %s sni %s", id, sni)

	var wg sync.WaitGroup
	wg.Add(2)
	go proxyCopy(&wg, haproxyConn, clientConn)
	go proxyCopy(&wg, clientConn, haproxyConn)
	wg.Wait()

	cm.Remove(id)
	log.Printf("Closed TLS termination connection id %s", id)
}

// handleTLSPassthrough tunnels raw TLS connections directly to destination based on SNI.
func handleTLSPassthrough(clientConn net.Conn, cm *ConnManager, filter *RequestFilter) {
	defer clientConn.Close()
	log.Printf("Handling HTTPS passthrough from %v", clientConn.RemoteAddr())

	sni, err := peekClientHelloSNI(clientConn)
	if err != nil || sni == "" {
		log.Printf("Failed to parse or no SNI for passthrough: %v", err)
		return
	}

	if !filter.AllowSNI(sni) {
		log.Printf("Blocked HTTPS passthrough SNI %s by filter", sni)
		return
	}

	// Dial destination server on port 443
	destConn, err := net.DialTimeout("tcp", sni+":443", 10*time.Second)
	if err != nil {
		log.Printf("Failed to dial destination %s for passthrough: %v", sni, err)
		return
	}
	defer destConn.Close()

	meta := ConnMeta{
		ClientAddr: clientConn.RemoteAddr().String(),
		ServerAddr: destConn.RemoteAddr().String(),
		SNI:        sni,
		Protocol:   "https_tls_passthrough",
		CreatedAt:  time.Now(),
	}
	id := cm.Add(clientConn, destConn, meta)
	log.Printf("Tracking TLS passthrough connection id %s sni %s", id, sni)

	var wg sync.WaitGroup
	wg.Add(2)
	go proxyCopy(&wg, destConn, clientConn)
	go proxyCopy(&wg, clientConn, destConn)
	wg.Wait()

	cm.Remove(id)
	log.Printf("Closed TLS passthrough connection id %s", id)
}

// parseClientHelloSNI reads the initial TLS ClientHello packet to extract the SNI hostname.
func parseClientHelloSNI(conn net.Conn) (bool, string) {
	// Use peekClientHelloSNI to read bytes non-destructively
	sni, err := peekClientHelloSNI(conn)
	return err == nil && sni != "", sni
}

// peekClientHelloSNI reads TLS ClientHello and returns SNI without consuming from conn.
func peekClientHelloSNI(conn net.Conn) (string, error) {
	reader := bufio.NewReader(conn)
	data, err := reader.Peek(1024) // peek enough bytes for SNI
	if err != nil {
		return "", err
	}

	sni, err := extractSNIFromTLSClientHello(data)
	if err != nil || sni == "" {
		return "", errors.New("SNI not found")
	}

	// Wrap conn so future reads get data from buffered reader
	*conn = &connWithBufferedReader{Conn: conn, reader: reader}
	return sni, nil
}

type connWithBufferedReader struct {
	net.Conn
	reader *bufio.Reader
}

func (c *connWithBufferedReader) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// extractSNIFromTLSClientHello is a simplified parser to find SNI in TLS ClientHello bytes.
// For production, replace with full parsing or third-party library.
func extractSNIFromTLSClientHello(data []byte) (string, error) {
	// Simplified example:
	// This dummy implementation assumes the SNI is always "example.com"
	// Replace with real TLS ClientHello parser (e.g. github.com/refraction-networking/utls)
	return "example.com", nil
}

