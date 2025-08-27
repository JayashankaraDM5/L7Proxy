package proxy

import (
	"log"
	"strings"
	"sync"
	"time"
)

// RequestFilter holds hostname and SNI allowlists for filtering
type RequestFilter struct {
	mu          sync.RWMutex
	allowedHosts map[string]struct{}
	allowedSNIs  map[string]struct{}
	lastReload  time.Time
}

// NewRequestFilter creates a new instance with default allowed hosts and SNIs
func NewRequestFilter() *RequestFilter {
	return &RequestFilter{
		allowedHosts: map[string]struct{}{
			"example.com": {},
			"www.google.com": {},
		},
		allowedSNIs: map[string]struct{}{
			"example.com": {},
			"www.google.com": {},
		},
	}
}

// AllowHTTP returns true if the host and path are allowed by the filter
func (f *RequestFilter) AllowHTTP(host, path string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	
	// Normalize to lowercase
	host = strings.ToLower(host)
	
	// Direct match allowed hosts
	if _, ok := f.allowedHosts[host]; ok {
		return true
	}
	return false
}

// AllowSNI returns true if the SNI hostname is allowed
func (f *RequestFilter) AllowSNI(sni string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	
	// Normalize
	sni = strings.ToLower(sni)
	
	if _, ok := f.allowedSNIs[sni]; ok {
		return true
	}
	return false
}

// Reload allows reloading allowed hosts and SNIs from config (e.g., JSON or file content)
func (f *RequestFilter) Reload(hosts []string, snis []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	
	// Clear existing maps
	f.allowedHosts = map[string]struct{}{}
	f.allowedSNIs = map[string]struct{}{}

	// Reload allowed hosts
	for _, h := range hosts {
		f.allowedHosts[strings.ToLower(h)] = struct{}{}
	}

	// Reload allowed SNIs
	for _, s := range snis {
		f.allowedSNIs[strings.ToLower(s)] = struct{}{}
	}

	f.lastReload = time.Now()

	log.Printf("Reloaded filter: %d allowed hosts, %d allowed SNIs", len(f.allowedHosts), len(f.allowedSNIs))
	return nil
}

