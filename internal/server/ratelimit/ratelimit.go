// Package ratelimit limits unauthenticated endpoints per source IP.
package ratelimit

import (
	"net/netip"
	"sync"

	"golang.org/x/time/rate"
)

// IPLimiter rate-limits an unauthenticated endpoint per source IP. The map is reset
// when it grows too large, which bounds memory under address-spoofing floods at the cost
// of briefly forgetting limits.
type IPLimiter struct {
	mu    sync.Mutex
	m     map[netip.Addr]*rate.Limiter
	limit rate.Limit
	burst int
	max   int
}

// New allows burst requests and then limit per second for each IP.
func New(limit rate.Limit, burst int) *IPLimiter {
	return &IPLimiter{m: make(map[netip.Addr]*rate.Limiter), limit: limit, burst: burst, max: 10000}
}

// Allow reports whether ip may make another request now.
func (l *IPLimiter) Allow(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	lim, ok := l.m[ip]
	if !ok {
		if len(l.m) >= l.max {
			l.m = make(map[netip.Addr]*rate.Limiter)
		}
		lim = rate.NewLimiter(l.limit, l.burst)
		l.m[ip] = lim
	}
	return lim.Allow()
}
