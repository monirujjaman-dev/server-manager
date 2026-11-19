package enroll

import (
	"net/netip"
	"sync"

	"golang.org/x/time/rate"
)

// ipLimiter rate-limits an unauthenticated endpoint per source IP. The map is reset
// when it grows too large, which bounds memory under address-spoofing floods at the cost
// of briefly forgetting limits.
type ipLimiter struct {
	mu    sync.Mutex
	m     map[netip.Addr]*rate.Limiter
	limit rate.Limit
	burst int
	max   int
}

func newIPLimiter(limit rate.Limit, burst int) *ipLimiter {
	return &ipLimiter{m: make(map[netip.Addr]*rate.Limiter), limit: limit, burst: burst, max: 10000}
}

func (l *ipLimiter) allow(ip netip.Addr) bool {
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
