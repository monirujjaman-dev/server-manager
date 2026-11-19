package gateway

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// SessionInfo is a snapshot of one connected agent.
type SessionInfo struct {
	ServerID     uuid.UUID
	RemoteAddr   string
	AgentVersion string
	Hostname     string
	ConnectedAt  time.Time
	LastSeen     time.Time
}

type session struct {
	info   SessionInfo
	cancel context.CancelCauseFunc
}

// Registry tracks connected agents. At most one session per server ID is kept; a new
// connection from the same identity replaces the old one.
type Registry struct {
	mu       sync.RWMutex
	sessions map[uuid.UUID]*session
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{sessions: make(map[uuid.UUID]*session)}
}

func (r *Registry) attach(s *session) (replaced *session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	replaced = r.sessions[s.info.ServerID]
	r.sessions[s.info.ServerID] = s
	return replaced
}

// detach removes s only if it is still the current session for its server.
func (r *Registry) detach(s *session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions[s.info.ServerID] == s {
		delete(r.sessions, s.info.ServerID)
	}
}

func (r *Registry) touch(s *session, t time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s.info.LastSeen = t
}

// Get returns the session for a server, if connected.
func (r *Registry) Get(id uuid.UUID) (SessionInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[id]
	if !ok {
		return SessionInfo{}, false
	}
	return s.info, true
}

// List returns all connected sessions ordered by hostname.
func (r *Registry) List() []SessionInfo {
	r.mu.RLock()
	out := make([]SessionInfo, 0, len(r.sessions))
	for _, s := range r.sessions {
		out = append(out, s.info)
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out
}

// Len returns the number of connected agents.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

// Disconnect ends the session of one server (used when a server is revoked).
func (r *Registry) Disconnect(id uuid.UUID, cause error) bool {
	r.mu.RLock()
	s, ok := r.sessions[id]
	r.mu.RUnlock()
	if ok {
		s.cancel(cause)
	}
	return ok
}

// CloseAll ends every session, e.g. during shutdown.
func (r *Registry) CloseAll(cause error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.sessions {
		s.cancel(cause)
	}
}
