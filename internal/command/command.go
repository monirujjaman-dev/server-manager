// Package command signs and verifies control-plane commands and describes the typed
// actions (name, risk, privilege, parameter validation). It is shared by the control
// plane, the agent and the privileged helper so all three apply the same rules.
package command

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

// Timing limits.
const (
	// DefaultTTL is how long a dispatched command stays valid.
	DefaultTTL = 60 * time.Second
	// MaxTTL is the longest validity a verifier accepts.
	MaxTTL = 5 * time.Minute
	// ClockSkew is tolerated between control plane and agent.
	ClockSkew = 30 * time.Second
)

// Signer signs command envelopes.
type Signer struct {
	key ed25519.PrivateKey
	now func() time.Time
}

// NewSigner returns a signer for key.
func NewSigner(key ed25519.PrivateKey) *Signer { return &Signer{key: key, now: time.Now} }

// PublicKey returns the verification key.
func (s *Signer) PublicKey() ed25519.PublicKey { return s.key.Public().(ed25519.PublicKey) }

// Sign builds and signs an envelope for one job.
func (s *Signer) Sign(jobID, serverID uuid.UUID, req *agentv1.ActionRequest, ttl time.Duration) (*agentv1.Command, error) {
	if ttl <= 0 || ttl > MaxTTL {
		ttl = DefaultTTL
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	now := s.now()
	env := &agentv1.CommandEnvelope{
		Id: jobID.String(), ServerId: serverID.String(),
		IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(ttl)),
		Nonce: nonce, Request: req,
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(env)
	if err != nil {
		return nil, err
	}
	return &agentv1.Command{Envelope: raw, Signature: ed25519.Sign(s.key, raw)}, nil
}

// ErrRejected wraps every verification failure.
var ErrRejected = errors.New("command rejected")

func rejected(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrRejected, fmt.Sprintf(format, a...))
}

// Verifier checks signature, target, validity window and replay. It is safe for
// concurrent use.
type Verifier struct {
	pub      ed25519.PublicKey
	serverID uuid.UUID
	now      func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time // job ID -> forget after
}

// NewVerifier accepts only commands signed by pub for serverID.
func NewVerifier(pub ed25519.PublicKey, serverID uuid.UUID) *Verifier {
	return &Verifier{pub: pub, serverID: serverID, now: time.Now, seen: make(map[string]time.Time)}
}

// Verify returns the decoded envelope of a valid command. Each command is accepted once.
func (v *Verifier) Verify(cmd *agentv1.Command) (*agentv1.CommandEnvelope, error) {
	if len(v.pub) != ed25519.PublicKeySize {
		return nil, rejected("no command verification key")
	}
	if !ed25519.Verify(v.pub, cmd.GetEnvelope(), cmd.GetSignature()) {
		return nil, rejected("bad signature")
	}
	env := &agentv1.CommandEnvelope{}
	if err := proto.Unmarshal(cmd.GetEnvelope(), env); err != nil {
		return nil, rejected("malformed envelope")
	}
	if env.GetServerId() != v.serverID.String() {
		return nil, rejected("command is for server %s", env.GetServerId())
	}
	if _, err := uuid.Parse(env.GetId()); err != nil {
		return nil, rejected("bad command id")
	}
	now := v.now()
	issued, expires := env.GetIssuedAt().AsTime(), env.GetExpiresAt().AsTime()
	switch {
	case env.GetIssuedAt() == nil || env.GetExpiresAt() == nil:
		return nil, rejected("missing validity window")
	case expires.Sub(issued) > MaxTTL || !expires.After(issued):
		return nil, rejected("invalid validity window")
	case issued.After(now.Add(ClockSkew)):
		return nil, rejected("issued in the future (clock skew?)")
	case now.After(expires.Add(ClockSkew)):
		return nil, rejected("expired")
	}
	if err := Validate(env.GetRequest()); err != nil {
		return nil, rejected("%v", err)
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if _, dup := v.seen[env.GetId()]; dup {
		return nil, rejected("replayed")
	}
	if len(v.seen) > 1024 {
		for id, until := range v.seen {
			if now.After(until) {
				delete(v.seen, id)
			}
		}
	}
	v.seen[env.GetId()] = expires.Add(2 * ClockSkew)
	return env, nil
}
