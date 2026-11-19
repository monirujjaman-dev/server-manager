package command

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

func restart(unit string) *agentv1.ActionRequest {
	return &agentv1.ActionRequest{Action: &agentv1.ActionRequest_ServiceControl{ServiceControl: &agentv1.ServiceControlRequest{
		Unit: unit, Operation: agentv1.ServiceOperation_SERVICE_OPERATION_RESTART,
	}}}
}

func setup(t *testing.T) (*Signer, *Verifier, uuid.UUID) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	server := uuid.New()
	s := NewSigner(key)
	return s, NewVerifier(s.PublicKey(), server), server
}

func TestSignVerifyOnce(t *testing.T) {
	s, v, server := setup(t)
	cmd, err := s.Sign(uuid.New(), server, restart("nginx.service"), 0)
	if err != nil {
		t.Fatal(err)
	}
	env, err := v.Verify(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if env.GetRequest().GetServiceControl().GetUnit() != "nginx.service" {
		t.Fatalf("decoded %v", env)
	}
	if _, err := v.Verify(cmd); !errors.Is(err, ErrRejected) {
		t.Fatalf("replay accepted: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	s, v, server := setup(t)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)

	tampered, _ := s.Sign(uuid.New(), server, restart("nginx.service"), 0)
	tampered.Envelope[len(tampered.Envelope)-1] ^= 1

	wrongServer, _ := s.Sign(uuid.New(), uuid.New(), restart("nginx.service"), 0)
	foreign, _ := NewSigner(otherKey).Sign(uuid.New(), server, restart("nginx.service"), 0)

	old := NewSigner(s.key)
	old.now = func() time.Time { return time.Now().Add(-2 * time.Minute) }
	expired, _ := old.Sign(uuid.New(), server, restart("nginx.service"), 0)

	future := NewSigner(s.key)
	future.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	early, _ := future.Sign(uuid.New(), server, restart("nginx.service"), 0)

	badParams, _ := s.Sign(uuid.New(), server, restart("nginx; rm -rf /"), 0)

	// A validly signed envelope with an overlong validity window.
	env := &agentv1.CommandEnvelope{Id: uuid.NewString(), ServerId: server.String(),
		IssuedAt: timestamppb.Now(), ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)), Request: restart("a.service")}
	raw, _ := proto.Marshal(env)
	longLived := &agentv1.Command{Envelope: raw, Signature: ed25519.Sign(s.key, raw)}

	for name, cmd := range map[string]*agentv1.Command{
		"tampered": tampered, "wrong server": wrongServer, "foreign key": foreign,
		"expired": expired, "issued in future": early, "invalid params": badParams, "too long-lived": longLived,
	} {
		if _, err := v.Verify(cmd); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestValidate(t *testing.T) {
	sig := func(pid int32, s agentv1.Signal) *agentv1.ActionRequest {
		return &agentv1.ActionRequest{Action: &agentv1.ActionRequest_ProcessSignal{ProcessSignal: &agentv1.ProcessSignalRequest{Pid: pid, Signal: s}}}
	}
	bad := map[string]*agentv1.ActionRequest{
		"empty":          {},
		"unit traversal": restart("../../etc/passwd.service"),
		"unit no suffix": restart("nginx"),
		"pid 1":          sig(1, agentv1.Signal_SIGNAL_KILL),
		"no signal":      sig(100, agentv1.Signal_SIGNAL_UNSPECIFIED),
		"bad signal":     sig(100, agentv1.Signal(99)),
	}
	for name, req := range bad {
		if err := Validate(req); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := Validate(sig(1234, agentv1.Signal_SIGNAL_TERM)); err != nil {
		t.Error(err)
	}
	if err := Validate(restart("getty@tty1.service")); err != nil {
		t.Error(err)
	}
	logq := func(q *agentv1.LogQueryRequest) *agentv1.ActionRequest {
		return &agentv1.ActionRequest{Action: &agentv1.ActionRequest_LogQuery{LogQuery: q}}
	}
	seven, eight := uint32(7), uint32(8)
	for name, q := range map[string]*agentv1.LogQueryRequest{
		"flag as unit":     {Unit: "--merge"},
		"cursor injection": {AfterCursor: "x --merge"},
		"priority 8":       {MaxPriority: &eight},
		"huge limit":       {Limit: 10000},
	} {
		if Validate(logq(q)) == nil {
			t.Errorf("log query %s accepted", name)
		}
	}
	if err := Validate(logq(&agentv1.LogQueryRequest{Unit: "ssh.socket", MaxPriority: &seven, AfterCursor: "s=ab;i=1f;b=cd"})); err != nil {
		t.Error(err)
	}
	if NormalizeUnit("nginx") != "nginx.service" || NormalizeUnit("ssh.socket") != "ssh.socket" {
		t.Error("NormalizeUnit")
	}
}
