package audit_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/google/uuid"

	"github.com/monirujjaman-dev/server-manager/internal/server/audit"
	"github.com/monirujjaman-dev/server-manager/internal/server/store"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/storetest"
)

func appendEvents(t *testing.T, s *store.Store, n int) {
	t.Helper()
	ctx := context.Background()
	ip := netip.MustParseAddr("10.0.0.7")
	sid := uuid.New()
	for i := range n {
		tx, err := s.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = audit.Append(ctx, s.WithTx(tx), audit.Event{
			ActorType: audit.ActorUser, ActorID: "alice", SourceIP: &ip, ServerID: &sid,
			Action: "service.restart", Params: map[string]string{"unit": "nginx.service", "n": string(rune('a' + i))},
			Result: audit.Succeeded,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func TestChainVerifies(t *testing.T) {
	s, _ := storetest.Open(t)
	appendEvents(t, s, 5)
	n, err := audit.Verify(context.Background(), s.Queries)
	if err != nil || n != 5 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
}

func TestConcurrentAppendsStayChained(t *testing.T) {
	s, _ := storetest.Open(t)
	errc := make(chan error, 8)
	for range 8 {
		go func() {
			ctx := context.Background()
			tx, err := s.Pool.Begin(ctx)
			if err != nil {
				errc <- err
				return
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if _, err := audit.Append(ctx, s.WithTx(tx), audit.Event{
				ActorType: audit.ActorSystem, ActorID: "test", Action: "x", Result: audit.Succeeded,
			}); err != nil {
				errc <- err
				return
			}
			errc <- tx.Commit(ctx)
		}()
	}
	for range 8 {
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
	}
	if n, err := audit.Verify(context.Background(), s.Queries); err != nil || n != 8 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
}

func TestTamperingDetected(t *testing.T) {
	cases := map[string]string{
		"modified": "UPDATE audit_events SET params = '{\"unit\":\"sshd.service\"}' WHERE id = 3",
		"deleted":  "DELETE FROM audit_events WHERE id = 3",
	}
	for name, stmt := range cases {
		t.Run(name, func(t *testing.T) {
			s, _ := storetest.Open(t)
			appendEvents(t, s, 5)
			ctx := context.Background()
			// An attacker with database superuser rights could disable the append-only trigger.
			if _, err := s.Pool.Exec(ctx, "ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update_delete"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Pool.Exec(ctx, stmt); err != nil {
				t.Fatal(err)
			}
			_, err := audit.Verify(ctx, s.Queries)
			var broken *audit.ErrChainBroken
			if !errors.As(err, &broken) {
				t.Fatalf("Verify err = %v, want ErrChainBroken", err)
			}
			if broken.EventID < 3 || broken.EventID > 4 {
				t.Errorf("broken at %d, want 3 or 4", broken.EventID)
			}
		})
	}
}

func TestAppendValidates(t *testing.T) {
	s, _ := storetest.Open(t)
	if _, err := audit.Append(context.Background(), s.Queries, audit.Event{Action: "x"}); err == nil {
		t.Fatal("expected validation error")
	}
}
