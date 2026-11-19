package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/monirujjaman-dev/server-manager/internal/server/store/db"
)

// These tests need a dedicated, disposable PostgreSQL database:
//
//	SM_TEST_DATABASE_URL=postgres://user@127.0.0.1:5432/sm_test go test ./internal/server/store/
//
// The schema in that database is dropped and recreated.
func testURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("SM_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("SM_TEST_DATABASE_URL not set")
	}
	return url
}

func TestMigrationsAndQueries(t *testing.T) {
	url := testURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	m, err := NewMigrator(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	if err := m.DownTo(ctx, 0); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if n, err := m.Up(ctx); err != nil || n == 0 {
		t.Fatalf("up: applied %d, %v", n, err)
	}
	st, err := m.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range st {
		if !s.Applied {
			t.Errorf("migration %d not applied", s.Version)
		}
	}

	s, err := Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	t.Run("servers", func(t *testing.T) {
		g, err := s.CreateServerGroup(ctx, "production")
		if err != nil {
			t.Fatal(err)
		}
		id := uuid.New()
		if _, err := s.CreateServer(ctx, db.CreateServerParams{ID: id, Name: "web-1", GroupID: &g.ID}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateServer(ctx, db.CreateServerParams{ID: uuid.New(), Name: "Bad Name!"}); err == nil {
			t.Error("invalid server name accepted")
		}
		if err := s.UpdateServerFacts(ctx, db.UpdateServerFactsParams{
			ID: id, Hostname: "web-1.internal", OS: "linux", Arch: "amd64", Distro: "ubuntu", DistroVersion: "24.04", AgentVersion: "v0.0.1",
		}); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetServer(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != "online" || got.Hostname != "web-1.internal" || got.LastSeenAt == nil {
			t.Errorf("unexpected server row: %+v", got)
		}

		// A revoked server must not come back online through a heartbeat.
		if err := s.SetServerStatus(ctx, db.SetServerStatusParams{ID: id, Status: "revoked"}); err != nil {
			t.Fatal(err)
		}
		if err := s.MarkServerSeen(ctx, id); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.GetServer(ctx, id); got.Status != "revoked" {
			t.Errorf("revoked server status changed to %q", got.Status)
		}
	})

	t.Run("users", func(t *testing.T) {
		if _, err := s.CreateUser(ctx, db.CreateUserParams{Email: "Admin@Example.com", AuthProvider: "local"}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateUser(ctx, db.CreateUserParams{Email: "admin@example.com", AuthProvider: "local"}); err == nil {
			t.Error("duplicate e-mail with different case accepted")
		}
		u, err := s.GetUserByEmail(ctx, "ADMIN@example.com")
		if err != nil || !u.MfaRequired {
			t.Errorf("lookup: %+v, %v", u, err)
		}
	})

	t.Run("audit is append-only", func(t *testing.T) {
		h := sha256.Sum256([]byte("event-1"))
		id, err := s.InsertAuditEvent(ctx, db.InsertAuditEventParams{
			Ts: time.Now(), ActorType: "system", ActorID: "test", Action: "test.event",
			Params: json.RawMessage(`{}`), Result: "succeeded", Hash: h[:],
		})
		if err != nil {
			t.Fatal(err)
		}
		latest, err := s.LatestAuditHash(ctx)
		if err != nil || string(latest) != string(h[:]) {
			t.Fatalf("latest hash = %x, %v", latest, err)
		}
		for _, q := range []string{
			"UPDATE audit_events SET action = 'tampered' WHERE id = $1",
			"DELETE FROM audit_events WHERE id = $1",
		} {
			if _, err := s.Pool.Exec(ctx, q, id); err == nil {
				t.Errorf("%q succeeded on append-only table", q)
			}
		}
		if _, err := s.Pool.Exec(ctx, "TRUNCATE audit_events"); err == nil {
			t.Error("TRUNCATE succeeded on append-only table")
		}
	})

	s.Close()
	if err := m.DownTo(ctx, 0); err != nil {
		t.Fatalf("down: %v", err)
	}
	if _, err := m.Up(ctx); err != nil {
		t.Fatalf("up after down: %v", err)
	}
}
