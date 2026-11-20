package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/monirujjaman-dev/server-manager/internal/pki"
	"github.com/monirujjaman-dev/server-manager/internal/privd"
)

func TestCheckTrustDir(t *testing.T) {
	for _, tc := range []struct {
		dir, trust string
		ok         bool
	}{
		{"/etc/sm-agent", "/etc/sm-agent-trust", true},
		{"/etc/sm-agent", "/etc/sm-agent", false},
		{"/etc/sm-agent", "/etc/sm-agent/trust", false},
		{"/etc/sm-agent", "/etc/sm-agent/../sm-agent/x", false},
		{"/etc/sm-agent", "", false},
		{"/etc/sm-agent/sub", "/etc/sm-agent", true}, // parent of the agent dir: not writable through it
		{"/etc/sm-agent", "/etc/sm-agent/..trust", false},
		{"/etc/sm-agent", "/etc/sm-agent-trust/../sm-agent/t", false},
	} {
		err := checkTrustDir(tc.dir, tc.trust)
		if (err == nil) != tc.ok {
			t.Errorf("checkTrustDir(%q, %q) = %v, want ok=%v", tc.dir, tc.trust, err, tc.ok)
		}
	}
}

// oldEnrollment writes an agent directory as enrollments before the trust directory
// did: certificate plus command.pub next to the agent's key.
func oldEnrollment(t *testing.T) (dir string, id uuid.UUID, key ed25519.PublicKey) {
	t.Helper()
	base := t.TempDir()
	// Like /etc: not writable by group or others (a umask of 002 would make it so).
	for _, p := range []string{filepath.Dir(base), base} {
		if err := os.Chmod(p, 0o755); err != nil { //nolint:gosec // directories
			t.Fatal(err)
		}
	}
	dir = filepath.Join(base, "sm-agent")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ca, err := pki.CreateCA("Test")
	if err != nil {
		t.Fatal(err)
	}
	_, csr, _ := pki.NewAgentKey()
	id = uuid.New()
	cert, err := ca.SignAgentCSR(csr, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.WriteCertFile(filepath.Join(dir, "agent.crt"), cert); err != nil {
		t.Fatal(err)
	}
	key, _, _ = ed25519.GenerateKey(rand.Reader)
	if err := pki.WriteCommandPublicKey(filepath.Join(dir, "command.pub"), key); err != nil {
		t.Fatal(err)
	}
	return dir, id, key
}

func TestMigrateTrust(t *testing.T) {
	dir, id, key := oldEnrollment(t)
	trust := filepath.Join(filepath.Dir(dir), "sm-agent-trust")
	done, err := MigrateTrust(dir, trust)
	if err != nil || !done {
		t.Fatalf("MigrateTrust = %v, %v", done, err)
	}
	keyPath, idPath := privd.TrustPaths(trust)
	gotID, err := privd.ReadServerID(idPath)
	if err != nil || gotID != id {
		t.Fatalf("server id %v, %v; want %v", gotID, err, id)
	}
	gotKey, err := pki.ReadCommandPublicKey(keyPath)
	if err != nil || !gotKey.Equal(key) {
		t.Fatalf("key %x, %v", gotKey, err)
	}

	// Once migrated, a key the agent writes later into its own directory is ignored.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := pki.WriteCommandPublicKey(filepath.Join(dir, "command.pub"), other); err != nil {
		t.Fatal(err)
	}
	if done, err := MigrateTrust(dir, trust); err != nil || done {
		t.Fatalf("second MigrateTrust = %v, %v; want no-op", done, err)
	}
	if gotKey, _ := pki.ReadCommandPublicKey(keyPath); !gotKey.Equal(key) {
		t.Fatal("trust key was replaced by the agent's copy")
	}

	if _, err := MigrateTrust(dir, filepath.Join(dir, "trust")); err == nil || !strings.Contains(err.Error(), "inside") {
		t.Fatalf("trust dir inside the agent dir accepted: %v", err)
	}
}

func TestCheckTrustDirResolvesSymlinks(t *testing.T) {
	base := t.TempDir()
	agentDir := filepath.Join(base, "sm-agent")
	if err := os.Mkdir(agentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "looks-separate")
	if err := os.Symlink(agentDir, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := checkTrustDir(agentDir, filepath.Join(link, "trust")); err == nil {
		t.Fatal("trust dir reached through a symlink into the agent dir was accepted")
	}
}

func TestMigrateTrustNeverReplacesAndRefusesUnsafeInputs(t *testing.T) {
	dir, _, _ := oldEnrollment(t)
	trust := filepath.Join(filepath.Dir(dir), "sm-agent-trust")
	keyPath, idPath := privd.TrustPaths(trust)

	// A partial trust directory (key only) is left alone: nothing from the agent's
	// directory may replace a key that is already there.
	rootKey, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := os.MkdirAll(trust, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := pki.WriteCommandPublicKey(keyPath, rootKey); err != nil {
		t.Fatal(err)
	}
	if done, err := MigrateTrust(dir, trust); err != nil || done {
		t.Fatalf("partial trust dir: %v, %v; want no-op", done, err)
	}
	if k, _ := pki.ReadCommandPublicKey(keyPath); !k.Equal(rootKey) {
		t.Fatal("existing trust key replaced")
	}
	if _, err := os.Stat(idPath); err == nil {
		t.Fatal("server-id written next to a key that was not migrated")
	}

	for name, tamper := range map[string]func(t *testing.T){
		"missing command key": func(t *testing.T) {
			if err := os.Remove(filepath.Join(dir, "command.pub")); err != nil {
				t.Fatal(err)
			}
		},
		"symlinked command key": func(t *testing.T) {
			real := filepath.Join(t.TempDir(), "k.pub")
			k, _, _ := ed25519.GenerateKey(rand.Reader)
			if err := pki.WriteCommandPublicKey(real, k); err != nil {
				t.Fatal(err)
			}
			_ = os.Remove(filepath.Join(dir, "command.pub"))
			if err := os.Symlink(real, filepath.Join(dir, "command.pub")); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
		},
		"oversized certificate": func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, "agent.crt"), make([]byte, maxAgentFile+1), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			_ = os.RemoveAll(trust)
			dir, _, _ = oldEnrollment(t)
			trust = filepath.Join(filepath.Dir(dir), "sm-agent-trust")
			tamper(t)
			if done, err := MigrateTrust(dir, trust); err == nil || done {
				t.Fatalf("MigrateTrust = %v, %v; want an error", done, err)
			}
			if _, err := os.Stat(trust); err == nil {
				if entries, _ := os.ReadDir(trust); len(entries) > 0 {
					t.Fatalf("trust files written: %v", entries)
				}
			}
		})
	}
}
