package privd

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/uuid"

	"github.com/monirujjaman-dev/server-manager/internal/pki"
)

// The helper's trust anchors (the control plane's command key and this server's
// identity) live in a root-owned directory of their own. They must not be under
// /etc/sm-agent: that directory belongs to the unprivileged agent (it rewrites its
// certificate on renewal), and whoever can write a directory can replace or rename
// anything in it. A compromised agent that could plant its own command key would be
// able to sign arbitrary privileged commands.
const (
	DefaultTrustDir = "/etc/sm-agent-trust"
	commandKeyName  = "command.pub"
	serverIDName    = "server-id"
	// maxTrustFile bounds what is read from a trust file.
	maxTrustFile = 64 << 10
)

// TrustPaths returns the command key and server ID files in dir.
func TrustPaths(dir string) (commandKey, serverID string) {
	return filepath.Join(dir, commandKeyName), filepath.Join(dir, serverIDName)
}

// WriteTrust stores the command key and server identity in dir (created 0755), each
// file 0644 and replaced atomically through an exclusively created temporary file, so a
// planted symlink cannot redirect the write. It is called by `sm-agent enroll` and
// `sm-agent migrate-trust`, which run as root in production.
//
// On Linux dir and its parents must be controlled by the caller: owned by root or the
// caller's user and not writable by group or others. Writing as root into a directory
// someone else can modify would let them swap the files afterwards.
func WriteTrust(dir string, serverID uuid.UUID, commandKey ed25519.PublicKey) error {
	if len(commandKey) != ed25519.PublicKeySize {
		return errors.New("command key has the wrong size")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // public material, readable by the agent
		return err
	}
	if runtime.GOOS == "linux" { // the agent and its helper only run on Linux
		euid := uint32(os.Geteuid()) //nolint:gosec // UIDs fit uint32
		if _, err := checkChain(dir, &euid, true); err != nil {
			return fmt.Errorf("trust directory: %w", err)
		}
	}
	keyPath, idPath := TrustPaths(dir)
	if err := pki.WriteCommandPublicKey(keyPath, commandKey); err != nil {
		return err
	}
	// The identity is written last: its presence marks a complete trust directory.
	return writeAtomic(idPath, []byte(serverID.String()+"\n"))
}

// writeAtomic writes data to a new temporary file in path's directory (O_EXCL, never
// following a planted name) and renames it over path, mode 0644.
func writeAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ErrUntrustedFile is returned when a trust file or one of its directories could be
// modified by someone other than root.
var ErrUntrustedFile = errors.New("untrusted file")

// CheckTrusted verifies that path is a regular file and that it and every directory
// above it are owned by root (or by extraUID, used by tests) and not writable by group
// or others. A world-writable directory with the sticky bit (such as /tmp) is accepted,
// since others cannot rename or delete entries they do not own there. Symlinks are
// resolved first; it returns the resolved path, which callers must read instead of path
// so that a symlink cannot be retargeted between the check and the read.
func CheckTrusted(path string, extraUID *uint32) (string, error) {
	return checkChain(path, extraUID, false)
}

func checkChain(path string, extraUID *uint32, wantDir bool) (string, error) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	real, err = filepath.Abs(real)
	if err != nil {
		return "", err
	}
	for p := real; ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			return "", err
		}
		if p == real {
			if wantDir && !fi.IsDir() {
				return "", fmt.Errorf("%w: %s is not a directory", ErrUntrustedFile, p)
			}
			if !wantDir && !fi.Mode().IsRegular() {
				return "", fmt.Errorf("%w: %s is not a regular file", ErrUntrustedFile, p)
			}
		}
		uid, ok := fileOwner(fi)
		if !ok {
			return "", fmt.Errorf("%w: cannot determine the owner of %s", ErrUntrustedFile, p)
		}
		if uid != 0 && (extraUID == nil || uid != *extraUID) {
			return "", fmt.Errorf("%w: %s is owned by UID %d, not root", ErrUntrustedFile, p, uid)
		}
		mode := fi.Mode()
		sticky := fi.IsDir() && mode&os.ModeSticky != 0
		if mode.Perm()&0o022 != 0 && !sticky {
			return "", fmt.Errorf("%w: %s is writable by group or others (mode %v)", ErrUntrustedFile, p, mode.Perm())
		}
		if parent := filepath.Dir(p); parent == p {
			return real, nil
		}
	}
}

// readTrusted checks path with CheckTrusted and reads the resolved file (bounded).
func readTrusted(path string, extraUID *uint32) ([]byte, error) {
	real, err := CheckTrusted(path, extraUID)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(real) //nolint:gosec // checked above: root-controlled path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxTrustFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxTrustFile {
		return nil, fmt.Errorf("%s is too large", path)
	}
	return b, nil
}

// ParseServerID parses the content of a server-id file; name is used in errors.
func ParseServerID(data []byte, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(strings.TrimSpace(string(data)))
	if err != nil {
		return uuid.Nil, fmt.Errorf("%s: %w", name, err)
	}
	return id, nil
}

// ReadServerID reads a file written by WriteTrust (no ownership checks; for tools and
// tests).
func ReadServerID(path string) (uuid.UUID, error) {
	b, err := os.ReadFile(path) //nolint:gosec // configured path
	if err != nil {
		return uuid.Nil, err
	}
	return ParseServerID(b, path)
}
