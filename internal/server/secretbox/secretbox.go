// Package secretbox encrypts small secrets at rest (AES-256-GCM) with a key file kept
// next to the PKI, so a database dump alone does not reveal them. Phase 4 adds envelope
// encryption with an external KMS.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// KeyFile is the key's file name inside the PKI directory.
const KeyFile = "secrets.key"

// Box seals and opens secrets.
type Box struct{ aead cipher.AEAD }

// LoadOrCreate reads dir/secrets.key, creating a random key (mode 0600) on first use.
func LoadOrCreate(dir string) (*Box, bool, error) {
	path := filepath.Join(dir, KeyFile)
	key, err := os.ReadFile(path) //nolint:gosec // fixed file in the PKI directory
	created := false
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, false, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // fixed file
		if err != nil {
			return nil, false, err
		}
		if _, err := f.Write(key); err != nil {
			_ = f.Close()
			return nil, false, err
		}
		if err := f.Close(); err != nil {
			return nil, false, err
		}
		created = true
	} else if err != nil {
		return nil, false, err
	} else if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		return nil, false, fmt.Errorf("%s: permissions %o are too open (want 0600)", path, fi.Mode().Perm())
	}
	b, err := New(key)
	return b, created, err
}

// New creates a box from a 32-byte key.
func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, errors.New("secretbox: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts plaintext bound to context (e.g. "totp:<user id>"), so a ciphertext
// copied to another row does not decrypt.
func (b *Box) Seal(plaintext []byte, context string) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, plaintext, []byte(context)), nil
}

// Open decrypts a value from Seal.
func (b *Box) Open(ciphertext []byte, context string) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(ciphertext) < n {
		return nil, errors.New("secretbox: ciphertext too short")
	}
	return b.aead.Open(nil, ciphertext[:n], ciphertext[n:], []byte(context))
}
