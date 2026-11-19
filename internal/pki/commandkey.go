package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// CommandKeyFile holds the control plane's Ed25519 command-signing key. It is separate
// from the TLS keys so that it can later move to a KMS or HSM.
const CommandKeyFile = "command.key"

// LoadOrCreateCommandKey reads the command-signing key from dir, creating it on first use.
func LoadOrCreateCommandKey(dir string) (ed25519.PrivateKey, bool, error) {
	path := filepath.Join(dir, CommandKeyFile)
	signer, err := ReadKeyFile(path)
	if err == nil {
		k, ok := signer.(ed25519.PrivateKey)
		if !ok {
			return nil, false, fmt.Errorf("%s: want an Ed25519 key, got %T", path, signer)
		}
		return k, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, err
	}
	if err := WriteKeyFile(path, k, false); err != nil {
		return nil, false, err
	}
	return k, true, nil
}

// WriteCommandPublicKey stores a raw Ed25519 public key as PKIX PEM, atomically.
func WriteCommandPublicKey(path string, pub ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	return writeAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644)
}

// ReadCommandPublicKey reads a key written by WriteCommandPublicKey.
func ReadCommandPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // configured path
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%s: no PUBLIC KEY PEM block", path)
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: want an Ed25519 public key, got %T", path, k)
	}
	return pub, nil
}
