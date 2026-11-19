package pki

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// File names inside a control-plane PKI directory.
const (
	RootCertFile         = "root.crt"
	RootKeyFile          = "root.key"
	IntermediateCertFile = "intermediate.crt"
	IntermediateKeyFile  = "intermediate.key"
	ServerCertFile       = "server.crt" // leaf followed by intermediate
	ServerKeyFile        = "server.key"
)

// SaveCA writes the CA to dir. It refuses to overwrite an existing CA.
func SaveCA(dir string, ca *CA) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(dir, RootCertFile), EncodeCerts(ca.Root), 0o644); err != nil {
		return err
	}
	if ca.RootKey != nil {
		if err := writeKey(filepath.Join(dir, RootKeyFile), ca.RootKey, false); err != nil {
			return err
		}
	}
	if err := writeNew(filepath.Join(dir, IntermediateCertFile), EncodeCerts(ca.Intermediate), 0o644); err != nil {
		return err
	}
	return writeKey(filepath.Join(dir, IntermediateKeyFile), ca.IntermediateKey, false)
}

// LoadCA reads a CA from dir. The root key is optional.
func LoadCA(dir string) (*CA, error) {
	root, err := ReadCertFile(filepath.Join(dir, RootCertFile))
	if err != nil {
		return nil, err
	}
	intermediate, err := ReadCertFile(filepath.Join(dir, IntermediateCertFile))
	if err != nil {
		return nil, err
	}
	intKey, err := ReadKeyFile(filepath.Join(dir, IntermediateKeyFile))
	if err != nil {
		return nil, err
	}
	ca := &CA{Root: root[0], Intermediate: intermediate[0], IntermediateKey: intKey}
	if err := intermediate[0].CheckSignatureFrom(ca.Root); err != nil {
		return nil, fmt.Errorf("intermediate is not signed by root: %w", err)
	}
	if k, err := ReadKeyFile(filepath.Join(dir, RootKeyFile)); err == nil {
		ca.RootKey = k
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return ca, nil
}

// SaveServerCert writes the control-plane certificate chain and key to dir, replacing
// any previous pair atomically.
func SaveServerCert(dir string, ca *CA, cert *x509.Certificate, key crypto.Signer) error {
	if err := writeKey(filepath.Join(dir, ServerKeyFile), key, true); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, ServerCertFile), EncodeCerts(cert, ca.Intermediate), 0o644)
}

// NewAgentKey generates an agent key pair and a CSR for it. The private key never
// leaves the agent; only the CSR is sent to the control plane.
func NewAgentKey() (ed25519.PrivateKey, []byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "sm-agent"},
	}, priv)
	if err != nil {
		return nil, nil, err
	}
	return priv, csr, nil
}

// WriteKeyFile writes a private key in PKCS#8 PEM with mode 0600. With overwrite false
// it fails if the file exists.
func WriteKeyFile(path string, key crypto.Signer, overwrite bool) error {
	return writeKey(path, key, overwrite)
}

// WriteCertFile writes certificates as PEM, replacing the file atomically.
func WriteCertFile(path string, certs ...*x509.Certificate) error {
	return writeAtomic(path, EncodeCerts(certs...), 0o644)
}

// WriteCSRFile writes a DER CSR as PEM, replacing the file atomically.
func WriteCSRFile(path string, csrDER []byte) error {
	return writeAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), 0o644)
}

// ReadCSRFile reads a PEM CSR and returns its DER bytes.
func ReadCSRFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%s: no CERTIFICATE REQUEST PEM block", path)
	}
	return block.Bytes, nil
}

// EncodeCerts PEM-encodes certificates in order.
func EncodeCerts(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

// ReadCertFile reads all PEM certificates from path.
func ReadCertFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%s: no certificates found", path)
	}
	return certs, nil
}

// ReadKeyFile reads a PKCS#8 PEM private key. It refuses keys readable by group or others.
func ReadKeyFile(path string) (crypto.Signer, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: private key permissions %o are too open (want 0600)", path, fi.Mode().Perm())
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s: no PRIVATE KEY PEM block", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s: key type %T cannot sign", path, k)
	}
	return signer, nil
}

func writeKey(path string, key crypto.Signer, overwrite bool) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if overwrite {
		return writeAtomic(path, data, 0o600)
	}
	return writeNew(path, data, 0o600)
}

// writeNew creates path exclusively.
func writeNew(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm) //nolint:gosec // operator-supplied path
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// writeAtomic writes to a temporary file in the same directory and renames it over path.
func writeAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
