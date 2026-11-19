// Package auth implements operator authentication (Argon2id passwords plus mandatory
// TOTP), sessions and role-based authorization.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (RFC 9106, second recommended option).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

// MinPasswordLength is enforced for new passwords.
const MinPasswordLength = 12

// ErrWeakPassword is returned for passwords that are too short.
var ErrWeakPassword = fmt.Errorf("password must be at least %d characters", MinPasswordLength)

// CheckPassword applies the password policy.
func CheckPassword(pw string) error {
	if utf8.RuneCountInString(pw) < MinPasswordLength {
		return ErrWeakPassword
	}
	if len(pw) > 1024 {
		return errors.New("password too long")
	}
	return nil
}

// HashPassword returns a PHC-format Argon2id hash.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// VerifyPassword checks pw against a hash from HashPassword in constant time.
func VerifyPassword(pw, hash string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	var mem, iters uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iters, &threads); err != nil {
		return false
	}
	if mem > 1<<20 || iters > 10 || threads == 0 { // refuse absurd stored parameters
		return false
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := enc.DecodeString(parts[5])
	if err != nil || len(want) == 0 || len(want) > 64 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, iters, mem, threads, uint32(len(want))) //nolint:gosec // length checked above
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash is verified when a login names an unknown user, so that the response time
// does not reveal which accounts exist.
var dummyHash, _ = HashPassword("not-a-real-password-for-timing")
