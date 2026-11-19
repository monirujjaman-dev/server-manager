package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP uses HMAC-SHA1; authenticator apps expect it
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters understood by every authenticator app.
const (
	totpPeriod = 30
	totpDigits = 6
	// totpSkew accepts codes from one step before and after now.
	totpSkew = 1
)

// NewTOTPSecret returns 20 random bytes.
func NewTOTPSecret() ([]byte, error) {
	s := make([]byte, 20)
	_, err := rand.Read(s)
	return s, err
}

// EncodeSecret returns the base32 form shown to users.
func EncodeSecret(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// ProvisioningURI returns an otpauth:// URI for QR codes.
func ProvisioningURI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", EncodeSecret(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

func totpStep(t time.Time) int64 { return t.Unix() / totpPeriod }

// TOTPCode computes the code for a time step (RFC 6238 / RFC 4226).
func TOTPCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) //nolint:gosec // steps are positive
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, v%1000000)
}

// MatchTOTP returns the time step that code matches around now, or false.
func MatchTOTP(secret []byte, code string, now time.Time) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	cur := totpStep(now)
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		if subtle.ConstantTimeCompare([]byte(TOTPCode(secret, cur+d)), []byte(code)) == 1 {
			return cur + d, true
		}
	}
	return 0, false
}
