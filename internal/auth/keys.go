// Package auth resolves callers (virtual keys, master key, browser sessions) into
// Principals and answers authorization questions about them.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"math/big"

	"golang.org/x/crypto/bcrypt"
)

const KeyPrefix = "lg-"

const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func RandomString(n int) string {
	b := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range b {
		v, _ := rand.Int(rand.Reader, max)
		b[i] = alphabet[v.Int64()]
	}
	return string(b)
}

// NewKey returns a fresh secret key, its storage hash, and a display hint.
func NewKey() (plain, hash, hint string) {
	plain = KeyPrefix + RandomString(40)
	return plain, HashToken(plain), Hint(plain)
}

func HashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func Hint(plain string) string {
	if len(plain) < 8 {
		return "••••"
	}
	return plain[:3] + "…" + plain[len(plain)-4:]
}

func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

func CheckPassword(hash, pw string) bool {
	if hash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}
