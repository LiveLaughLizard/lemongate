// Package secret encrypts values at rest (upstream API keys, webhook URLs, client secrets)
// with AES-256-GCM using a key derived from LEMONGATE_SECRET_KEY.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

type Box struct{ aead cipher.AEAD }

func New(passphrase string) (*Box, error) {
	key := sha256.Sum256([]byte("lemongate/secret/v1:" + passphrase))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

func (b *Box) Seal(plain []byte) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, plain, nil), nil
}

func (b *Box) Open(sealed []byte) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("secret: ciphertext too short")
	}
	return b.aead.Open(nil, sealed[:n], sealed[n:], nil)
}

func (b *Box) SealString(s string) ([]byte, error) { return b.Seal([]byte(s)) }

func (b *Box) OpenString(sealed []byte) (string, error) {
	p, err := b.Open(sealed)
	return string(p), err
}

// Hint renders a short non-reversible preview of a secret, e.g. "sk-…a1b2".
func Hint(s string) string {
	if len(s) <= 8 {
		return "••••"
	}
	return s[:3] + "…" + s[len(s)-4:]
}
