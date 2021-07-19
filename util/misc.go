package util

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"

	ct "github.com/google/certificate-transparency-go"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// RandomBase64String creates a random base64 string of the specified length.
func RandomBase64String(length int) string {
	bs := make([]byte, 4)
	var builder strings.Builder
	for builder.Len() < length {
		rand.Read(bs)
		builder.WriteString(base64.StdEncoding.EncodeToString(bs))
	}
	return builder.String()[:length]
}

// NormalizeDomainName puts a domain name in normalized form
func NormalizeDomainName(rawName string) (string, error) {
	name, err := idna.ToASCII(rawName)
	if err != nil {
		return "", err
	}
	name = strings.ToLower(name)
	name, err = publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return "", err
	}
	return name, nil
}

// HashBytes returns the sha256 hash of the given bytes
func HashBytes(bs ...[]byte) []byte {
	h := sha256.New()
	for _, b := range bs {
		h.Write(b)
	}
	return h.Sum(nil)
}

// HashBytesFixed returns the sha256 hash of the given bytes in a fixed size array
func HashBytesFixed(bs ...[]byte) ct.SHA256Hash {
	h := sha256.New()
	for _, b := range bs {
		h.Write(b)
	}
	var result ct.SHA256Hash
	h.Sum(result[:0])
	return result
}
