package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func loadPublicKey(pemfile string) (*ecdsa.PublicKey, error) {
	pemdata, err := os.ReadFile(pemfile)
	if err != nil {
		return nil, fmt.Errorf("error reading PEM file (%q): %w", pemfile, err)
	}
	p, rest := pem.Decode(pemdata)
	if p == nil {
		return nil, fmt.Errorf("invalid PEM file %q", pemfile)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("extra data at end of PEM file %q: %q", pemfile, rest)
	}

	pubKey, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		return nil, err
	}
	return pubKey.(*ecdsa.PublicKey), nil
}
