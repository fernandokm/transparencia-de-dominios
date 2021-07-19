package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func generateAndSavePrivateKey(pemfile string) (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("error generating ECDSA private key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("error marshalling ECDSA private key: %w", err)
	}
	p := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	})
	if err = ioutil.WriteFile(pemfile, p, os.ModePerm); err != nil {
		return nil, fmt.Errorf("error saving ECDSA private key: %w", err)
	}
	log.Printf("Created new ECDSA private key: saved to %q\n", pemfile)
	return key, nil
}

func loadOrGeneratePrivateKey(pemfile string) (*ecdsa.PrivateKey, error) {
	pemdata, err := os.ReadFile(pemfile)
	if os.IsNotExist(err) {
		return generateAndSavePrivateKey(pemfile)
	} else if err != nil {
		return nil, fmt.Errorf("error reading PEM file (%q): %w", pemfile, err)
	}
	p, rest := pem.Decode(pemdata)
	if p == nil {
		return nil, fmt.Errorf("invalid PEM file %q", pemfile)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("extra data at end of PEM file %q: %q", pemfile, rest)
	}

	return x509.ParseECPrivateKey(p.Bytes)
}

func savePublicKey(pubKey *ecdsa.PublicKey, pemfile string) error {
	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("error marshalling ECDSA public key: %w", err)
	}
	p := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
	if err = ioutil.WriteFile(pemfile, p, os.ModePerm); err != nil {
		return fmt.Errorf("error saving ECDSA public key: %w", err)
	}
	log.Printf("Saved public ECDSA key to %q\n", pemfile)
	return nil
}

func loadOrGenerateKeys(privatePEMFile, publicPEMFile string) (*ecdsa.PrivateKey, error) {
	privKey, err := loadOrGeneratePrivateKey(privatePEMFile)
	if err != nil {
		return nil, err
	} else if _, err := os.Stat(publicPEMFile); os.IsNotExist(err) {
		return privKey, savePublicKey(&privKey.PublicKey, publicPEMFile)
	}
	return privKey, nil
}
