package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	cRand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"flag"
	"math/big"
	"math/rand"
	"time"

	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/fernandokm/transparencia-de-dominios/util"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

var (
	cmd      = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	runPart1 = cmd.Bool("part1", false, "Run part 1 of the demo")
	runPart2 = cmd.Bool("part2", false, "Run part 2 of the demo")
)

func getClient(logName string) *client.LogClient {
	logs := util.GetLogList().FindLogByName(logName)
	if len(logs) == 0 {
		panic(fmt.Errorf("getClient: invalid log name: %s", logName))
	} else if len(logs) > 1 {
		panic(fmt.Errorf("getClient: ambiguous log name: %s", logName))
	}
	c, err := client.New(logs[0].URL, http.DefaultClient, jsonclient.Options{PublicKeyDER: logs[0].Key})
	if err != nil {
		panic(fmt.Errorf("getClient: error creating client for log %q: %w", logName, err))
	}
	return c
}

func loadCACertificateAndKey() (*x509.Certificate, crypto.Signer) {
	// Load certificate
	pemBytes, err := os.ReadFile("ct_config/ca_cert.pem")
	if err != nil {
		panic(fmt.Errorf("loadCACertificateAndKey: io error: %w", err))
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		panic(fmt.Errorf("loadCACertificateAndKey: pem file has invalid contents"))
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(fmt.Errorf("loadCACertificateAndKey: certificate error: %w", err))
	}

	// Load key
	pemBytes, err = os.ReadFile("ct_config/ca_priv.pem")
	if err != nil {
		panic(fmt.Errorf("loadCACertificateAndKey: io error: %w", err))
	}

	block, _ = pem.Decode(pemBytes)
	if block == nil {
		panic(fmt.Errorf("loadCACertificateAndKey: pem file has invalid contents"))
	}

	var pk crypto.PrivateKey
	switch strings.ToUpper(block.Type) {
	case "EC PRIVATE KEY":
		pk, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		pk, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		pk, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		panic(fmt.Errorf("loadCACertificateAndKey: pem file (%s block) has invalid contents: %w", block.Type, err))
	}

	switch pk := pk.(type) {
	case *rsa.PrivateKey:
		return cert, pk
	case *ecdsa.PrivateKey:
		return cert, pk
	case ed25519.PrivateKey:
		return cert, pk
	default:
		panic(fmt.Errorf("loadCACertificateAndKey: unsupported key type: %T", pk))
	}
}

func generateCertificate(domain string, caCert *x509.Certificate, caPriv crypto.Signer) []ct.ASN1Cert {
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber:       big.NewInt(rand.Int63()),
		Subject:            pkix.Name{CommonName: domain},
		NotBefore:          now,
		NotAfter:           now.Add(365 * 24 * time.Hour),
		SignatureAlgorithm: x509.SHA256WithRSA,

		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		IsCA:     false,
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), cRand.Reader)
	if err != nil {
		panic(fmt.Errorf("generateCertificate: error generating certificate key: %w", err))
	}

	signedCert, err := x509.CreateCertificate(cRand.Reader, cert, caCert, &priv.PublicKey, caPriv)
	if err != nil {
		panic(fmt.Errorf("generateCertificate: error generating certificate: %w", err))
	}

	return []ct.ASN1Cert{
		{Data: signedCert},
		{Data: caCert.Raw},
	}
}

func main() {
	cmd.Parse(os.Args[1:])
	if !*runPart1 && !*runPart2 {
		fmt.Println("Exactly one of --part1 and --part2 must be specified.")
		fmt.Println()
		cmd.Usage()
		return
	}
	if *runPart1 && *runPart2 {
		fmt.Println("Exactly one of --part1 and --part2 must be specified.")
		fmt.Println()
		cmd.Usage()
		return
	}

	var logs []*client.LogClient
	var logNames []string
	if *runPart1 {
		logs = append(logs, getClient("demo-log1"))
		logNames = append(logNames, "demo-log1")
	} else if *runPart2 {
		logs = append(logs, getClient("demo-log1"))
		logs = append(logs, getClient("demo-log2"))
		logNames = append(logNames, "demo-log1")
		logNames = append(logNames, "demo-log2")
	}

	caCert, caPriv := loadCACertificateAndKey()

	domains := []string{
		"example-1.com", "example-2.com", "example-3.com",
		"example-4.com", "example-5.com", "example-6.com",
		"example-7.com", "example-8.com", "example-9.com"}
	i := 0
	for {
		for j, log := range logs {
			chain := generateCertificate(domains[i], caCert, caPriv)
			_, err := log.AddChain(context.Background(), chain)
			if err != nil {
				fmt.Printf("Error adding certificate to %s: %v\n", logNames[j], err)
			} else {
				fp := sha256.Sum256(chain[0].Data)
				fmt.Printf("Added certificate for %q to %s  (sha256 fingerprint: %x...)\n", domains[i], logNames[j], fp[:4])
			}
			i = (i + 1) % len(domains)
			time.Sleep(400 * time.Millisecond)
		}
	}

}
