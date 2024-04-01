// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const ext = ".pem"

func CertToFile(t *testing.T, cert tls.Certificate, name string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, name+ext)
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("unable to create file: %v", err)
	}
	if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}); err != nil {
		t.Fatalf("unable to write cert: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("unable to close file: %v", err)
	}

	return path
}

func KeyToFile(t *testing.T, cert tls.Certificate, name string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, name+ext)
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("unable to create file: %v", err)
	}
	p, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatalf("unable to marshal private key: %v", err)
	}
	if err := pem.Encode(file, &pem.Block{Type: "PRIVATE KEY", Bytes: p}); err != nil {
		t.Fatalf("unable to write key: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("unable to close file: %v", err)
	}

	return path
}

// Generates expired CA for tests
func GenExpCA(t *testing.T) tls.Certificate {
	return genCA(t, true)
}

// Generates unexpired CA for tests
func GenCA(t *testing.T) tls.Certificate {
	return genCA(t, false)
}

// GenCA generates a CA for tests
// Based on elastic-agent-libs/transport/tlscommon/ca_pinning_test.go
// implementation
func genCA(t *testing.T, isExpired bool) tls.Certificate {
	t.Helper()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2000),
		Subject: pkix.Name{
			CommonName:    "localhost",
			Organization:  []string{"TESTING"},
			Country:       []string{"CANADA"},
			Province:      []string{"QUEBEC"},
			Locality:      []string{"MONTREAL"},
			StreetAddress: []string{"testing road"},
			PostalCode:    []string{"HOH OHO"},
		},
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	if isExpired {
		ca.NotBefore = time.Now().Add(-48 * time.Hour)
		ca.NotAfter = time.Now().Add(-24 * time.Hour)
	} else {
		ca.NotBefore = time.Now()
		ca.NotAfter = time.Now().Add(1 * time.Hour)
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048) // less secure key for quicker testing.
	if err != nil {
		t.Fatalf("fail to generate RSA key: %v", err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("fail to create certificate: %v", err)
	}

	leaf, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatalf("fail to parse certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{caBytes},
		PrivateKey:  caKey,
		Leaf:        leaf,
	}
}

// GenCert generates a test keypair and signs the cert with the passed CA.
// copied from elastic-agent-libs/transport/tlscommon/ca_pinning_test.go
func GenCert(t *testing.T, ca tls.Certificate) tls.Certificate {
	t.Helper()
	ts := time.Now().UTC()

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2000),

		// Subject Alternative Name fields
		IPAddresses: []net.IP{{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		DNSNames:    []string{"localhost"},

		Subject: pkix.Name{
			CommonName:    "fleet-server testing",
			Organization:  []string{"TESTING"},
			Country:       []string{"CANADA"},
			Province:      []string{"QUEBEC"},
			Locality:      []string{"MONTREAL"},
			StreetAddress: []string{"testing road"},
			PostalCode:    []string{"HOH OHO"},
		},

		NotBefore:             ts,
		NotAfter:              ts.Add(24 * time.Hour),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("fail to generate RSA key: %v", err)
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		cert,
		ca.Leaf,
		&certKey.PublicKey,
		ca.PrivateKey,
	)
	if err != nil {
		t.Fatalf("fail to create signed certificate: %v", err)
	}

	leaf, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("fail to parse the certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  certKey,
		Leaf:        leaf,
	}
}
