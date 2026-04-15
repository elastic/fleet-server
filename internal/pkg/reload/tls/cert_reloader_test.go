// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/testing/certs"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

// writeCertAndKey writes a TLS certificate and key to the given directory,
// returning the file paths. Unlike certs.CertToFile/KeyToFile, this writes
// to a caller-controlled directory so files can be overwritten in place.
func writeCertAndKey(t *testing.T, dir string, cert stdtls.Certificate) (certPath, keyPath string) {
	t.Helper()

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certOut, err := os.Create(certPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	require.NoError(t, certOut.Close())

	keyBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	require.NoError(t, err)
	keyOut, err := os.Create(keyPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
	require.NoError(t, keyOut.Close())

	return certPath, keyPath
}

func TestNew_ValidCertPair(t *testing.T) {
	ca := certs.GenCA(t)
	cert := certs.GenCert(t, ca)

	dir := t.TempDir()
	certPath, keyPath := writeCertAndKey(t, dir, cert)

	r, err := New(certPath, keyPath, 0)
	require.NoError(t, err)

	got, err := r.GetCertificate(nil)
	require.NoError(t, err)
	assert.NotNil(t, got)
	assert.Equal(t, cert.Certificate[0], got.Certificate[0])
}

func TestNew_InvalidCertPair(t *testing.T) {
	ca := certs.GenCA(t)
	cert1 := certs.GenCert(t, ca)
	cert2 := certs.GenCert(t, ca)

	dir := t.TempDir()

	// Write cert from cert1 but key from cert2 (mismatched)
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	certOut, err := os.Create(certPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert1.Certificate[0]}))
	require.NoError(t, certOut.Close())

	keyBytes, err := x509.MarshalPKCS8PrivateKey(cert2.PrivateKey)
	require.NoError(t, err)
	keyOut, err := os.Create(keyPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
	require.NoError(t, keyOut.Close())

	_, err = New(certPath, keyPath, 0)
	assert.Error(t, err)
}

func TestNew_MissingFiles(t *testing.T) {
	_, err := New("/nonexistent/cert.pem", "/nonexistent/key.pem", 0)
	assert.Error(t, err)
}

func TestNew_EmptyPaths(t *testing.T) {
	_, err := New("", "", 0)
	assert.Error(t, err)
}

func TestReload_CertChange(t *testing.T) {
	ca := certs.GenCA(t)
	cert1 := certs.GenCert(t, ca)

	dir := t.TempDir()
	certPath, keyPath := writeCertAndKey(t, dir, cert1)

	r, err := New(certPath, keyPath, 100*time.Millisecond)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	ctx = testlog.SetLogger(t).WithContext(ctx)
	defer cancel()

	go func() {
		_ = r.Run(ctx)
	}()

	// Verify initial cert
	got, err := r.GetCertificate(nil)
	require.NoError(t, err)
	assert.Equal(t, cert1.Certificate[0], got.Certificate[0])

	// Generate and write a new cert
	cert2 := certs.GenCert(t, ca)
	writeCertAndKey(t, dir, cert2)

	// Wait for debounce + buffer
	time.Sleep(300 * time.Millisecond)

	// Verify new cert is served
	got, err = r.GetCertificate(nil)
	require.NoError(t, err)
	assert.Equal(t, cert2.Certificate[0], got.Certificate[0])
}

func TestReload_InvalidNewCert_KeepsOld(t *testing.T) {
	ca := certs.GenCA(t)
	cert1 := certs.GenCert(t, ca)

	dir := t.TempDir()
	certPath, keyPath := writeCertAndKey(t, dir, cert1)

	r, err := New(certPath, keyPath, 100*time.Millisecond)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	ctx = testlog.SetLogger(t).WithContext(ctx)
	defer cancel()

	go func() {
		_ = r.Run(ctx)
	}()

	// Overwrite cert with garbage
	require.NoError(t, os.WriteFile(certPath, []byte("not a cert"), 0o644))

	// Wait for debounce + buffer
	time.Sleep(300 * time.Millisecond)

	// Original cert should still be served
	got, err := r.GetCertificate(nil)
	require.NoError(t, err)
	assert.Equal(t, cert1.Certificate[0], got.Certificate[0])
}

func TestReload_Debounce(t *testing.T) {
	ca := certs.GenCA(t)
	cert1 := certs.GenCert(t, ca)

	dir := t.TempDir()
	certPath, keyPath := writeCertAndKey(t, dir, cert1)

	r, err := New(certPath, keyPath, 500*time.Millisecond)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	ctx = testlog.SetLogger(t).WithContext(ctx)
	defer cancel()

	go func() {
		_ = r.Run(ctx)
	}()

	// Generate a new cert
	cert2 := certs.GenCert(t, ca)

	// Write cert file first
	certOut, err := os.Create(certPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert2.Certificate[0]}))
	require.NoError(t, certOut.Close())

	// Wait 200ms, then write key file (resets debounce timer)
	time.Sleep(200 * time.Millisecond)
	keyBytes, err := x509.MarshalPKCS8PrivateKey(cert2.PrivateKey)
	require.NoError(t, err)
	keyOut, err := os.Create(keyPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
	require.NoError(t, keyOut.Close())

	// At 400ms total (200ms since key write), cert should NOT yet be reloaded
	time.Sleep(200 * time.Millisecond)
	got, err := r.GetCertificate(nil)
	require.NoError(t, err)
	assert.Equal(t, cert1.Certificate[0], got.Certificate[0], "cert should not have reloaded yet")

	// At 800ms total (500ms+ since key write), cert should be reloaded
	time.Sleep(400 * time.Millisecond)
	got, err = r.GetCertificate(nil)
	require.NoError(t, err)
	assert.Equal(t, cert2.Certificate[0], got.Certificate[0], "cert should have reloaded after debounce")
}

func TestRun_ContextCancellation(t *testing.T) {
	ca := certs.GenCA(t)
	cert := certs.GenCert(t, ca)

	dir := t.TempDir()
	certPath, keyPath := writeCertAndKey(t, dir, cert)

	r, err := New(certPath, keyPath, 100*time.Millisecond)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	ctx = testlog.SetLogger(t).WithContext(ctx)

	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx)
	}()

	cancel()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}

// genCertDirect generates a certificate without using testing.T helpers, for
// cases where we need more control over the certificate content (e.g., different
// serial numbers to distinguish certs).
func genCertDirect(t *testing.T, ca stdtls.Certificate, serial int64) stdtls.Certificate {
	t.Helper()

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		IPAddresses:  []net.IP{{127, 0, 0, 1}},
		DNSNames:     []string{"localhost"},
		Subject: pkix.Name{
			CommonName:   "fleet-server testing",
			Organization: []string{"TESTING"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Leaf, &key.PublicKey, ca.PrivateKey)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	return stdtls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}
