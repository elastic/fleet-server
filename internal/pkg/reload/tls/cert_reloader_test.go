// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tls

import (
	"bytes"
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
	// Generate a valid CA and leaf certificate pair.
	ca := certs.GenCA(t)
	cert := certs.GenCert(t, ca)

	// Write the cert and key to disk.
	dir := t.TempDir()
	certPath, keyPath := writeCertAndKey(t, dir, cert)

	// Creating a new CertReloader should succeed and load the cert.
	r, err := New(certPath, keyPath, 0)
	require.NoError(t, err)

	// The loaded cert should match the one we wrote to disk.
	got, err := r.GetCertificate(nil)
	require.NoError(t, err)
	assert.NotNil(t, got)
	assert.Equal(t, cert.Certificate[0], got.Certificate[0])
}

func TestNew_InvalidCertPair(t *testing.T) {
	// Generate two different certs from the same CA.
	ca := certs.GenCA(t)
	cert1 := certs.GenCert(t, ca)
	cert2 := certs.GenCert(t, ca)

	dir := t.TempDir()

	// Write the certificate from cert1 but the private key from cert2.
	// This creates a mismatched pair that should fail validation.
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

	// New() should fail because the cert and key don't match.
	_, err = New(certPath, keyPath, 0)
	assert.Error(t, err)
}

func TestNew_MissingFiles(t *testing.T) {
	// Attempting to create a reloader with paths that don't exist should fail
	// on the initial certificate load.
	_, err := New("/nonexistent/cert.pem", "/nonexistent/key.pem", 0)
	assert.Error(t, err)
}

func TestNew_EmptyPaths(t *testing.T) {
	// Empty paths should be rejected before attempting any file I/O.
	_, err := New("", "", 0)
	assert.Error(t, err)
}

func TestReload_CertChange(t *testing.T) {
	ca := certs.GenCA(t)
	cert1 := certs.GenCert(t, ca)

	dir := t.TempDir()
	certPath, keyPath := writeCertAndKey(t, dir, cert1)

	// Use a short debounce (100ms) to keep the test fast.
	r, err := New(certPath, keyPath, 100*time.Millisecond)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	ctx = testlog.SetLogger(t).WithContext(ctx)
	defer cancel()

	// Start the file watcher in the background.
	go func() {
		_ = r.Run(ctx)
	}()

	// Verify the initial cert is served.
	got, err := r.GetCertificate(nil)
	require.NoError(t, err)
	assert.Equal(t, cert1.Certificate[0], got.Certificate[0])

	// Overwrite both cert and key files with a new certificate.
	cert2 := certs.GenCert(t, ca)
	writeCertAndKey(t, dir, cert2)

	// After the debounce, GetCertificate should return the new cert.
	require.Eventually(t, func() bool {
		got, err := r.GetCertificate(nil)
		return err == nil && bytes.Equal(got.Certificate[0], cert2.Certificate[0])
	}, 2*time.Second, 50*time.Millisecond, "cert should have been reloaded")
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

	// Overwrite the cert file with invalid data. The reloader should detect
	// the change, attempt to load the new pair, fail validation, and keep
	// serving the original cert.
	require.NoError(t, os.WriteFile(certPath, []byte("not a cert"), 0o600))

	// The original cert should remain served for the entire debounce window
	// and beyond, since the new cert is invalid and should be rejected.
	require.Never(t, func() bool {
		got, err := r.GetCertificate(nil)
		if err != nil {
			return true
		}
		return !bytes.Equal(got.Certificate[0], cert1.Certificate[0])
	}, 500*time.Millisecond, 50*time.Millisecond, "cert should not have changed after invalid reload")
}

func TestReload_Debounce(t *testing.T) {
	ca := certs.GenCA(t)
	cert1 := certs.GenCert(t, ca)

	dir := t.TempDir()
	certPath, keyPath := writeCertAndKey(t, dir, cert1)

	// Use a 200ms debounce so we can test the timer reset behavior.
	r, err := New(certPath, keyPath, 200*time.Millisecond)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	ctx = testlog.SetLogger(t).WithContext(ctx)
	defer cancel()

	go func() {
		_ = r.Run(ctx)
	}()

	cert2 := certs.GenCert(t, ca)

	// T=0ms: Write only the cert file. This starts the 200ms debounce timer.
	certOut, err := os.Create(certPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert2.Certificate[0]}))
	require.NoError(t, certOut.Close())

	// T=80ms: Write the key file. This should reset the debounce timer back
	// to 200ms, so the reload won't happen until ~T=280ms.
	time.Sleep(80 * time.Millisecond)
	keyBytes, err := x509.MarshalPKCS8PrivateKey(cert2.PrivateKey)
	require.NoError(t, err)
	keyOut, err := os.Create(keyPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
	require.NoError(t, keyOut.Close())

	// For 100ms after the key write, the cert should NOT have reloaded yet
	// because we're still within the 200ms debounce window.
	require.Never(t, func() bool {
		got, _ := r.GetCertificate(nil)
		return bytes.Equal(got.Certificate[0], cert2.Certificate[0])
	}, 100*time.Millisecond, 10*time.Millisecond, "cert should not have reloaded yet")

	// After the debounce window expires, the new cert should be loaded.
	require.Eventually(t, func() bool {
		got, err := r.GetCertificate(nil)
		return err == nil && bytes.Equal(got.Certificate[0], cert2.Certificate[0])
	}, 2*time.Second, 50*time.Millisecond, "cert should have reloaded after debounce")
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

	// Start the watcher and immediately cancel the context.
	// Run should exit cleanly with no error.
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx)
	}()

	cancel()

	// Verify Run exits promptly (within 2s) and returns nil.
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
