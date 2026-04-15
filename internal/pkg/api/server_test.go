// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	libsconfig "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/go-ucfg/yaml"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor/mock"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/elastic/fleet-server/v7/internal/pkg/testing/certs"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

func Test_server_Run(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	port, err := ftesting.FreePort()
	require.NoError(t, err)
	cfg := &config.Server{}
	cfg.InitDefaults()
	cfg.Host = "localhost"
	cfg.Port = port
	addr := cfg.BindEndpoints()[0]

	srv := NewServer(addr, cfg)

	started := make(chan struct{}, 1)
	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Go(func() {
		started <- struct{}{}
		if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- err
		}
	})

	select { // if the goroutine has started within 500ms something is wrong, test has timed out
	case <-started:
	case <-time.After(500 * time.Millisecond):
		require.Fail(t, "timed out waiting for server to start")
	}
	select { // check if there is an error in the 1st 500ms of the server running
	case err := <-errCh:
		require.NoError(t, err, "error during startup")
	case <-time.After(500 * time.Millisecond):
		break
	}

	cancel()
	wg.Wait()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	default:
	}
}

var tlsCFGTempl = `
enabled: true
certificate_authorities: ["%s"]
certificate: "%s"
key: "%s"
client_authentication: "optional"
`

func Test_server_ClientCert(t *testing.T) {
	// prep self monitor mock for status endpoint
	sm := mock.NewMockMonitor()
	sm.On("State").Return(client.UnitStateHealthy)

	// prep server tls config
	ca := certs.GenCA(t)
	caPath := certs.CertToFile(t, ca, "ca")
	cert := certs.GenCert(t, ca)
	certPath := certs.CertToFile(t, cert, "cert")
	keyPath := certs.KeyToFile(t, cert, "key")

	tlsYML := fmt.Sprintf(tlsCFGTempl,
		caPath,
		certPath,
		keyPath,
	)
	ucfg, err := yaml.NewConfig([]byte(tlsYML))
	require.NoError(t, err)
	tlsCFG := &tlscommon.ServerConfig{}
	err = tlsCFG.Unpack(libsconfig.C(*ucfg))
	require.NoError(t, err)

	t.Run("no client certs", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ctx = testlog.SetLogger(t).WithContext(ctx)

		port, err := ftesting.FreePort()
		require.NoError(t, err)
		cfg := &config.Server{}
		cfg.InitDefaults()
		cfg.Host = "localhost"
		cfg.Port = port
		addr := cfg.BindEndpoints()[0]
		cfg.TLS = &config.ServerTLSConfig{ServerConfig: *tlsCFG}

		st := NewStatusT(cfg, nil, nil, WithSelfMonitor(sm))
		srv := NewServer(addr, cfg, WithStatus(st))

		// make http client with no client certs
		certPool := x509.NewCertPool()
		certPool.AddCert(ca.Leaf)
		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: certPool,
				},
			},
		}

		started := make(chan struct{}, 1)
		errCh := make(chan error, 1)
		var wg sync.WaitGroup
		wg.Go(func() {
			started <- struct{}{}
			if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- err
			}
		})

		select { // make sure goroutine starts within 500ms
		case <-started:
		case <-time.After(500 * time.Millisecond):
			require.Fail(t, "timed out waiting for server to start")
		}
		select { // make sure there are no errors within 500ms of api server running
		case err := <-errCh:
			require.NoError(t, err, "error during startup")
		case <-time.After(500 * time.Millisecond):
			break
		}

		rCtx, rCancel := context.WithTimeout(ctx, 5*time.Second)
		defer rCancel()
		req, err := http.NewRequestWithContext(rCtx, "GET", "https://"+addr+"/api/status", nil)
		require.NoError(t, err)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		cancel()
		wg.Wait()
		select {
		case err := <-errCh:
			require.NoError(t, err)
		default:
		}
	})

	t.Run("valid client certs", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ctx = testlog.SetLogger(t).WithContext(ctx)

		port, err := ftesting.FreePort()
		require.NoError(t, err)
		cfg := &config.Server{}
		cfg.InitDefaults()
		cfg.Host = "localhost"
		cfg.Port = port
		addr := cfg.BindEndpoints()[0]
		cfg.TLS = &config.ServerTLSConfig{ServerConfig: *tlsCFG}

		st := NewStatusT(cfg, nil, nil, WithSelfMonitor(sm))
		srv := NewServer(addr, cfg, WithStatus(st))

		// make http client with valid client certs
		clientCert := certs.GenCert(t, ca)
		certPool := x509.NewCertPool()
		certPool.AddCert(ca.Leaf)
		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:      certPool,
					Certificates: []tls.Certificate{clientCert},
				},
			},
		}

		started := make(chan struct{}, 1)
		errCh := make(chan error, 1)
		var wg sync.WaitGroup
		wg.Go(func() {
			started <- struct{}{}
			if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- err
			}
		})

		select {
		case <-started:
		case <-time.After(500 * time.Millisecond):
			require.Fail(t, "timed out waiting for server to start")
		}
		select {
		case err := <-errCh:
			require.NoError(t, err, "error during startup")
		case <-time.After(500 * time.Millisecond):
			break
		}

		rCtx, rCancel := context.WithTimeout(ctx, 5*time.Second)
		defer rCancel()
		req, err := http.NewRequestWithContext(rCtx, "GET", "https://"+addr+"/api/status", nil)
		require.NoError(t, err)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		cancel()
		wg.Wait()
		select {
		case err := <-errCh:
			require.NoError(t, err)
		default:
		}
	})

	t.Run("invalid client certs", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ctx = testlog.SetLogger(t).WithContext(ctx)

		port, err := ftesting.FreePort()
		require.NoError(t, err)
		cfg := &config.Server{}
		cfg.InitDefaults()
		cfg.Host = "localhost"
		cfg.Port = port
		addr := cfg.BindEndpoints()[0]
		cfg.TLS = &config.ServerTLSConfig{ServerConfig: *tlsCFG}

		st := NewStatusT(cfg, nil, nil, WithSelfMonitor(sm))
		srv := NewServer(addr, cfg, WithStatus(st))

		// make http client with invalid client certs
		clientCA := certs.GenCA(t)
		clientCert := certs.GenCert(t, clientCA)
		certPool := x509.NewCertPool()
		certPool.AddCert(ca.Leaf)
		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:      certPool,
					Certificates: []tls.Certificate{clientCert},
				},
			},
		}

		started := make(chan struct{}, 1)
		errCh := make(chan error, 1)
		var wg sync.WaitGroup
		wg.Go(func() {
			started <- struct{}{}
			if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- err
			}
		})

		select {
		case <-started:
		case <-time.After(500 * time.Millisecond):
			require.Fail(t, "timed out waiting for server to start")
		}
		select {
		case err := <-errCh:
			require.NoError(t, err, "error during startup")
		case <-time.After(500 * time.Millisecond):
			break
		}

		rCtx, rCancel := context.WithTimeout(ctx, 5*time.Second)
		defer rCancel()
		req, err := http.NewRequestWithContext(rCtx, "GET", "https://"+addr+"/api/status", nil)
		require.NoError(t, err)
		_, err = httpClient.Do(req)
		require.Error(t, err)

		cancel()
		wg.Wait()
		select {
		case err := <-errCh:
			require.NoError(t, err)
		default:
		}
	})

	t.Run("valid client certs no certs requested", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ctx = testlog.SetLogger(t).WithContext(ctx)

		port, err := ftesting.FreePort()
		require.NoError(t, err)
		cfg := &config.Server{}
		cfg.InitDefaults()
		cfg.Host = "localhost"
		cfg.Port = port
		addr := cfg.BindEndpoints()[0]

		// prep server config without specifing client_authentication
		tlsYML := fmt.Sprintf(`
enabled: true
certificate: "%s"
key: %s`,
			certPath, keyPath)
		ucfg, err := yaml.NewConfig([]byte(tlsYML))
		require.NoError(t, err)
		tlsCFG := &tlscommon.ServerConfig{}
		err = tlsCFG.Unpack(libsconfig.C(*ucfg))
		require.NoError(t, err)
		cfg.TLS = &config.ServerTLSConfig{ServerConfig: *tlsCFG}

		st := NewStatusT(cfg, nil, nil, WithSelfMonitor(sm))
		srv := NewServer(addr, cfg, WithStatus(st))

		// make http client with valid client certs
		clientCert := certs.GenCert(t, ca)
		certPool := x509.NewCertPool()
		certPool.AddCert(ca.Leaf)
		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:      certPool,
					Certificates: []tls.Certificate{clientCert},
				},
			},
		}

		started := make(chan struct{}, 1)
		errCh := make(chan error, 1)
		var wg sync.WaitGroup
		wg.Go(func() {
			started <- struct{}{}
			if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- err
			}
		})

		select {
		case <-started:
		case <-time.After(500 * time.Millisecond):
			require.Fail(t, "timed out waiting for server to start")
		}
		select {
		case err := <-errCh:
			require.NoError(t, err, "error during startup")
		case <-time.After(500 * time.Millisecond):
			break
		}

		rCtx, rCancel := context.WithTimeout(ctx, 5*time.Second)
		defer rCancel()
		req, err := http.NewRequestWithContext(rCtx, "GET", "https://"+addr+"/api/status", nil)
		require.NoError(t, err)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		cancel()
		wg.Wait()
		select {
		case err := <-errCh:
			require.NoError(t, err)
		default:
		}
	})
}

func Test_server_TLSCertReload(t *testing.T) {
	// This test verifies end-to-end TLS certificate hot-reload through a
	// running server: start the server with cert1, rotate to cert2 on disk,
	// and verify that new TLS connections receive cert2.

	sm := mock.NewMockMonitor()
	sm.On("State").Return(client.UnitStateHealthy)

	ca := certs.GenCA(t)
	cert1 := certs.GenCert(t, ca)

	// Write cert and key to a shared directory so we can overwrite them
	// in place to simulate certificate rotation.
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	caPath := certs.CertToFile(t, ca, "ca")

	writePEM := func(path string, pemType string, data []byte) {
		t.Helper()
		f, err := os.Create(path)
		require.NoError(t, err)
		require.NoError(t, pem.Encode(f, &pem.Block{Type: pemType, Bytes: data}))
		require.NoError(t, f.Close())
	}
	writeCertAndKey := func(cert tls.Certificate) {
		t.Helper()
		writePEM(certPath, "CERTIFICATE", cert.Certificate[0])
		keyBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
		require.NoError(t, err)
		writePEM(keyPath, "PRIVATE KEY", keyBytes)
	}

	// Write the initial certificate pair.
	writeCertAndKey(cert1)

	// Build the TLS config via YAML, same as the other TLS tests.
	tlsYML := fmt.Sprintf(tlsCFGTempl, caPath, certPath, keyPath)
	ucfg, err := yaml.NewConfig([]byte(tlsYML))
	require.NoError(t, err)
	tlsCFG := &tlscommon.ServerConfig{}
	err = tlsCFG.Unpack(libsconfig.C(*ucfg))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	// Configure the server with certificate reload enabled.
	port, err := ftesting.FreePort()
	require.NoError(t, err)
	cfg := &config.Server{}
	cfg.InitDefaults()
	cfg.Host = "localhost"
	cfg.Port = port
	addr := cfg.BindEndpoints()[0]
	cfg.TLS = &config.ServerTLSConfig{ServerConfig: *tlsCFG}
	cfg.TLS.CertificateReload.Enabled = true

	st := NewStatusT(cfg, nil, nil, WithSelfMonitor(sm))
	srv := NewServer(addr, cfg, WithStatus(st))

	// Trust the test CA for client connections.
	certPool := x509.NewCertPool()
	certPool.AddCert(ca.Leaf)

	// Start the server in a background goroutine.
	started := make(chan struct{}, 1)
	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		started <- struct{}{}
		if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- err
		}
		wg.Done()
	}()

	// Wait for the server goroutine to start and verify no startup errors.
	select {
	case <-started:
	case <-time.After(500 * time.Millisecond):
		require.Fail(t, "timed out waiting for server to start")
	}
	select {
	case err := <-errCh:
		require.NoError(t, err, "error during startup")
	case <-time.After(500 * time.Millisecond):
		break
	}

	// getServerCert makes an HTTPS request to the server and captures the raw
	// server certificate from the TLS handshake via VerifyConnection callback.
	getServerCert := func() []byte {
		t.Helper()
		var serverCert []byte
		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: certPool,
					VerifyConnection: func(cs tls.ConnectionState) error {
						if len(cs.PeerCertificates) > 0 {
							serverCert = cs.PeerCertificates[0].Raw
						}
						return nil
					},
				},
			},
		}
		rCtx, rCancel := context.WithTimeout(ctx, 5*time.Second)
		defer rCancel()
		req, err := http.NewRequestWithContext(rCtx, "GET", "https://"+addr+"/api/status", nil)
		require.NoError(t, err)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		return serverCert
	}

	// Capture the server cert before rotation.
	initialCert := getServerCert()
	require.NotEmpty(t, initialCert)

	// Simulate certificate rotation by writing a new cert/key pair to the
	// same paths. The CertReloader's fsnotify watcher should detect this.
	cert2 := certs.GenCert(t, ca)
	writeCertAndKey(cert2)

	// Wait for the debounce period (default 5s) plus a buffer for fsnotify
	// delivery and reload processing.
	time.Sleep(7 * time.Second)

	// After the reload, the server should present the new certificate.
	newCert := getServerCert()
	require.NotEmpty(t, newCert)
	assert.NotEqual(t, initialCert, newCert, "server should present the new certificate after reload")

	// Clean shutdown.
	cancel()
	wg.Wait()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	default:
	}
}
