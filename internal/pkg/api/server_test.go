// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

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
	wg.Add(1)
	go func() {
		started <- struct{}{}
		if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- err
		}
		wg.Done()
	}()

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
		cfg.TLS = tlsCFG

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
		wg.Add(1)
		go func() {
			started <- struct{}{}
			if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- err
			}
			wg.Done()
		}()

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

		rCtx, rCancel := context.WithTimeout(ctx, time.Second)
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
		cfg.TLS = tlsCFG

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
		wg.Add(1)
		go func() {
			started <- struct{}{}
			if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- err
			}
			wg.Done()
		}()

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

		rCtx, rCancel := context.WithTimeout(ctx, time.Second)
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
		cfg.TLS = tlsCFG

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
		wg.Add(1)
		go func() {
			started <- struct{}{}
			if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- err
			}
			wg.Done()
		}()

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

		rCtx, rCancel := context.WithTimeout(ctx, time.Second)
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
		cfg.TLS = tlsCFG

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
		wg.Add(1)
		go func() {
			started <- struct{}{}
			if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- err
			}
			wg.Done()
		}()

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

		rCtx, rCancel := context.WithTimeout(ctx, time.Second)
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
