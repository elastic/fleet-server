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

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	libsconfig "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/go-ucfg/yaml"
	"github.com/stretchr/testify/require"

	fbuild "github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/checkin"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor/mock"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
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

	verCon := mustBuildConstraints("8.0.0")
	c, err := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
	require.NoError(t, err)
	bulker := ftesting.NewMockBulk()
	pim := mock.NewMockMonitor()
	pm := policy.NewMonitor(bulker, pim, config.ServerLimits{PolicyLimit: config.Limit{Interval: 5 * time.Millisecond, Burst: 1}})
	bc := checkin.NewBulk(nil)
	ct := NewCheckinT(verCon, cfg, c, bc, pm, nil, nil, nil, nil)
	et, err := NewEnrollerT(verCon, cfg, nil, c)
	require.NoError(t, err)

	srv := NewServer(addr, cfg, ct, et, nil, nil, nil, nil, fbuild.Info{}, nil, nil, nil, nil, nil)
	errCh := make(chan error)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		if err := srv.Run(ctx); err != nil {
			errCh <- err
		}
		wg.Done()
	}()
	var errFromChan error
	select {
	case err := <-errCh:
		errFromChan = err
	case <-time.After(500 * time.Millisecond):
		break
	}
	cancel()
	wg.Wait()
	require.NoError(t, errFromChan)
	if !errors.Is(err, http.ErrServerClosed) {
		require.NoError(t, err)
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

		st := NewStatusT(cfg, nil, nil)
		srv := NewServer(addr, cfg, nil, nil, nil, nil, st, sm, fbuild.Info{}, nil, nil, nil, nil, nil)
		errCh := make(chan error)

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
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			started <- struct{}{}
			if err := srv.Run(ctx); err != nil {
				errCh <- err
			}
			wg.Done()
		}()

		<-started
		rCtx, rCancel := context.WithTimeout(ctx, time.Second)
		defer rCancel()
		req, err := http.NewRequestWithContext(rCtx, "GET", "https://"+addr+"/api/status", nil)
		require.NoError(t, err)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		select {
		case err := <-errCh:
			require.NoError(t, err)
		default:
		}
		cancel()
		wg.Wait()
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

		st := NewStatusT(cfg, nil, nil)
		srv := NewServer(addr, cfg, nil, nil, nil, nil, st, sm, fbuild.Info{}, nil, nil, nil, nil, nil)
		errCh := make(chan error)

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
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			started <- struct{}{}
			if err := srv.Run(ctx); err != nil {
				errCh <- err
			}
			wg.Done()
		}()

		<-started
		rCtx, rCancel := context.WithTimeout(ctx, time.Second)
		defer rCancel()
		req, err := http.NewRequestWithContext(rCtx, "GET", "https://"+addr+"/api/status", nil)
		require.NoError(t, err)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		select {
		case err := <-errCh:
			require.NoError(t, err)
		default:
		}
		cancel()
		wg.Wait()
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

		st := NewStatusT(cfg, nil, nil)
		srv := NewServer(addr, cfg, nil, nil, nil, nil, st, sm, fbuild.Info{}, nil, nil, nil, nil, nil)
		errCh := make(chan error)

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
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			started <- struct{}{}
			if err := srv.Run(ctx); err != nil {
				errCh <- err
			}
			wg.Done()
		}()

		<-started
		rCtx, rCancel := context.WithTimeout(ctx, time.Second)
		defer rCancel()
		req, err := http.NewRequestWithContext(rCtx, "GET", "https://"+addr+"/api/status", nil)
		require.NoError(t, err)
		_, err = httpClient.Do(req)
		require.Error(t, err)

		select {
		case err := <-errCh:
			require.NoError(t, err)
		default:
		}
		cancel()
		wg.Wait()
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

		st := NewStatusT(cfg, nil, nil)
		srv := NewServer(addr, cfg, nil, nil, nil, nil, st, sm, fbuild.Info{}, nil, nil, nil, nil, nil)
		errCh := make(chan error)

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

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			if err := srv.Run(ctx); err != nil {
				errCh <- err
			}
			wg.Done()
		}()

		rCtx, rCancel := context.WithTimeout(ctx, time.Second)
		defer rCancel()
		req, err := http.NewRequestWithContext(rCtx, "GET", "https://"+addr+"/api/status", nil)
		require.NoError(t, err)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		select {
		case err := <-errCh:
			require.NoError(t, err)
		default:
		}
		cancel()
		wg.Wait()
	})
}
