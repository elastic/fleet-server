// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	libsconfig "github.com/elastic/beats/v7/pkg/config"
	"github.com/elastic/beats/v7/pkg/transport/tlscommon"
	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/go-ucfg/yaml"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger/ecs"
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

// Test_server_RouteMonitoring makes sure that the route metrics and the request
// log match the requests that the server receives.
func Test_server_RouteMonitoring(t *testing.T) {
	routes := map[string]struct {
		path  string
		stats *routeStats
	}{
		"status": {
			path:  "/api/status",
			stats: &cntStatus,
		},
		"OpAMP": {
			path:  "/v1/opamp",
			stats: &cntOpAMP,
		},
	}

	tests := []struct {
		name           string
		route          string
		opAMPEnabled   bool
		rateLimited    bool
		wantCode       int
		wantRejections uint64
	}{{
		name:         "a status request is counted and logged",
		route:        "status",
		opAMPEnabled: true,
		wantCode:     http.StatusOK,
	}, {
		name:         "a status request is counted and logged when OpAMP is disabled",
		route:        "status",
		opAMPEnabled: false,
		wantCode:     http.StatusOK,
	}, {
		name:         "an OpAMP request is counted and logged",
		route:        "OpAMP",
		opAMPEnabled: true,
		wantCode:     http.StatusOK,
	}, {
		name:         "an OpAMP request is counted and logged when OpAMP is disabled",
		route:        "OpAMP",
		opAMPEnabled: false,
		wantCode:     http.StatusNotFound,
	}, {
		name:           "a status request that the rate limit rejects is counted as a rejection and logged",
		route:          "status",
		opAMPEnabled:   true,
		rateLimited:    true,
		wantCode:       http.StatusTooManyRequests,
		wantRejections: 1,
	}, {
		name:           "an OpAMP request that the rate limit rejects is counted as a rejection and logged",
		route:          "OpAMP",
		opAMPEnabled:   true,
		rateLimited:    true,
		wantCode:       http.StatusTooManyRequests,
		wantRejections: 1,
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sm := mock.NewMockMonitor()
			sm.On("State").Return(client.UnitStateHealthy)

			cfg := &config.Server{}
			cfg.InitDefaults()
			cfg.Features.EnableOpAMP = tc.opAMPEnabled
			cfg.Limits.MaxConnections = 10
			if tc.rateLimited {
				rejectAll := config.Limit{Interval: time.Hour}
				cfg.Limits.StatusLimit = rejectAll
				cfg.Limits.OpAMPLimit = rejectAll
			}

			st := NewStatusT(cfg, nil, nil, WithSelfMonitor(sm))
			oa := &OpAMPT{
				cfg: cfg,
				handler: func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				},
			}
			srv := NewServer("", cfg, WithStatus(st), WithOpAMP(oa))

			route := routes[tc.route]
			var logs bytes.Buffer
			ctx := zerolog.New(&logs).Level(zerolog.DebugLevel).WithContext(t.Context())
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, route.path, nil)
			rec := httptest.NewRecorder()

			total := route.stats.total.metric.Get()
			rejections := route.stats.rateLimit.metric.Get()
			srv.handler.ServeHTTP(rec, req)

			require.Equal(t, tc.wantCode, rec.Code)

			requestID := rec.Header().Get(logger.HeaderRequestID)
			assert.NotEmpty(t, requestID)

			requestLog := logs.String()
			loggedCode := fmt.Sprintf(`"%s":%d`, ecs.HTTPResponseCode, tc.wantCode)
			assert.Contains(t, requestLog, loggedCode)

			count := route.stats.total.metric.Get() - total
			assert.Equal(t, uint64(1), count, "route total")

			rejectionCount := route.stats.rateLimit.metric.Get() - rejections
			assert.Equal(t, tc.wantRejections, rejectionCount, "rate limit rejections")
		})
	}
}
