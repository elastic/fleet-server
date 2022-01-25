// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration
// +build integration

package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/sleep"
	"github.com/elastic/fleet-server/v7/internal/pkg/status"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

const (
	serverVersion = "1.0.0"

	testWaitServerUp = 3 * time.Second
)

type tserver struct {
	cfg *config.Config
	g   *errgroup.Group
	srv *FleetServer
}

func (s *tserver) baseUrl() string {
	input, _ := s.cfg.GetFleetInput()
	tls := input.Server.TLS
	schema := "http"
	if tls != nil && tls.IsEnabled() {
		schema = "https"
	}
	return fmt.Sprintf("%s://%s:%d", schema, input.Server.Host, input.Server.Port)
}

func (s *tserver) waitExit() error {
	return s.g.Wait()
}

func startTestServer(ctx context.Context) (*tserver, error) {
	cfg, err := config.LoadFile("../../fleet-server.yml")
	if err != nil {
		return nil, err
	}

	logger.Init(cfg, "fleet-server")

	port, err := ftesting.FreePort()
	if err != nil {
		return nil, err
	}

	srvcfg := &config.Server{}
	srvcfg.InitDefaults()
	srvcfg.Host = "localhost"
	srvcfg.Port = port
	cfg.Inputs[0].Server = *srvcfg
	log.Info().Uint16("port", port).Msg("Test fleet server")

	srv, err := NewFleetServer(cfg, build.Info{Version: serverVersion}, status.NewLog())
	if err != nil {
		return nil, err
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return srv.Run(ctx)
	})

	tsrv := &tserver{cfg: cfg, g: g, srv: srv}
	err = tsrv.waitServerUp(ctx, testWaitServerUp)
	if err != nil {
		return nil, err
	}
	return tsrv, nil
}

func (s *tserver) waitServerUp(ctx context.Context, dur time.Duration) error {
	start := time.Now()
	cli := cleanhttp.DefaultClient()
	for {
		res, err := cli.Get(s.baseUrl() + "/api/status")
		if err != nil {
			if time.Since(start) > dur {
				return err
			}
		} else {
			defer res.Body.Close()
			return nil
		}

		err = sleep.WithContext(ctx, 100*time.Millisecond)
		if err != nil {
			return err
		}
	}

}

func (s *tserver) buildUrl(id string, cmd string) string {
	ur := "/api/fleet/agents"
	if id != "" {
		ur = path.Join(ur, id)
	}
	if cmd != "" {
		ur = path.Join(ur, cmd)
	}

	return s.baseUrl() + ur
}

func TestServerUnauthorized(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start test server
	srv, err := startTestServer(ctx)
	require.NoError(t, err)

	agentId := uuid.Must(uuid.NewV4()).String()
	cli := cleanhttp.DefaultClient()

	agenturls := []string{
		srv.buildUrl(agentId, "checkin"),
		srv.buildUrl(agentId, "acks"),
	}

	allurls := []string{
		srv.buildUrl("", "enroll"),
	}
	allurls = append(allurls, agenturls...)

	// Expecting no authorization header error
	// Not sure if this is right response, just capturing what we have so far
	// TODO: revisit error response format
	t.Run("no auth header", func(t *testing.T) {
		for _, u := range allurls {
			res, err := cli.Post(u, "application/json", bytes.NewBuffer([]byte("{}")))
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			diff := cmp.Diff(400, res.StatusCode)
			if diff != "" {
				t.Fatal(diff)
			}

			raw, _ := ioutil.ReadAll(res.Body)
			var resp errResp
			err = json.Unmarshal(raw, &resp)
			if err != nil {
				t.Fatal(err)
			}
			diff = cmp.Diff(400, resp.StatusCode)
			if diff != "" {
				t.Fatal(diff)
			}
			diff = cmp.Diff("BadRequest", resp.Error)
			if diff != "" {
				t.Fatal(diff)
			}
		}
	})

	// Unauthorized, expecting error from /_security/_authenticate
	t.Run("unauthorized", func(t *testing.T) {

		for _, u := range agenturls {
			req, err := http.NewRequest("POST", u, bytes.NewBuffer([]byte("{}")))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "ApiKey ZExqY1hYWUJJUVVxWDVia2JvVGM6M05XaUt5aHBRYk9YSTRQWDg4YWp0UQ==")
			res, err := cli.Do(req)

			require.NoError(t, err)
			defer res.Body.Close()

			diff := cmp.Diff(400, res.StatusCode)
			if diff != "" {
				t.Fatal(diff)
			}

			raw, _ := ioutil.ReadAll(res.Body)
			var resp errResp
			err = json.Unmarshal(raw, &resp)
			if err != nil {
				t.Fatal(err)
			}
			diff = cmp.Diff(400, resp.StatusCode)
			if diff != "" {
				t.Fatal(diff)
			}
			diff = cmp.Diff("BadRequest", resp.Error)
			if diff != "" {
				t.Fatal(diff)
			}
		}
	})

	// Stop test server
	cancel()
	srv.waitExit()
}

func TestServerInstrumentation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tracerConnected := make(chan struct{}, 1)
	tracerDisconnected := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/intake/v2/events" {
			return
		}
		tracerConnected <- struct{}{}
		io.Copy(io.Discard, req.Body)
		tracerDisconnected <- struct{}{}
	}))
	defer server.Close()

	// Start test server
	srv, err := startTestServer(ctx)
	require.NoError(t, err)

	newInstrumentationCfg := func(cfg config.Config, instr config.Instrumentation) {
		cfg.Inputs[0] = cfg.Inputs[0]
		cfg.Inputs[0].Server.Instrumentation = instr

		newCfg, err := srv.cfg.Merge(&cfg)
		require.NoError(t, err)

		require.NoError(t, srv.srv.Reload(ctx, newCfg))
	}

	// Enable instrumentation
	newInstrumentationCfg(*srv.cfg, config.Instrumentation{
		Enabled: true,
		Hosts:   []string{server.URL},
	})

	stopClient := make(chan struct{})
	cli := cleanhttp.DefaultClient()
	callCheckinFunc := func() {
		for {
			agentId := "1e4954ce-af37-4731-9f4a-407b08e69e42"
			cli.Post(srv.buildUrl(agentId, "checkin"), "application/json", bytes.NewBuffer([]byte("{}")))
			require.NoError(t, err)
			select {
			case <-ctx.Done():
				return
			case <-stopClient:
				return
			case <-time.After(time.Second):
			}
		}
	}
	go callCheckinFunc()

	// Verify the APM tracer connects to the mocked APM Server.
	// Errors if the tracer doesn't establish a connection within 5 seconds.
	select {
	case <-tracerConnected:
		stopClient <- struct{}{}
	case <-time.After(5 * time.Second):
		t.Error("did not receive any data from the instrumented fleet-server")
	}

	// Turn instrumentation off
	newInstrumentationCfg(*srv.cfg, config.Instrumentation{
		Enabled: false,
		Hosts:   []string{server.URL},
	})

	// Verify the APM Tracer closes the connection to the mocked APM Server.
	// Errors if the hasn't closed the connection after 5 seconds.
	select {
	case <-tracerDisconnected:
	case <-time.After(5 * time.Second):
		t.Error("APM tracer still connected after server restart, bug in the tracing code")
	}

	go callCheckinFunc()

	// Verify the APM Tracer doesn't connect to the mocked APM Server.
	select {
	case <-tracerConnected:
		t.Error("APM Tracer connected to APM Server, bug in the tracing code")
	case <-time.After(5 * time.Second):
	}

	stopClient <- struct{}{}
	close(stopClient)
	cancel()
	require.NoError(t, srv.waitExit())
}
