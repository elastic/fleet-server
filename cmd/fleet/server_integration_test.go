// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build integration

package fleet

import (
	"bytes"
	"context"
	"fleet/internal/pkg/config"
	"fleet/internal/pkg/logger"
	"fleet/internal/pkg/sleep"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/google/go-cmp/cmp"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	ftesting "fleet/internal/pkg/testing"

	"github.com/hashicorp/go-cleanhttp"
)

const (
	serverVersion = "1.0.0"

	testWaitServerUp = 3 * time.Second
)

type tserver struct {
	cfg *config.Config
	g   *errgroup.Group
}

func (s *tserver) baseUrl() string {
	input := s.cfg.Inputs[0]
	tls := input.Server.TLS
	schema := "http"
	if tls.Key != "" || tls.Cert != "" {
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

	err = initGlobalCache()
	if err != nil {
		return nil, err
	}

	logger.Init(cfg)

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

	srv, err := NewFleetServer(cfg, serverVersion)
	if err != nil {
		return nil, err
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return srv.Run(ctx)
	})

	tsrv := &tserver{cfg, g}
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
		res, err := cli.Get(s.baseUrl())
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
		srv.buildUrl(agentId, "result"),
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
			diff = cmp.Diff("no authorization header\n", string(raw))
			if diff != "" {
				t.Fatal(diff)
			}
		}
	})

	// Unauthorized, expecting error from /_security/_authenticate
	t.Run("unauthorized", func(t *testing.T) {
		const expectedErrResponsePrefix = `Fail Auth: [401 Unauthorized]`
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
			if !strings.HasPrefix(string(raw), expectedErrResponsePrefix) {
				t.Fatalf("unexpected error: %s", string(raw))
			}
		}
	})

	// Stop test server
	cancel()
	srv.waitExit()
}
