// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration
// +build !integration

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	fbuild "github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/google/go-cmp/cmp"

	"github.com/julienschmidt/httprouter"
	"github.com/stretchr/testify/require"
)

func withAuthFunc(authfn AuthFunc) OptFunc {
	return func(st *StatusT) {
		if authfn != nil {
			st.authfn = authfn
		}
	}
}

type mockPolicyMonitor struct {
	state client.UnitState
}

func (pm *mockPolicyMonitor) Run(ctx context.Context) error {
	return nil
}

func (pm *mockPolicyMonitor) State() client.UnitState {
	return pm.state
}

func TestHandleStatus(t *testing.T) {
	ctx := context.Background()

	cfg := &config.Server{}
	cfg.InitDefaults()
	c, err := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
	require.NoError(t, err)

	authfnOk := func(r *http.Request) (*apikey.APIKey, error) {
		return nil, nil
	}
	authfnFail := func(r *http.Request) (*apikey.APIKey, error) {
		return nil, apikey.ErrNoAuthHeader
	}

	tests := []struct {
		Name   string
		AuthFn AuthFunc
		Authed bool
	}{
		{
			Name:   "authenticated",
			AuthFn: authfnOk,
			Authed: true,
		},
		{
			Name:   "non authenticated",
			AuthFn: authfnFail,
		},
	}

	// Test table, with inner loop on all available statuses
	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			for k, v := range proto.State_name {
				t.Run(v, func(t *testing.T) {
					state := client.UnitState(k)
					r := Router{
						ctx: ctx,
						st:  NewStatusT(cfg, nil, c, withAuthFunc(tc.AuthFn)),
						sm:  &mockPolicyMonitor{state},
						bi: fbuild.Info{
							Version:   "8.1.0",
							Commit:    "4eff928",
							BuildTime: time.Now(),
						},
					}

					hr := httprouter.New()
					hr.Handle(http.MethodGet, RouteStatus, r.handleStatus)

					w := httptest.NewRecorder()
					req, _ := http.NewRequestWithContext(ctx, http.MethodGet, RouteStatus, nil)
					hr.ServeHTTP(w, req)

					expectedCode := http.StatusServiceUnavailable
					if state == client.UnitStateDegraded || state == client.UnitStateHealthy {
						expectedCode = http.StatusOK
					}

					if diff := cmp.Diff(w.Code, expectedCode); diff != "" {
						t.Error(diff)
					}

					var res StatusResponse
					if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
						t.Fatal(err)
					}

					if diff := cmp.Diff(res.Name, "fleet-server"); diff != "" {
						t.Error(diff)
					}

					if diff := cmp.Diff(res.Status, state.String()); diff != "" {
						t.Error(diff)
					}

					// Expect extended version information if authenticated
					if tc.Authed {
						if res.Version == nil {
							t.Fatal("expected non-nil version information")
						}

						if diff := cmp.Diff(r.bi.Version, res.Version.Number); diff != "" {
							t.Error(diff)
						}
						if diff := cmp.Diff(r.bi.Commit, res.Version.BuildHash); diff != "" {
							t.Error(diff)
						}
						if diff := cmp.Diff(r.bi.BuildTime.Format(time.RFC3339), res.Version.BuildTime); diff != "" {
							t.Error(diff)
						}
					} else {
						if res.Version != nil {
							t.Error("expected nil version information")
						}
					}
				})
			}
		})
	}
}
