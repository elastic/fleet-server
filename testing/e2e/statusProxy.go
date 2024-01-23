// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build e2e

package e2e

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
)

type statusProxy struct {
	t       testing.TB
	enabled *atomic.Bool
	status  int
}

// Create a new Status Proxy
// If the proxy is enabled, the passed status is returned for all requiests
// If it's disabled requests are made to upstream instead.
func NewStatusProxy(t testing.TB, status int) *statusProxy {
	t.Helper()
	s := &statusProxy{
		t:       t,
		enabled: new(atomic.Bool),
		status:  status,
	}
	return s
}

func (s *statusProxy) Enable() {
	s.enabled.Store(true)
}

func (s *statusProxy) Disable() {
	s.enabled.Store(false)
}

func (s *statusProxy) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	if s.enabled.Load() {
		wr.WriteHeader(s.status)
		return
	}
	req.RequestURI = ""

	if cIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		req.Header.Set("X-Forwarded-For", cIP)
	}

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		s.t.Fatal(err)
		return
	}
	defer resp.Body.Close()
	for name, values := range resp.Header {
		for _, value := range values {
			wr.Header().Add(name, value)
		}
	}
	wr.WriteHeader(resp.StatusCode)
	io.Copy(wr, resp.Body)
}
