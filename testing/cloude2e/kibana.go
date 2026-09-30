// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build cloude2e

package cloude2e

import (
	"net/http"
	"time"

	"github.com/elastic/elastic-agent-libs/kibana"

	"github.com/elastic/fleet-server/v7/version"
)

const (
	kibanaRetryMaxWait = 10 * time.Second
	kibanaMaxRetries   = 5
)

// kibanaRetryBackoff is an exponential backoff capped at kibanaRetryMaxWait,
// mirroring the backoff elastic-agent's test clients use.
func kibanaRetryBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	// 1<<5 seconds is already past the cap; clamp the shift to avoid overflow
	// on the large attempt numbers kibanaMaxRetries allows.
	if attempt > 5 {
		return kibanaRetryMaxWait
	}
	return min((1<<(attempt-1))*time.Second, kibanaRetryMaxWait)
}

// newKibanaClient returns a Kibana client for the cloud deployment under test.
//
// The client retries transport errors and throttling/server responses itself,
// so the tests survive a blip without any retry code of their own:
// NewClientWithConfigDefault reads the Kibana version from /api/status on
// construction, and that request goes through the same retry loop as every
// later call. 401 and 403 are not retried, so a misconfigured deployment
// still fails fast.
func newKibanaClient(kibanaURL, username, password string) (*kibana.Client, error) {
	return kibana.NewClientWithConfigDefault(&kibana.ClientConfig{
		Host:          kibanaURL,
		Username:      username,
		Password:      password,
		IgnoreVersion: false,
		Retry: kibana.RetryConfig{
			MaxRetries: kibanaMaxRetries,
			RetryOnStatus: []int{
				http.StatusTooManyRequests,
				http.StatusInternalServerError,
				http.StatusBadGateway,
				http.StatusServiceUnavailable,
				http.StatusGatewayTimeout,
			},
			RetryBackoff: kibanaRetryBackoff,
		},
	}, 443, "fleet-server-cloude2e", version.DefaultVersion, "", time.Now().UTC().Format(time.RFC3339))
}
