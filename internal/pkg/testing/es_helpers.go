// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package testing

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// VerifyAPIKeyInvalidated polls Elasticsearch until the given API key reports the
// expected `invalidated` state. esURL must include scheme and credentials, e.g.
// "http://elastic:changeme@localhost:9200" or "https://elastic:changeme@localhost:9201".
//
// TLS certificate verification is skipped so the helper works with self-signed
// certificates (as used by the integration elasticsearch-remote container).
func VerifyAPIKeyInvalidated(t *testing.T, ctx context.Context, esURL, apiKeyID string, invalidated bool) {
	t.Helper()
	tr := &http.Transport{
		// #nosec G402
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cli := &http.Client{Transport: tr}
	requestURL := fmt.Sprintf("%s/_security/api_key?id=%s", esURL, apiKeyID)

	Retry(t, ctx, func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
		if err != nil {
			return fmt.Errorf("creating request for api key %s: %w", apiKeyID, err)
		}
		res, err := cli.Do(req)
		if err != nil {
			return fmt.Errorf("querying api key %s: %w", apiKeyID, err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("api key %s: unexpected status %d", apiKeyID, res.StatusCode)
		}
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf("reading api key %s response: %w", apiKeyID, err)
		}
		want := fmt.Sprintf(`"invalidated":%t`, invalidated)
		if !strings.Contains(string(body), want) {
			return fmt.Errorf("api key %s: want %s in response; got %s", apiKeyID, want, body)
		}
		return nil
	}, RetrySleep(2*time.Second), RetryCount(10))
}

// LocalESURL returns the local Elasticsearch base URL with embedded credentials.
// It reads ELASTICSEARCH_HOSTS (comma-separated), takes the first entry, strips any
// existing scheme, and prepends "http://elastic:changeme@". Defaults to localhost:9200.
func LocalESURL() string {
	hosts := os.Getenv("ELASTICSEARCH_HOSTS")
	if hosts == "" {
		return "http://elastic:changeme@localhost:9200"
	}
	raw := strings.SplitN(hosts, ",", 2)[0]
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// bare host:port with no scheme
		u = &url.URL{Host: raw}
	}
	u.Scheme = "http"
	u.User = url.UserPassword("elastic", "changeme")
	return u.String()
}
