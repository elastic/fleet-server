// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package es

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/http"
	"runtime"
	"syscall"
	"time"

	"go.elastic.co/apm/module/apmelasticsearch/v2"

	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/rs/zerolog"

	backoff "github.com/cenkalti/backoff/v7"
	"github.com/elastic/elastic-transport-go/v8/elastictransport"
	"github.com/elastic/go-elasticsearch/v8"
)

const (
	initialRetryBackoff = 500 * time.Millisecond
	maxRetryBackoff     = 10 * time.Second
	randomizationFactor = 0.5

	opTypeCreate = "create"
)

// ConfigOption configures the Elasticsearch client built by NewClient.
// Obtain values using the With* functions in this package.
type ConfigOption struct {
	esOpts        []elasticsearch.Option
	rtWrap        func(http.RoundTripper) http.RoundTripper
	retryPred     func(*http.Request, error) bool // OR-composed with defaults in NewClient
	retryStatuses []int                           // unioned with defaults in NewClient
	userAgent     string                          // if set, overrides User-Agent in the request header
}

// defaultRetryStatuses is the baseline set of HTTP status codes that trigger a retry.
var defaultRetryStatuses = []int{
	http.StatusTooManyRequests,
	http.StatusRequestTimeout,
	http.StatusTooEarly,
	http.StatusBadGateway,
	http.StatusServiceUnavailable,
	http.StatusGatewayTimeout,
}

func newESOption(opt elasticsearch.Option) ConfigOption {
	return ConfigOption{esOpts: []elasticsearch.Option{opt}}
}

// NewConfigOption wraps one or more elasticsearch.Option values as a ConfigOption.
// Prefer the typed With* helpers in this package; use this only when you need
// to pass a raw elasticsearch option that has no helper (e.g. in tests).
func NewConfigOption(opts ...elasticsearch.Option) ConfigOption {
	return ConfigOption{esOpts: opts}
}

// defaultRetryOnError is the baseline retry predicate: retry on connection
// refused/reset (server may be restarting) and TLS handshake failures (the
// latter matters when multiple ES hosts chain to different CAs — a single bad
// host should not abort the request when another live host is available).
// Timeouts are retried only for document creates (see shouldRetryTimeoutForCreate).
func defaultRetryOnError(req *http.Request, err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		isTLSHandshakeError(err) ||
		shouldRetryTimeoutForCreate(req, err)
}

// exponentialBackoffDelay computes a jittered exponential back-off delay from
// the attempt counter alone (attempt starts at 1), so it carries no shared
// mutable state and is safe for concurrent use across in-flight requests. The
// result is clamped to the representable time.Duration range, mirroring
// backoff.ExponentialBackOff's overflow handling.
func exponentialBackoffDelay(attempt int, initial, maxInterval time.Duration, multiplier, randomization float64) time.Duration {
	interval := float64(initial)
	for i := 1; i < attempt; i++ {
		interval *= multiplier
		if interval > float64(maxInterval) {
			interval = float64(maxInterval)
			break
		}
	}
	delta := randomization * interval
	d := interval - delta + rand.Float64()*2*delta //nolint:gosec // non-cryptographic jitter
	switch {
	case d != d || d <= 0: // NaN or non-positive
		return 0
	case d >= math.MaxInt64:
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(d)
}

// exponentialBackoffFromAttempt is the default retry backoff schedule.
func exponentialBackoffFromAttempt(attempt int) time.Duration {
	return exponentialBackoffDelay(attempt, initialRetryBackoff, maxRetryBackoff, backoff.DefaultMultiplier, randomizationFactor)
}

func defaultOptions(disableRetry bool, retryPred func(*http.Request, error) bool, retryStatuses []int, maxRetries int) []elasticsearch.Option {
	if disableRetry {
		return []elasticsearch.Option{
			elasticsearch.WithTransportOptions(elastictransport.WithDisableRetry()),
		}
	}

	return []elasticsearch.Option{
		elasticsearch.WithTransportOptions(
			elastictransport.WithRetryOnError(retryPred),
			elastictransport.WithRetryOnStatus(retryStatuses...),
			elastictransport.WithRetryBackoff(exponentialBackoffFromAttempt),
			elastictransport.WithMaxRetries(maxRetries),
		),
	}
}

func NewClient(ctx context.Context, cfg *config.Config, longPoll bool, opts ...ConfigOption) (*elasticsearch.Client, error) {
	tCfg, err := cfg.Output.Elasticsearch.ToESTransportConfig(longPoll)
	if err != nil {
		return nil, err
	}
	addr := cfg.Output.Elasticsearch.Hosts
	mcph := cfg.Output.Elasticsearch.MaxConnPerHost

	// Apply any transport wrappers (e.g. APM instrumentation) in order.
	// Collect caller retry predicates (OR-composed) and extra statuses (unioned).
	var rt http.RoundTripper = tCfg.Transport
	combinedPred := defaultRetryOnError
	seenStatuses := make(map[int]struct{}, len(defaultRetryStatuses))
	retryStatuses := make([]int, len(defaultRetryStatuses))
	copy(retryStatuses, defaultRetryStatuses)
	for _, s := range defaultRetryStatuses {
		seenStatuses[s] = struct{}{}
	}
	var callerESopts []elasticsearch.Option
	for _, opt := range opts {
		if opt.rtWrap != nil {
			rt = opt.rtWrap(rt)
		}
		if opt.retryPred != nil {
			prev, p := combinedPred, opt.retryPred
			combinedPred = func(r *http.Request, err error) bool {
				return prev(r, err) || p(r, err)
			}
		}
		for _, s := range opt.retryStatuses {
			if _, ok := seenStatuses[s]; !ok {
				seenStatuses[s] = struct{}{}
				retryStatuses = append(retryStatuses, s)
			}
		}
		// WithUserAgent overwrites any operator-configured User-Agent header so
		// fleet-server's identity is always present, matching the old Config API.
		if opt.userAgent != "" {
			tCfg.Header.Set("User-Agent", opt.userAgent)
		}
		callerESopts = append(callerESopts, opt.esOpts...)
	}

	// Build base client options from the resolved transport config.
	baseOpts := []elasticsearch.Option{
		elasticsearch.WithAddresses(tCfg.Addresses...),
		elasticsearch.WithTransportOptions(
			elastictransport.WithTransport(rt),
			elastictransport.WithHeader(tCfg.Header),
		),
	}
	if tCfg.ServiceToken != "" {
		baseOpts = append(baseOpts, elasticsearch.WithServiceToken(tCfg.ServiceToken))
	}

	zlog := zerolog.Ctx(ctx).With().
		Strs("cluster.addr", addr).
		Int("cluster.maxConnsPersHost", mcph).
		Logger()

	zlog.Debug().Msg("init es")

	allOpts := append(append(baseOpts, defaultOptions(tCfg.DisableRetry, combinedPred, retryStatuses, tCfg.MaxRetries)...), callerESopts...)
	es, err := elasticsearch.New(allOpts...)
	if err != nil {
		zlog.Error().Err(err).Msg("fail elasticsearch init")
		return nil, err
	}

	return es, nil
}

// WithUserAgent sets the User-Agent header that fleet-server sends to
// Elasticsearch. It overwrites any User-Agent value the operator may have set
// in output.elasticsearch.headers, matching the behaviour of the old
// Config-based API where this helper called config.Header.Set directly.
func WithUserAgent(name string, bi build.Info) ConfigOption {
	return ConfigOption{userAgent: userAgent(name, bi)}
}

// InstrumentRoundTripper wraps the underlying HTTP transport with APM tracing.
// Apply this option when APM instrumentation is enabled.
func InstrumentRoundTripper() ConfigOption {
	return ConfigOption{
		rtWrap: func(rt http.RoundTripper) http.RoundTripper {
			return apmelasticsearch.WrapRoundTripper(rt)
		},
	}
}

// WithRetryOnErrs adds extra error values to the retry predicate. The default
// predicate (ECONNREFUSED, ECONNRESET, TLS handshake errors) is always active;
// this option only widens it — it never replaces the defaults.
func WithRetryOnErrs(errs ...error) ConfigOption {
	return ConfigOption{
		retryPred: func(_ *http.Request, err error) bool {
			for _, e := range errs {
				if errors.Is(err, e) {
					return true
				}
			}
			return false
		},
	}
}

// WithRetryOnTLSHandshakeError enables retries on TLS handshake failures such
// as certificate verification errors ("x509: certificate signed by unknown
// authority", expired certs, hostname mismatches, etc.).
//
// TLS handshake errors are already included in the default retry predicate, so
// this option is a no-op when used with NewClient. It is kept for call sites
// that build clients independently and want to be explicit about TLS retries.
func WithRetryOnTLSHandshakeError() ConfigOption {
	return ConfigOption{
		retryPred: func(_ *http.Request, err error) bool {
			return isTLSHandshakeError(err)
		},
	}
}

// isTLSHandshakeError reports whether err originated from a TLS certificate
// verification failure. These errors are surfaced by crypto/tls as
// *tls.CertificateVerificationError and are typically wrapped in a *url.Error
// and/or *net.OpError by the HTTP transport, so the check walks the unwrap
// chain via errors.As.
func isTLSHandshakeError(err error) bool {
	var certErr *tls.CertificateVerificationError
	return errors.As(err, &certErr)
}

// shouldRetryTimeoutForCreate reports whether err is a timeout on a document
// create request (PUT <index>/_doc/<id>?op_type=create).
//
// A timed-out request has an unknown outcome: Elasticsearch may still commit
// the write after the client gives up. A create with a fixed _id is safe to
// retry because a second attempt returns 409 if the first one landed, which
// callers can treat as success. Other request types are not necessarily
// idempotent and are never retried on timeout.
func shouldRetryTimeoutForCreate(req *http.Request, err error) bool {
	if req == nil || req.Method != http.MethodPut || req.URL.Query().Get("op_type") != opTypeCreate {
		return false
	}
	// A done request context means the caller gave up or its deadline passed,
	// so another attempt cannot succeed.
	if req.Context().Err() != nil {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func WithMaxRetries(retries int) ConfigOption {
	return newESOption(elasticsearch.WithTransportOptions(
		elastictransport.WithMaxRetries(retries),
	))
}

// WithRetryOnStatus adds a single HTTP status code to the retry set. The six
// default statuses (429, 408, 425, 502, 503, 504) are always retained; this
// option only widens the set — it never replaces the defaults.
func WithRetryOnStatus(status int) ConfigOption {
	return ConfigOption{retryStatuses: []int{status}}
}

func WithBackoff(cfg *backoff.ExponentialBackOff) ConfigOption {
	if cfg == nil {
		return newESOption(elasticsearch.WithTransportOptions(
			elastictransport.WithRetryBackoff(nil),
		))
	}
	// Copy scalar fields from cfg so the closure captures only immutable values.
	// This avoids sharing cfg's mutable interval state across concurrent requests,
	// which would cause a data race (ExponentialBackOff is not thread-safe).
	initialInterval := cfg.InitialInterval
	maxInterval := cfg.MaxInterval
	multiplier := cfg.Multiplier
	randomFactor := cfg.RandomizationFactor
	return newESOption(elasticsearch.WithTransportOptions(
		elastictransport.WithRetryBackoff(func(attempt int) time.Duration {
			return exponentialBackoffDelay(attempt, initialInterval, maxInterval, multiplier, randomFactor)
		}),
	))
}

func userAgent(name string, bi build.Info) string {
	return fmt.Sprintf("Elastic-%s/%s (%s; %s; %s; %s)",
		name,
		bi.Version, runtime.GOOS, runtime.GOARCH,
		bi.Commit, bi.BuildTime)
}
