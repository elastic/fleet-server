// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	urlutil "github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/go-elasticsearch/v8"
)

// The timeout would be driven by the server for long poll.
// Giving it some sane long value.
const httpTransportLongPollTimeout = 10 * time.Minute
const schemeHTTP = "http"

const (
	DefaultElasticsearchHost             = "localhost:9200"
	DefaultElasticsearchTimeout          = 90 * time.Second
	DefaultElasticsearchMaxRetries       = 3
	DefaultElasticsearchMaxConnPerHost   = 128
	DefaultElasticsearchMaxContentLength = 100 * 1024 * 1024
)

var hasScheme = regexp.MustCompile(`^([a-z][a-z0-9+\-.]*)://`)

// Output is the output configuration to elasticsearch.
type Output struct {
	Elasticsearch Elasticsearch          `config:"elasticsearch"`
	Extra         map[string]interface{} `config:",inline"`
}

// Elasticsearch is the configuration for elasticsearch.
type Elasticsearch struct {
	Protocol         string            `config:"protocol"`
	Hosts            []string          `config:"hosts"`
	Path             string            `config:"path"`
	Headers          map[string]string `config:"headers"`
	ServiceToken     string            `config:"service_token"`
	ServiceTokenPath string            `config:"service_token_path"`
	ProxyURL         string            `config:"proxy_url"`
	ProxyDisable     bool              `config:"proxy_disable"`
	ProxyHeaders     map[string]string `config:"proxy_headers"`
	TLS              *tlscommon.Config `config:"ssl"`
	MaxRetries       int               `config:"max_retries"`
	MaxConnPerHost   int               `config:"max_conn_per_host"`
	Timeout          time.Duration     `config:"timeout"`
	MaxContentLength int               `config:"max_content_length"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *Elasticsearch) InitDefaults() {
	c.Protocol = schemeHTTP
	c.Hosts = []string{DefaultElasticsearchHost}
	c.Timeout = DefaultElasticsearchTimeout
	c.MaxRetries = DefaultElasticsearchMaxRetries
	c.MaxConnPerHost = DefaultElasticsearchMaxConnPerHost
	c.MaxContentLength = DefaultElasticsearchMaxContentLength
}

// Validate ensures that the configuration is valid.
func (c *Elasticsearch) Validate() error {
	if c.ProxyURL != "" && !c.ProxyDisable {
		if _, err := urlutil.ParseURL(c.ProxyURL); err != nil {
			return err
		}
	}
	if c.TLS != nil && c.TLS.IsEnabled() {
		_, err := tlscommon.LoadTLSConfig(c.TLS)
		if err != nil {
			return err
		}
	}
	return nil
}

// ToESConfig converts the configuration object into the config for the elasticsearch client.
func (c *Elasticsearch) ToESConfig(longPoll bool) (elasticsearch.Config, error) {
	// build the addresses
	addrs := make([]string, len(c.Hosts))
	for i, host := range c.Hosts {
		addr, err := makeURL(c.Protocol, c.Path, host, 9200)
		if err != nil {
			return elasticsearch.Config{}, err
		}
		addrs[i] = addr
	}

	// build the transport from the config
	httpTransport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		DisableKeepAlives:     false,
		DisableCompression:    false,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   32,
		MaxConnsPerHost:       c.MaxConnPerHost,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: c.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	disableRetry := false

	if longPoll {
		httpTransport.IdleConnTimeout = httpTransportLongPollTimeout
		httpTransport.ResponseHeaderTimeout = httpTransportLongPollTimeout

		// no retries for long poll monitoring
		disableRetry = true
	}

	if c.TLS != nil && c.TLS.IsEnabled() {
		tls, err := tlscommon.LoadTLSConfig(c.TLS)
		if err != nil {
			return elasticsearch.Config{}, err
		}
		httpTransport.TLSClientConfig = tls.ToConfig()
	}

	if !c.ProxyDisable {
		if c.ProxyURL != "" {
			proxyURL, err := urlutil.ParseURL(c.ProxyURL)
			if err != nil {
				return elasticsearch.Config{}, err
			}
			httpTransport.Proxy = http.ProxyURL(proxyURL)
		} else {
			httpTransport.Proxy = http.ProxyFromEnvironment
		}

		var proxyHeaders http.Header
		if len(c.ProxyHeaders) > 0 {
			proxyHeaders = make(http.Header, len(c.ProxyHeaders))
			for k, v := range c.ProxyHeaders {
				proxyHeaders.Add(k, v)
			}
		}
		httpTransport.ProxyConnectHeader = proxyHeaders
	}

	h := http.Header{}
	for key, val := range c.Headers {
		h.Set(key, val)
	}

	// Set special header "X-elastic-product-origin" for .fleet-* indices based on the latest conversation with ES team
	// This eliminates the warning while accessing the system index
	h.Set("X-elastic-product-origin", "fleet")

	serviceToken := c.ServiceToken
	if c.ServiceToken == "" && c.ServiceTokenPath != "" {
		p, err := os.ReadFile(c.ServiceTokenPath)
		if err != nil {
			return elasticsearch.Config{}, fmt.Errorf("unable to read service_token_path: %w", err)
		}
		serviceToken = string(p)
	}

	return elasticsearch.Config{
		Addresses:    addrs,
		ServiceToken: serviceToken,
		Header:       h,
		Transport:    httpTransport,
		MaxRetries:   c.MaxRetries,
		DisableRetry: disableRetry,
	}, nil
}

// MergeElasticsearchPolicy will merge elasticsearch settings retrieved from the fleet-server's policy into the base configuration and return the resulting config.
// ucfg.Merge and config.Config.Merge will both fail at merging configs because the verification mode is not detect as a string type value
func MergeElasticsearchFromPolicy(cfg, pol Elasticsearch) Elasticsearch {
	res := Elasticsearch{
		Protocol:         cfg.Protocol,
		Hosts:            cfg.Hosts,
		Headers:          cfg.Headers,
		ServiceToken:     cfg.ServiceToken, // ServiceToken will always be specified from the settings and not in the policy.
		ServiceTokenPath: cfg.ServiceTokenPath,
		ProxyURL:         cfg.ProxyURL,
		ProxyDisable:     cfg.ProxyDisable,
		ProxyHeaders:     cfg.ProxyHeaders,
		TLS:              mergeElasticsearchTLS(cfg.TLS, pol.TLS), // tls can be a special case
		MaxRetries:       cfg.MaxRetries,
		MaxConnPerHost:   cfg.MaxConnPerHost,
		Timeout:          cfg.Timeout,
		MaxContentLength: cfg.MaxContentLength,
	}
	// If policy has a non-default Hosts value use it's values for Protocol and hosts
	if pol.Hosts != nil && !(len(pol.Hosts) == 1 && pol.Hosts[0] == DefaultElasticsearchHost) {
		res.Protocol = pol.Protocol
		res.Hosts = pol.Hosts
	}
	if pol.Headers != nil {
		res.Headers = pol.Headers
	}
	// If the policy ProxyURL is set, use all of the policy's Proxy values.
	if pol.ProxyURL != "" {
		res.ProxyURL = pol.ProxyURL
		res.ProxyDisable = pol.ProxyDisable
		res.ProxyHeaders = pol.ProxyHeaders
	}
	if pol.MaxRetries != DefaultElasticsearchMaxRetries {
		res.MaxRetries = pol.MaxRetries
	}
	if pol.MaxConnPerHost != DefaultElasticsearchMaxConnPerHost {
		res.MaxConnPerHost = pol.MaxConnPerHost
	}
	if pol.Timeout != DefaultElasticsearchTimeout {
		res.Timeout = pol.Timeout
	}
	if pol.MaxContentLength != DefaultElasticsearchMaxContentLength {
		res.MaxContentLength = pol.MaxContentLength
	}
	return res
}

// mergeElasticsearchTLS merges the TLS settings received from the fleet-server's policy into the settings the agent passes
func mergeElasticsearchTLS(cfg, pol *tlscommon.Config) *tlscommon.Config {
	if cfg == nil && pol == nil {
		return nil
	} else if cfg == nil && pol != nil {
		return pol
	} else if cfg != nil && pol == nil {
		return cfg
	}
	res := &tlscommon.Config{
		Enabled:              cfg.Enabled,
		VerificationMode:     cfg.VerificationMode,
		Versions:             cfg.Versions,
		CipherSuites:         cfg.CipherSuites,
		CAs:                  cfg.CAs,
		Certificate:          cfg.Certificate,
		CurveTypes:           cfg.CurveTypes,
		Renegotiation:        cfg.Renegotiation,
		CASha256:             cfg.CASha256,
		CATrustedFingerprint: cfg.CATrustedFingerprint,
	}
	if pol.Enabled != nil {
		res.Enabled = pol.Enabled
	}
	if pol.VerificationMode != tlscommon.VerifyFull {
		res.VerificationMode = pol.VerificationMode // VerificationMode defaults to VerifyFull
	}
	if pol.Versions != nil {
		res.Versions = pol.Versions
	}
	if pol.CipherSuites != nil {
		res.CipherSuites = pol.CipherSuites
	}
	if pol.CAs != nil {
		res.CAs = pol.CAs
	}
	if pol.Certificate.Certificate != "" {
		res.Certificate = pol.Certificate
	}
	if pol.CurveTypes != nil {
		res.CurveTypes = pol.CurveTypes
	}
	if pol.Renegotiation != tlscommon.TLSRenegotiationSupport(tls.RenegotiateNever) {
		res.Renegotiation = pol.Renegotiation
	}
	if pol.CASha256 != nil {
		res.CASha256 = pol.CASha256
	}
	if pol.CATrustedFingerprint != "" {
		res.CATrustedFingerprint = pol.CATrustedFingerprint
	}

	return res
}

// Validate validates that only elasticsearch is defined on the output.
func (c *Output) Validate() error {
	if c.Extra == nil {
		return nil
	}
	_, ok := c.Extra["elasticsearch"]
	if (!ok && len(c.Extra) > 0) || (ok && len(c.Extra) > 1) {
		return fmt.Errorf("can only contain elasticsearch key")
	}
	// clear Extra because its valid (only used for validation)
	c.Extra = nil
	return nil
}

func makeURL(defaultScheme string, defaultPath string, rawURL string, defaultPort int) (string, error) {
	if defaultScheme == "" {
		defaultScheme = schemeHTTP
	}
	if !hasScheme.MatchString(rawURL) {
		rawURL = fmt.Sprintf("%v://%v", defaultScheme, rawURL)
	}
	addr, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	scheme := addr.Scheme
	host := addr.Host
	port := strconv.Itoa(defaultPort)

	if host == "" {
		host = "localhost"
	} else {
		// split host and optional port
		if splitHost, splitPort, err := net.SplitHostPort(host); err == nil {
			host = splitHost
			port = splitPort
		}

		// Check if ipv6
		if strings.Count(host, ":") > 1 && strings.Count(host, "]") == 0 {
			host = "[" + host + "]"
		}
	}

	// Assign default path if not set
	if addr.Path == "" {
		addr.Path = defaultPath
	}

	// reconstruct url
	addr.Scheme = scheme
	addr.Host = host + ":" + port
	return addr.String(), nil
}
