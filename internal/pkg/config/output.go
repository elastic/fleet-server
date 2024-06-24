// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"bytes"
	"context"
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
	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog"
)

// The timeout would be driven by the server for long poll.
// Giving it some sane long value.
const httpTransportLongPollTimeout = 10 * time.Minute
const schemeHTTP = "http"

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
	c.Hosts = []string{"localhost:9200"}
	c.Timeout = 90 * time.Second
	c.MaxRetries = 3
	c.MaxConnPerHost = 128
	c.MaxContentLength = 100 * 1024 * 1024
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

func (c *Elasticsearch) DiagRequests(ctx context.Context) []byte {
	pURL, err := httpcommon.NewProxyURIFromString(c.ProxyURL)
	if err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).Msg("Unable to transform proxy_url to url.URL")
	}
	settings := httpcommon.HTTPTransportSettings{
		TLS:     c.TLS,
		Timeout: c.Timeout,
		Proxy: httpcommon.HTTPClientProxySettings{
			Disable: c.ProxyDisable,
			URL:     pURL,
			Headers: httpcommon.ProxyHeaders(c.ProxyHeaders),
		},
	}
	headers := http.Header{}
	for k, v := range c.Headers {
		headers.Set(k, v)
	}

	reqs := make([]*http.Request, 0, len(c.Hosts))

	var res bytes.Buffer
	for _, host := range c.Hosts {
		u, err := url.Parse(host)
		if err != nil {
			zerolog.Ctx(ctx).Warn().Err(err).Str("host", host).Msg("Unable to transform host to url.URL")
			res.WriteString(fmt.Sprintf("Unable to transform host %q to url.URL: %v\n", host, err))
			continue
		}
		if u.Scheme == "" {
			u.Scheme = c.Protocol
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			zerolog.Ctx(ctx).Warn().Err(err).Str("host", host).Msg("Unable to create request to host")
			res.WriteString(fmt.Sprintf("Unable to create request to host %q: %v\n", host, err))
			continue
		}
		req.Header = headers.Clone()
		reqs = append(reqs, req)
	}
	res.Write(settings.DiagRequests(reqs)())
	return res.Bytes()
}
