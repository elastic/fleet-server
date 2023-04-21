// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/elastic/elastic-agent-libs/transport/tlscommon"

	apmtransport "go.elastic.co/apm/v2/transport"
)

// Instrumentation configures APM Tracing for the `fleet-server`.
type Instrumentation struct {
	Enabled bool               `config:"enabled"`
	TLS     InstrumentationTLS `config:"tls"`
	// Environment specifies the environment name - may be specified with ELASTIC_APM_ENVIRONMENT
	Environment string `config:"environment"`
	// APIKey specifies the API key value - may be specified with ELASTIC_APM_API_KEY
	APIKey string `config:"api_key"`
	// APIKeyPath specifies the path to the API key secret file
	APIKeyPath string `config:"api_key_path"`
	// SecretToken specifies the secret token value - may be specified with ELASTIC_APM_SECRET_TOKEN
	SecretToken string `config:"secret_token"`
	// SecretTokenPath specifies the path to the secret token file
	SecretTokenPath string `config:"secret_token_path"`
	// Hosts specifies the APM server urls - may be specified with ELASTIC_APM_SERVER_URL
	Hosts []string `config:"hosts"`
	// GlobalLabels specifies apm global labels - may be specified with ELASTIC_APM_GLOBAL_LABELS
	GlobalLabels string `config:"global_labels"`
	// TransactionSampleRate sets the sample rate  - may be specified with ELASTIC_APM_TRANSACTION_SAMPLE_RATE
	TransactionSampleRate string `config:"transaction_sample_rate"`
}

type InstrumentationTLS struct {
	// APM certificate validation skip - may be specified with ELASTIC_APM_VERIFY_SERVER_CERT
	SkipVerify bool `config:"skip_verify"`
	// APM server certificate path - may be specified with ELASTIC_APM_SERVER_CERT
	ServerCertificate string `config:"server_certificate"`
	// APM server CA path - may be specified with ELASTIC_APM_SERVER_CA_CERT_FILE
	ServerCA string `config:"server_ca"`
}

// APMHTTPTransportOptions will return an APM HTTP transport options configuration specifier.
func (c *Instrumentation) APMHTTPTransportOptions() (apmtransport.HTTPTransportOptions, error) {
	hosts := make([]*url.URL, 0, len(c.Hosts))
	for _, host := range c.Hosts {
		u, err := url.Parse(host)
		if err != nil {
			return apmtransport.HTTPTransportOptions{}, fmt.Errorf("failed parsing %s: %w", host, err)
		}
		hosts = append(hosts, u)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.TLS.SkipVerify, //nolint:gosec // users can disable tls validation
	}

	if c.TLS.ServerCertificate != "" {
		p, err := os.ReadFile(c.TLS.ServerCertificate)
		if err != nil {
			return apmtransport.HTTPTransportOptions{}, fmt.Errorf("unable to read instrumentation certificate: %w", err)
		}
		block, _ := pem.Decode(p)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return apmtransport.HTTPTransportOptions{}, fmt.Errorf("unable to parse instrumentation certificate: %w", err)
		}
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return verifyPeerCertificate(rawCerts, cert)
		}
	}

	if c.TLS.ServerCA != "" {
		pool, errs := tlscommon.LoadCertificateAuthorities([]string{c.TLS.ServerCA})
		// FIXME once we update elastic-agent-libs to go 1.20 we can return multiple errors directly with errors.Join()
		if len(errs) != 0 {
			return apmtransport.HTTPTransportOptions{}, fmt.Errorf("unable to load instrumentation cas: %w", errors.Join(errs...))
		}
		tlsConfig.RootCAs = pool
	}

	apiKey := c.APIKey
	if c.APIKey == "" && c.APIKeyPath != "" {
		p, err := os.ReadFile(c.APIKeyPath)
		if err != nil {
			return apmtransport.HTTPTransportOptions{}, fmt.Errorf("unable to read API key file: %w", err)
		}
		apiKey = string(p)
	}

	secretToken := c.SecretToken
	if c.SecretToken == "" && c.SecretTokenPath != "" {
		p, err := os.ReadFile(c.SecretTokenPath)
		if err != nil {
			return apmtransport.HTTPTransportOptions{}, fmt.Errorf("unable to read secret token file: %w", err)
		}
		secretToken = string(p)
	}

	return apmtransport.HTTPTransportOptions{
		APIKey:          apiKey,
		SecretToken:     secretToken,
		ServerURLs:      hosts,
		TLSClientConfig: tlsConfig,
	}, nil
}

// verifyPeerCertificate copied from elastic/apm-agent-go/transport/http.go with the following alterations:
// - replaced use of pkg/errors with fmt
func verifyPeerCertificate(rawCerts [][]byte, trusted *x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("missing leaf certificate")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate from server: %w", err)
	}
	if !cert.Equal(trusted) {
		return fmt.Errorf("failed to verify server certificate")
	}
	return nil
}
