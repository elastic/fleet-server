// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"errors"

	"github.com/elastic/go-ucfg"
	"github.com/elastic/go-ucfg/flag"
	"github.com/elastic/go-ucfg/yaml"
)

// DefaultOptions defaults options used to read the configuration
var DefaultOptions = []ucfg.Option{
	ucfg.PathSep("."),
	ucfg.ResolveEnv,
	ucfg.VarExp,
	ucfg.FieldReplaceValues("inputs"),
}

// Config is the global configuration.
type Config struct {
	Fleet   Fleet   `config:"fleet"`
	Output  Output  `config:"output"`
	Inputs  []Input `config:"inputs"`
	Logging Logging `config:"logging"`
	HTTP    HTTP    `config:"http"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *Config) InitDefaults() {
	c.Inputs = make([]Input, 1)
	c.Inputs[0].InitDefaults()
	c.HTTP.InitDefaults()
}

// Validate ensures that the configuration is valid.
func (c *Config) Validate() error {
	if len(c.Inputs) == 0 {
		return errors.New("a fleet-server input must be defined")
	}
	if len(c.Inputs) > 1 {
		return errors.New("only 1 fleet-server input can be defined")
	}
	return nil
}

// Merge merges two configurations together.
func (c *Config) Merge(other *Config) (*Config, error) {
	repr, err := ucfg.NewFrom(c, DefaultOptions...)
	if err != nil {
		return nil, err
	}
	err = repr.Merge(other, DefaultOptions...)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	err = repr.Unpack(cfg, DefaultOptions...)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

<<<<<<< HEAD
=======
func RedactOutput(cfg *Config) Output {
	redacted := cfg.Output

	if redacted.Elasticsearch.ServiceToken != "" {
		redacted.Elasticsearch.ServiceToken = kRedacted
	}

	if redacted.Elasticsearch.TLS != nil {
		newTLS := *redacted.Elasticsearch.TLS

		if newTLS.Certificate.Key != "" {
			newTLS.Certificate.Key = kRedacted
		}
		if newTLS.Certificate.Passphrase != "" {
			newTLS.Certificate.Passphrase = kRedacted
		}

		redacted.Elasticsearch.TLS = &newTLS
	}

	if redacted.Elasticsearch.Headers != nil {
		redacted.Elasticsearch.Headers = redactHeaders(redacted.Elasticsearch.Headers)
	}

	if redacted.Elasticsearch.ProxyHeaders != nil {
		redacted.Elasticsearch.ProxyHeaders = redactHeaders(redacted.Elasticsearch.ProxyHeaders)
	}
	return redacted
}

// redactHeaders returns a copy of the passed headers map.
// It will do a best-effort attempt to redact sensitive headers based on header names.
func redactHeaders(headers map[string]string) map[string]string {
	redactedHeaders := make(map[string]string)
	for k, v := range headers {
		redactedHeaders[k] = v
		lk := strings.ToLower(k)
		if strings.Contains(lk, "auth") || strings.Contains(lk, "token") || strings.Contains(lk, "key") || strings.Contains(lk, "bearer") {
			redactedHeaders[k] = kRedacted
		}
	}
	return redactedHeaders
}

func redactServer(cfg *Config) Server {
	redacted := cfg.Inputs[0].Server

	if redacted.TLS != nil {
		newTLS := *redacted.TLS

		if newTLS.Certificate.Key != "" {
			newTLS.Certificate.Key = kRedacted
		}
		if newTLS.Certificate.Passphrase != "" {
			newTLS.Certificate.Passphrase = kRedacted
		}

		redacted.TLS = &newTLS
	}

	if redacted.Instrumentation.APIKey != "" {
		redacted.Instrumentation.APIKey = kRedacted
	}

	if redacted.Instrumentation.SecretToken != "" {
		redacted.Instrumentation.SecretToken = kRedacted
	}

	if redacted.StaticPolicyTokens.PolicyTokens != nil {
		policyTokens := make([]PolicyToken, len(redacted.StaticPolicyTokens.PolicyTokens))
		for i := range redacted.StaticPolicyTokens.PolicyTokens {
			policyTokens[i] = PolicyToken{
				TokenKey: kRedacted,
				PolicyID: redacted.StaticPolicyTokens.PolicyTokens[i].PolicyID,
			}
		}
		redacted.StaticPolicyTokens.PolicyTokens = policyTokens
	}

	return redacted
}

// Redact returns a copy of the config with all sensitive attributes redacted.
func (c *Config) Redact() *Config {
	redacted := &Config{
		Fleet:   c.Fleet,
		Output:  c.Output,
		Inputs:  make([]Input, 1),
		Logging: c.Logging,
		HTTP:    c.HTTP,
	}
	redacted.Inputs[0].Server = redactServer(c)
	redacted.Output = RedactOutput(c)
	return redacted
}

func checkDeprecatedOptions(deprecatedOpts map[string]string, c *ucfg.Config) {
	for opt, message := range deprecatedOpts {
		if c.HasField(opt) {
			zerolog.Ctx(context.TODO()).Warn().Msg(message) // TODO is used as this may be called before logger config is read.
		}
	}
}

>>>>>>> f023602 (Redact output log lines during bootstrap config (#4775))
// FromConfig returns Config from the ucfg.Config.
func FromConfig(c *ucfg.Config) (*Config, error) {
	cfg := &Config{}
	err := c.Unpack(cfg, DefaultOptions...)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadFile take a path and load the file and return a new configuration.
func LoadFile(path string) (*Config, error) {
	c, err := yaml.NewConfigWithFile(path, DefaultOptions...)
	if err != nil {
		return nil, err
	}
	return FromConfig(c)
}

// Flag captures key/values pairs into an ucfg.Config object.
type Flag flag.FlagValue

// NewFlag creates an instance that allows the `-E` flag to overwrite
// the configuration from the command-line.
func NewFlag() *Flag {
	opts := append(
		[]ucfg.Option{
			ucfg.MetaData(ucfg.Meta{Source: "command line flag"}),
		},
		DefaultOptions...,
	)

	tmp := flag.NewFlagKeyValue(ucfg.New(), true, opts...)
	return (*Flag)(tmp)
}

func (f *Flag) access() *flag.FlagValue {
	return (*flag.FlagValue)(f)
}

// Config returns the config object the Flag stores applied settings to.
func (f *Flag) Config() *ucfg.Config {
	return f.access().Config()
}

// Set sets a settings value in the Config object.  The input string must be a
// key-value pair like `key=value`. If the value is missing, the value is set
// to the boolean value `true`.
func (f *Flag) Set(s string) error {
	return f.access().Set(s)
}

// Get returns the Config object used to store values.
func (f *Flag) Get() interface{} {
	return f.Config()
}

// String always returns an empty string. It is required to fulfil
// the flag.Value interface.
func (f *Flag) String() string {
	return ""
}

// Type reports the type of contents (setting=value) expected to be parsed by Set.
// It is used to build the CLI usage string.
func (f *Flag) Type() string {
	return "setting=value"
}
