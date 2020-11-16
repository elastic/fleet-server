// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package config

import (
	"fmt"
	"time"

	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/common/transport/kerberos"
	"github.com/elastic/beats/v7/libbeat/common/transport/tlscommon"
)

// ElasticsearchBackoff is the backoff configuration for Elasticsearch.
type ElasticsearchBackoff struct {
	Init time.Duration
	Max  time.Duration
}

// Elasticsearch is the configuration for elasticsearch.
type Elasticsearch struct {
	Protocol         string               `config:"protocol"`
	Hosts            []string             `config:"hosts"`
	Path             string               `config:"path"`
	Params           map[string]string    `config:"parameters"`
	Headers          map[string]string    `config:"headers"`
	Username         string               `config:"username"`
	Password         string               `config:"password"`
	APIKey           string               `config:"api_key"`
	ProxyURL         string               `config:"proxy_url"`
	ProxyDisable     bool                 `config:"proxy_disable"`
	LoadBalance      bool                 `config:"loadbalance"`
	CompressionLevel int                  `config:"compression_level" validate:"min=0, max=9"`
	EscapeHTML       bool                 `config:"escape_html"`
	TLS              *tlscommon.Config    `config:"ssl"`
	Kerberos         *kerberos.Config     `config:"kerberos"`
	BulkMaxSize      int                  `config:"bulk_max_size"`
	MaxRetries       int                  `config:"max_retries"`
	Timeout          time.Duration        `config:"timeout"`
	Backoff          ElasticsearchBackoff `config:"backoff"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *Elasticsearch) InitDefaults() {
	c.Protocol = "http"
	c.Hosts = []string{"localhost:9200"}
	c.Timeout = 90 * time.Second
	c.MaxRetries = 3
	c.LoadBalance = true
	c.Backoff = ElasticsearchBackoff{
		Init: 1 * time.Second,
		Max:  60 * time.Second,
	}
}

// Validate ensures that the configuration is valid.
func (c *Elasticsearch) Validate() error {
	if c.APIKey != "" {
		return fmt.Errorf("cannot run with api_key; must use username/password")
	}
	if c.Username == "" || c.Password == "" {
		return fmt.Errorf("cannot run without username/password")
	}
	if c.ProxyURL != "" && !c.ProxyDisable {
		if _, err := common.ParseURL(c.ProxyURL); err != nil {
			return err
		}
	}
	return nil
}
