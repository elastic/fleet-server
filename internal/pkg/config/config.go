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
	"github.com/elastic/go-ucfg"
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
	Fleet  Fleet   `config:"fleet"`
	Output Output  `config:"output"`
	Inputs []Input `config:"inputs"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *Config) InitDefaults() {
	c.Inputs = make([]Input, 1)
	c.Inputs[0].InitDefaults()
}

// Validate ensures that the configuration is valid.
func (c *Config) Validate() error {
	if c.Inputs == nil || len(c.Inputs) == 0 {
		return fmt.Errorf("a fleet-server input can be defined")
	}
	if len(c.Inputs) > 1 {
		return fmt.Errorf("only 1 fleet-server input can be defined")
	}
	return nil
}

// LoadFile take a path and load the file and return a new configuration.
func LoadFile(path string) (*Config, error) {
	cfg := &Config{}
	c, err := yaml.NewConfigWithFile(path, DefaultOptions...)
	if err != nil {
		return nil, err
	}
	err = c.Unpack(cfg, DefaultOptions...)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}
