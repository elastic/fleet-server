// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"bytes"
	"errors"
)

type PBKDF2 struct {
	Iterations int `config:"iterations"`
	KeyLength  int `config:"key_length"`
	SaltLength int `config:"salt_length"`

	// BlockSize must be a factor of aes.BlockSize
	BlockSize int `config:"block_size"`
}

// Validate the config options
func (p *PBKDF2) Validate() error {
	if p.Iterations == 0 {
		return errors.New("iterations must be superior to 0")
	}
	if p.KeyLength == 0 {
		return errors.New("key_length must be superior to 0")
	}
	if p.SaltLength == 0 {
		return errors.New("salt_length must be superior to 0")
	}
	return nil
}

// InitDefaults is the default options to use with PDKDF2, changing might decrease
// the efficacy of the encryption.
func (p *PBKDF2) InitDefaults() {
	p.Iterations = 10000
	p.KeyLength = 32
	p.SaltLength = 64
	p.BlockSize = bytes.MinRead
}
