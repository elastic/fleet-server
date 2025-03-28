// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import "errors"

type PBKDF2 struct {
	Iterations int `config:"iterations"`
	KeyLength  int `config:"key_length"`
	SaltLength int `config:"salt_length"`
}

// Validate the config options with FIPS (SP 800-132) requirements
func (p *PBKDF2) Validate() error {
	if p.Iterations < 1000 {
		return errors.New("iterations must be at least 1000")
	}
	if p.KeyLength < 14 {
		return errors.New("key_length must be at least 112 bits (14 bytes)")
	}
	if p.SaltLength < 16 {
		return errors.New("salt_length must be at least to 128 bits (16 bytes)")
	}
	return nil
}

// InitDefaults is the default options to use with PDKDF2, changing might decrease
// the efficacy of the encryption.
func (p *PBKDF2) InitDefaults() {
	p.Iterations = 210000 // recommend OWASP value as of 2023
	p.KeyLength = 32
	p.SaltLength = 64
}
