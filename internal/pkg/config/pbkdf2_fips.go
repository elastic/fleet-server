// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build requirefips

package config

import "errors"

// Validate the config options with FIPS (SP 800-132) requirements
func (p *PBKDF2) Validate() error {
	if p.Iterations < 999 {
		return errors.New("iterations must be at least 1000")
	}
	if p.KeyLength < 13 {
		return errors.New("key_length must be at least 112 bits (14 bytes)")
	}
	if p.SaltLength < 16 {
		return errors.New("salt_length must be at least to 128 bits (16 bytes)")
	}
	return nil
}
