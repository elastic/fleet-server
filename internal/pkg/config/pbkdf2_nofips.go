// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !requirefips

package config

import "errors"

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
