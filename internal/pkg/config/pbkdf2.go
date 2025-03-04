// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

type PBKDF2 struct {
	Iterations int `config:"iterations"`
	KeyLength  int `config:"key_length"`
	SaltLength int `config:"salt_length"`
}

// InitDefaults is the default options to use with PDKDF2, changing might decrease
// the efficacy of the encryption.
func (p *PBKDF2) InitDefaults() {
	p.Iterations = 210000 // recommend OWASP value as of 2023
	p.KeyLength = 32
	p.SaltLength = 64
}
