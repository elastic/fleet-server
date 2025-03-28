// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"errors"
	"testing"
)

func TestPbkdf2Validation(t *testing.T) {
	for _, test := range []struct {
		name string
		p    *PBKDF2
		err  error
	}{
		{
			name: "valid",
			p:    &PBKDF2{Iterations: 1000, KeyLength: 14, SaltLength: 16},
			err:  nil,
		},
		{
			name: "invalid iterations",
			p:    &PBKDF2{Iterations: 999, KeyLength: 14, SaltLength: 16},
			err:  errors.New("iterations must be at least 1000"),
		},
		{
			name: "invalid key length",
			p:    &PBKDF2{Iterations: 1000, KeyLength: 13, SaltLength: 16},
			err:  errors.New("key_length must be at least 112 bits (14 bytes)"),
		},
		{
			name: "invalid salt length",
			p:    &PBKDF2{Iterations: 1000, KeyLength: 14, SaltLength: 15},
			err:  errors.New("salt_length must be at least to 128 bits (16 bytes)"),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.p.Validate()
			if err == nil && test.err == nil {
				return
			}
			if err == nil || test.err == nil || err.Error() != test.err.Error() {
				t.Errorf("expected error %v, got %v", test.err, err)
			}
		})
	}
}
