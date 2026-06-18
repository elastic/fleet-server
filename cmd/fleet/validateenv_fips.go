// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package fleet

import (
	"crypto/fips140"
	"fmt"
)

func validateEnv() error {
	if !fips140.Enabled() {
		return fmt.Errorf("fips disabled")
	}
}
