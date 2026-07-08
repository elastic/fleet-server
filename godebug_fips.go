// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

// Enforce FIPS 140-3 mode at runtime so the binary rejects non-compliant crypto.
//go:debug fips140=on

package main
