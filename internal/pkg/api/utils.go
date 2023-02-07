// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

// ptr is a helper function to get a pointer to whatever is passed, including a literal
//
//nolint:deadcode,unused // used in tests at the moment
func ptr[T any](v T) *T {
	return &v
}

// fromPtr takes a pointer to a val and returns the val, or the zero-type of it if it's nil
func fromPtr[T any](v *T) T {
	if v == nil {
		var x T
		return x
	}
	return *v
}
