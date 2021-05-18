// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package danger

import (
	"crypto/rand"
	"testing"
)

// Validate that if a buffer needs to grow during a write,
// Previous cached pointers into underlying data are still valid.
func TestBufGrowWhileWrite(t *testing.T) {

	nBytes := 1024 * 1024
	src := make([]byte, 1024*1024)
	_, err := rand.Read(src)
	if err != nil {
		t.Fatal(err)
	}

	ptrs := make([][]byte, 0, nBytes)

	var dst Buf
	for i := 0; i < nBytes; i++ {

		if err = dst.WriteByte(src[i]); err != nil {
			t.Fatal(err)
		}

		ptr := dst.Bytes()[i:]

		ptrs = append(ptrs, ptr)
	}

	for i, p := range ptrs {

		if p[0] != src[i] {
			t.Fatal("Mismatch: ", i)
		}
	}
}
