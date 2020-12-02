// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package saved

import (
	"crypto/rand"
)

const (
	ivLen   = 12
	saltLen = 64
)

type nonceT struct {
	buf []byte
}

func newNonce() (nonceT, error) {
	n := nonceT{
		buf: make([]byte, saltLen+ivLen),
	}

	_, err := rand.Read(n.buf)
	return n, err
}

func (n nonceT) iv() []byte {
	return n.buf[saltLen:]
}

func (n nonceT) salt() []byte {
	return n.buf[:saltLen]
}

func (n nonceT) both() []byte {
	return n.buf
}
