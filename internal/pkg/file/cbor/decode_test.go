// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cbor

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hexDecode(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func TestDecode(t *testing.T) {
	// a small blue png, wrapped in an elasticsearch result document
	in := bytes.NewReader(hexDecode("bf665f696e64657878212e666c6565742d66696c6564656c69766572792d646174612d656e64706f696e74635f6964654142432e30685f76657273696f6e02675f7365715f6e6f016d5f7072696d6172795f7465726d0165666f756e64f5666669656c6473bf64646174619f586789504e470d0a1a0a0000000d494844520000010000000100010300000066bc3a2500000003504c5445b5d0d0630416ea0000001f494441546881edc1010d000000c2a0f74f6d0e37a00000000000000000be0d210000019a60e1d50000000049454e44ae426082ffffff"))

	dec := NewChunkDecoder(in)
	require.NotNil(t, dec)

	out, err := dec.Decode()
	require.NoError(t, err)

	// only the file contents
	assert.Equal(t, hexDecode("89504e470d0a1a0a0000000d494844520000010000000100010300000066bc3a2500000003504c5445b5d0d0630416ea0000001f494441546881edc1010d000000c2a0f74f6d0e37a00000000000000000be0d210000019a60e1d50000000049454e44ae426082"), out)
}

func TestDecodeMissingStopByte(t *testing.T) {
	// nearly correct document and file, missing a final 0xff stop byte (invalid CBOR)
	in := bytes.NewReader(hexDecode("bf665f696e64657878212e666c6565742d66696c6564656c69766572792d646174612d656e64706f696e74635f6964654142432e30685f76657273696f6e02675f7365715f6e6f016d5f7072696d6172795f7465726d0165666f756e64f5666669656c6473bf64646174619f586789504e470d0a1a0a0000000d494844520000010000000100010300000066bc3a2500000003504c5445b5d0d0630416ea0000001f494441546881edc1010d000000c2a0f74f6d0e37a00000000000000000be0d210000019a60e1d50000000049454e44ae426082ffff"))

	dec := NewChunkDecoder(in)
	require.NotNil(t, dec)

	_, err := dec.Decode()
	assert.Error(t, err)
}

func TestDecodeInvalid(t *testing.T) {

	// a small blue png, wrapped in an elasticsearch result document
	in := bytes.NewReader(hexDecode("deadbeef"))

	dec := NewChunkDecoder(in)
	require.NotNil(t, dec)

	_, err := dec.Decode()
	assert.Error(t, err)
}
