// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cbor

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChunkWriter(t *testing.T) {
	contents := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	chunkLength := 9
	body := io.NopCloser(bytes.NewReader(contents))

	w := NewChunkWriter(body, false, "foobar", "56ab", int64(chunkLength))

	outbuf, err := io.ReadAll(w)
	require.NoError(t, err)

	expected := []byte{
		0xA4,                           // object with 4 keys
		0x64, 'l', 'a', 's', 't', 0xF4, // last: false
		0x63, 'b', 'i', 'd', 0x78, 0x06, 'f', 'o', 'o', 'b', 'a', 'r', // "bid": "foobar"
		0x64, 's', 'h', 'a', '2', 0x78, 0x04, '5', '6', 'a', 'b', // "sha2": "56ab"
		0x64, 'd', 'a', 't', 'a', // data:
		0x5A, 0x00, 0x00, 0x00, uint8(chunkLength), // 4-byte length instruction, then the actual 4-byte big-endian length
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, // contents
	}

	assert.Equal(t, expected, outbuf)
}

func TestChunkWriterLastChunk(t *testing.T) {
	contents := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	chunkLength := 20 // describes what a "full" chunk length is, not THIS chunk
	body := io.NopCloser(bytes.NewReader(contents))

	w := NewChunkWriter(body, true, "foobar", "face", int64(chunkLength))

	outbuf, err := io.ReadAll(w)
	require.NoError(t, err)

	expected := []byte{
		0xA4,                           // object with 4 keys
		0x64, 'l', 'a', 's', 't', 0xF5, // last: true
		0x63, 'b', 'i', 'd', 0x78, 0x06, 'f', 'o', 'o', 'b', 'a', 'r', // "bid": "foobar"
		0x64, 's', 'h', 'a', '2', 0x78, 0x04, 'f', 'a', 'c', 'e', // "sha2": "face"
		0x64, 'd', 'a', 't', 'a', // data:
		0x5F, // indeterminate length sequence
	}

	// assert equality up to the constant set point
	assert.Equal(t, expected, outbuf[:len(expected)])
	assert.Equal(t, uint8(0xFF), outbuf[len(outbuf)-1]) // final byte MUST be a 0xFF terminating byte when using indeterminate-length style

	// some light parsing, since this is variable depending on how Read() sizes its buffers internally
	parsedContents := make([]byte, len(contents))
	pi := 0 // write pointer for above buffer
	for i := len(expected); i < len(outbuf)-2; {
		assert.Equal(t, uint8(0x5A), outbuf[i])                     // expect a descriptor for 4-byte length sequence
		buflen := binary.BigEndian.Uint32(outbuf[i+1:])             // read 4 byte length descriptor
		n := copy(parsedContents[pi:], outbuf[i+5:i+5+int(buflen)]) // and copy those over
		pi += n
		i += n + 5 // 5 = 1 from (0x5A) and 4 from length descriptor
	}

	assert.Equal(t, contents, parsedContents)
}

func TestChunkWriterLargeLastChunk(t *testing.T) {
	// generates a large enough chunk to test multiple read calls internally

	contents := make([]byte, 4096)

	n, err := rand.Read(contents)
	require.NoError(t, err)
	require.Equal(t, n, 4096)

	chunkLength := 8192 // describes what a "full" chunk length is, not THIS chunk
	body := io.NopCloser(bytes.NewReader(contents))

	w := NewChunkWriter(body, true, "foobar", "face", int64(chunkLength))

	outbuf, err := io.ReadAll(w)
	require.NoError(t, err)

	expected := []byte{
		0xA4,                           // object with 4 keys
		0x64, 'l', 'a', 's', 't', 0xF5, // last: true
		0x63, 'b', 'i', 'd', 0x78, 0x06, 'f', 'o', 'o', 'b', 'a', 'r', // "bid": "foobar"
		0x64, 's', 'h', 'a', '2', 0x78, 0x04, 'f', 'a', 'c', 'e', // "sha2": "face"
		0x64, 'd', 'a', 't', 'a', // data:
		0x5F, // indeterminate length sequence
	}

	// assert equality up to the constant set point
	assert.Equal(t, expected, outbuf[:len(expected)])
	assert.Equal(t, uint8(0xFF), outbuf[len(outbuf)-1]) // final byte MUST be a 0xFF terminating byte when using indeterminate-length style

	// some light parsing, since this is variable depending on how Read() sizes its buffers internally
	parsedContents := make([]byte, len(contents))
	pi := 0 // write pointer for above buffer
	for i := len(expected); i < len(outbuf)-2; {
		assert.Equal(t, uint8(0x5A), outbuf[i])                     // expect a descriptor for 4-byte length sequence
		buflen := binary.BigEndian.Uint32(outbuf[i+1:])             // read 4 byte length descriptor
		n := copy(parsedContents[pi:], outbuf[i+5:i+5+int(buflen)]) // and copy those over
		pi += n
		i += n + 5 // 5 = 1 from (0x5A) and 4 from length descriptor
	}

	assert.Equal(t, contents, parsedContents)
}
