// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cbor

import (
	"encoding/binary"
	"errors"
	"io"
)

// This is a trimmed-down special purpose writer
// and cbor encoder used to streamline upload chunk writing
// without buffering large amounts of data
// in memory.
// It is not a general-purpose CBOR encoder.
// A suitable general purpose library, if the future needs one, is github.com/fxamacker/cbor/v2
type ChunkEncoder struct {
	chunk       io.Reader
	final       bool
	preamble    []byte
	prbWritten  bool
	prbWritePos int
	wroteTerm   bool
}

func NewChunkWriter(chunkData io.Reader, finalChunk bool, baseID string, chunkHash string, chunkSize int64) *ChunkEncoder {
	return &ChunkEncoder{
		chunk:       chunkData,
		final:       finalChunk,
		preamble:    encodePreambleToCBOR(finalChunk, baseID, chunkHash, chunkSize),
		prbWritten:  false,
		prbWritePos: 0,
		wroteTerm:   false,
	}
}

// Writes the start of a CBOR object (equiv. JSON object)
// {
//	"last": true/false,
//	"bid": "baseID",
//	"sha2": "...",
//	"data":
// }
// the slice ends where the chunk data bytes ("byte string") should begin.
// it is therefore an incomplete CBOR object on its own
// expecting the next section to be filled in by the caller.
// the CBOR spec may be found here: https://www.rfc-editor.org/rfc/rfc8949
// chunksize is ignored when writing the "final"=true chunk
func encodePreambleToCBOR(final bool, baseID string, chunkHash string, chunkSize int64) []byte {
	bidLen := len(baseID)
	hashLen := len(chunkHash)

	// if we know the size of the chunk stream, we will write the 4-byte uint32
	// descriptor of that length
	// otherwise it will be a *single* byte saying it is an unknown length
	// and we will write out lengths as the chunk is read
	chunkLen := 5 // space for describing sequence length. 1 byte to SAY 32-bit int (4byte), then 4 bytes
	if final {
		chunkLen = 1
	}

	preamble := make([]byte, 11+bidLen+2+5+hashLen+2+chunkLen+5)
	preamble[0] = 0xA4 // Object with 4 keys
	preamble[1] = 0x64 // string with 4 chars (key: last)
	preamble[2] = 'l'
	preamble[3] = 'a'
	preamble[4] = 's'
	preamble[5] = 't'
	if final {
		preamble[6] = 0xF5 // bool true
	} else {
		preamble[6] = 0xF4 // bool false
	}
	preamble[7] = 0x63 // string with 3 chars (key: bid)
	preamble[8] = 'b'
	preamble[9] = 'i'
	preamble[10] = 'd'
	i := 11
	if n, err := writeString(preamble[i:], baseID); err != nil {
		return nil
	} else {
		i = 11 + n
	}
	if n, err := writeKey(preamble[i:], "sha2"); err != nil {
		return nil
	} else {
		i += n
	}
	if n, err := writeString(preamble[i:], chunkHash); err != nil {
		return nil
	} else {
		i += n
	}
	if n, err := writeKey(preamble[i:], "data"); err != nil {
		return nil
	} else {
		i += n
	}
	if !final {
		// byte data should be precisely chunkSize long, otherwise malformed
		preamble[i] = 0x5A // say length descriptor will be 32-bit int
		binary.BigEndian.PutUint32(preamble[i+1:], uint32(chunkSize))
	} else {
		// final chunk may be less than full size, will need to determine length
		preamble[i] = 0x5F // indeterminate-length byte sequence
	}
	return preamble
}

const varLenHeaderSize = 5

// io.Reader interface for streaming out
func (c *ChunkEncoder) Read(buf []byte) (int, error) {
	if c.wroteTerm { // already wrote a terminating instruction for undefined byte sequence length
		return 0, io.EOF
	}

	if !c.prbWritten {
		n := copy(buf, c.preamble[c.prbWritePos:])
		if n == len(c.preamble[c.prbWritePos:]) {
			c.prbWritten = true
		}
		c.prbWritePos += n
		return n, nil
	}

	if c.final {
		// need to write length headers before the byte sequence
		if len(buf) < 10 {
			return 0, errors.New("buffer too small")
		}
		n, err := c.chunk.Read(buf[varLenHeaderSize:])
		buf[0] = 0x5A // 4-byte length descriptor to follow
		binary.BigEndian.PutUint32(buf[1:], uint32(n))

		if errors.Is(err, io.EOF) {
			if n == 0 { // chunk data has been exhausted, write the terminating byte and get out
				buf[0] = 0xFF
				c.wroteTerm = true
				return 1, io.EOF
			}
			// if we can tack-on the terminating byte from this read call, do it
			if len(buf) > n+varLenHeaderSize+1 {
				buf[n+varLenHeaderSize] = 0xFF
				c.wroteTerm = true
				n = n + 1
			} else {
				//otherwise, wait for the next call to Read(), hide the EOF err
				err = nil
			}
		}
		return n + varLenHeaderSize, err
	}

	return c.chunk.Read(buf)

}

// writes len(key)+1 bytes
func writeKey(buf []byte, key string) (int, error) {
	keylen := len(key)
	if keylen > 0x17 { // CBOR spec max size for single-byte string length descriptor
		// another method would have to be used for writing the string length
		return 0, errors.New("large key size, write manually")
	}
	if len(buf) < keylen+1 {
		return 0, errors.New("cbor buffer size too small")
	}

	buf[0] = byte(0x60 + keylen)
	for i, c := range key {
		buf[i+1] = byte(c)
	}

	return keylen + 1, nil
}

// writes len(string)+2 bytes
func writeString(buf []byte, val string) (int, error) {
	strlen := len(val)
	if strlen > 0xff { // max single-byte strlen
		return 0, errors.New("oversize string")
	}
	if len(buf) < strlen+2 {
		return 0, errors.New("cbor buffer size too small")
	}

	buf[0] = 0x78 // Descriptor for: "UTF8 string. Next byte is a uint8 for n, and then n bytes follow"
	buf[1] = uint8(strlen)
	for i, c := range val {
		buf[i+2] = byte(c)
	}

	return strlen + 2, nil
}
