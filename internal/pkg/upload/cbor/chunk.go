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
	chunk       io.ReadCloser
	final       bool
	preamble    []byte
	prbWritten  bool
	prbWritePos int
	wroteTerm   bool
}

func NewChunkWriter(chunkData io.ReadCloser, finalChunk bool, baseID string, chunkSize int64) *ChunkEncoder {
	return &ChunkEncoder{
		chunk:       chunkData,
		final:       finalChunk,
		preamble:    encodePreambleToCBOR(finalChunk, baseID, chunkSize),
		prbWritten:  false,
		prbWritePos: 0,
		wroteTerm:   false,
	}
}

// Writes the start of a CBOR object (equiv. JSON object)
// {
//	"bid": "baseID",
//	"last": true/false,
//	"data":
// }
// the slice ends where the chunk data bytes ("byte string") should begin.
// it is therefore an incomplete CBOR object on its own
// expecting the next section to be filled in by the caller.
// the CBOR spec may be found here: https://www.rfc-editor.org/rfc/rfc8949
func encodePreambleToCBOR(final bool, baseID string, chunkSize int64) []byte {
	bidLen := len(baseID)

	// if we know the size of the chunk stream, we will write the 4-byte uint32
	// descriptor of that length
	// otherwise it will be a *single* byte saying it is an unknown length
	// and we will write out lengths as the chunk is read
	chunkLen := 5 // space for describing sequence length. 1 byte to SAY 32-bit int (4byte), then 4 bytes
	if final {
		chunkLen = 1
	}

	preamble := make([]byte, 13+bidLen+chunkLen+5)
	preamble[0] = 0xA3 // Object with 3 keys
	preamble[1] = 0x64 // string with 4 chars
	preamble[2] = 'l'
	preamble[3] = 'a'
	preamble[4] = 's'
	preamble[5] = 't'
	if final {
		preamble[6] = 0xF5 // bool true
	} else {
		preamble[6] = 0xF4 // bool false
	}
	preamble[7] = 0x63 // string with 3 chars
	preamble[8] = 'b'
	preamble[9] = 'i'
	preamble[10] = 'd'
	preamble[11] = 0x78 // UTF-8 string coming, next byte describes length
	preamble[12] = uint8(bidLen)
	i := 13
	for _, c := range baseID { // now write the document baseID
		preamble[i] = byte(c)
		i++
	}
	preamble[i] = 0x64 // string with 4 chars
	preamble[i+1] = 'd'
	preamble[i+2] = 'a'
	preamble[i+3] = 't'
	preamble[i+4] = 'a'
	i += 5
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
		n, err := c.chunk.Read(buf[5:])
		buf[0] = 0x5A // 4-byte length descriptor to follow
		binary.BigEndian.PutUint32(buf[1:], uint32(n))

		if errors.Is(err, io.EOF) {
			if n == 0 { // chunk data has been exhausted, write the terminating byte and get out
				buf[0] = 0xFF
				c.wroteTerm = true
				return 1, io.EOF
			}
			// if we can tack-on the terminating byte from this read call, do it
			if len(buf) > n+5+1 {
				buf[n+5] = 0xFF
				c.wroteTerm = true
				n = n + 1
			} else {
				//otherwise, wait for the next call to Read(), hide the EOF err
				err = nil
			}
		}
		return n + 5, err
	}

	return c.chunk.Read(buf)

}
