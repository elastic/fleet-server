// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cbor

import (
	"io"

	fxcbor "github.com/fxamacker/cbor/v2"
)

type ChunkDecoder struct {
	dec *fxcbor.Decoder
}

func NewChunkDecoder(chunkData io.Reader) *ChunkDecoder {
	return &ChunkDecoder{fxcbor.NewDecoder(chunkData)}
}

func (c *ChunkDecoder) Decode() ([]byte, error) {

	type Packet struct {
		Fields struct {
			Data struct {
				_       struct{} `cbor:",toarray"`
				RawData []byte
			} `cbor:"data"`
		} `cbor:"fields"`
	}

	var p Packet
	if err := c.dec.Decode(&p); err != nil {
		return nil, err
	}
	return p.Fields.Data.RawData, nil

}
