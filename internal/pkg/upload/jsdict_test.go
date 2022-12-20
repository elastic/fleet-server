// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upload

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSDictDecodesValidJSON(t *testing.T) {
	inputs := []string{
		`{}`,
		`{"foo":"bar"}`,
		`{"action_id":"32a4c404-1418-4bba-8f2b-e704faf897f8","agent_id":"f2eec0f8-468d-4950-9fd3-9c260584885c","file":{"ext":"gif","mime_type":"image/gif","mode":"0644","name":"wallet.gif","path":"/tmp/meme.gif","size":3417671,"type":"file"},"src":"endpoint"}`,
	}

	for i, tc := range inputs {
		t.Run(fmt.Sprintf("json-%d", i), func(t *testing.T) {
			_, err := ReadDict(strings.NewReader(tc))
			assert.NoError(t, err)
		})
	}

}

func TestJSDictFetchIntDefaultMethod(t *testing.T) {
	// number chosen to be larger than any int32 or uint32 to hold
	input := bytes.NewReader([]byte(`{"num":5000000000}`))

	// manually decoding into a JSDict to ignore whatever default behavior
	// in ReadDict(), to ensure Int retrieval works with either json
	// decoding behavior
	var d JSDict
	err := json.NewDecoder(input).Decode(&d)
	require.NoError(t, err)

	val, ok := d.Int64("num")
	assert.True(t, ok, "num conversion should return ok=true status")

	assert.Equal(t, int64(5000000000), val)
}

func TestJSDictFetchIntNumberMethod(t *testing.T) {
	// number chosen to be larger than any int32 or uint32 to hold
	input := bytes.NewReader([]byte(`{"num":5000000000}`))

	// manually decoding into a JSDict to ignore whatever default behavior
	// in ReadDict(), to ensure Int retrieval works with either json
	// decoding behavior
	var d JSDict
	decoder := json.NewDecoder(input)
	decoder.UseNumber() // This defines a specific number decoding strategy
	err := decoder.Decode(&d)
	require.NoError(t, err)

	val, ok := d.Int64("num")
	assert.True(t, ok, "num conversion should return ok=true status")

	assert.Equal(t, int64(5000000000), val)
}
