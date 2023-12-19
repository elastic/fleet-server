// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package gcheckpt handles the fleet API's global_checkpoints operations
// checkpoints are used to track which actions, agetnc (docs in general) have been read based on the seqno received.

//nolint:nakedret // FIXME refactor without naked returns at a later date
package gcheckpt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	esh "github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

var ErrGlobalCheckpoint = errors.New("global checkpoint error")

// Global checkpoint response
// {"global_checkpoints":[-1]}

type globalCheckpointsResponse struct {
	GlobalCheckpoints []int64         `json:"global_checkpoints"`
	TimedOut          bool            `json:"timed_out"`
	Error             json.RawMessage `json:"error,omitempty"`
}

func Query(ctx context.Context, es *elasticsearch.Client, index string) (seqno sqn.SeqNo, err error) {
	res, err := es.FleetGlobalCheckpoints(
		index,
		es.FleetGlobalCheckpoints.WithContext(ctx),
	)
	if err != nil {
		return
	}

	seqno, err = processGlobalCheckpointResponse(res)
	if errors.Is(err, esh.ErrIndexNotFound) {
		seqno = sqn.DefaultSeqNo
		err = nil
	}

	return seqno, err
}

func WaitAdvance(ctx context.Context, es *elasticsearch.Client, index string, checkpoint sqn.SeqNo, to time.Duration) (seqno sqn.SeqNo, err error) {
	res, err := es.FleetGlobalCheckpoints(
		index,
		es.FleetGlobalCheckpoints.WithContext(ctx),
		es.FleetGlobalCheckpoints.WithCheckpoints(checkpoint.String()),
		es.FleetGlobalCheckpoints.WithWaitForAdvance(true),
		es.FleetGlobalCheckpoints.WithWaitForIndex(true),
		es.FleetGlobalCheckpoints.WithTimeout(to),
	)
	if err != nil {
		return
	}

	return processGlobalCheckpointResponse(res)
}

func processGlobalCheckpointResponse(res *esapi.Response) (seqno sqn.SeqNo, err error) {
	defer res.Body.Close()

	// Don't parse the payload if timeout
	if res.StatusCode == http.StatusGatewayTimeout {
		return seqno, esh.ErrTimeout
	}

	// Parse payload
	var sres globalCheckpointsResponse
	err = json.NewDecoder(res.Body).Decode(&sres)
	if err != nil {
		return
	}

	// Check error
	err = esh.TranslateError(res.StatusCode, sres.Error)
	if err != nil {
		return nil, err
	}

	if sres.TimedOut {
		return nil, esh.ErrTimeout
	}

	if len(sres.GlobalCheckpoints) == 0 {
		return nil, esh.ErrNotFound
	}

	return sres.GlobalCheckpoints, nil
}
