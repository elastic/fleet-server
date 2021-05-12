// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitor

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
	GlobalCheckpoints []int64    `json:"global_checkpoints"`
	TimedOut          bool       `json:"timed_out"`
	Error             esh.ErrorT `json:"error,omitempty"`
}

func queryGlobalCheckpoint(ctx context.Context, es *elasticsearch.Client, index string) (seqno sqn.SeqNo, err error) {
	req := esh.NewGlobalCheckpointsRequest(es.Transport)
	res, err := req(req.WithContext(ctx),
		req.WithIndex(index))

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

func waitCheckpointAdvance(ctx context.Context, es *elasticsearch.Client, index string, checkpoint sqn.SeqNo, to time.Duration) (seqno sqn.SeqNo, err error) {
	req := esh.NewGlobalCheckpointsRequest(es.Transport)
	res, err := req(req.WithContext(ctx),
		req.WithIndex(index),
		req.WithCheckpoints(checkpoint),
		req.WithWaitForAdvance(true),
		req.WithWaitForIndex(true),
		req.WithTimeout(to),
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
	err = esh.TranslateError(res.StatusCode, &sres.Error)
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
