// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package es

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"
	"github.com/elastic/go-elasticsearch/v7/esapi"
)

// The wrapper for the new _fleet global_checkpoints that is not the part of the
// standard client library at the moment.
// The shape mimics the official client API and should be easy drop-in replacement in the future.
// This should be replaced the official client library when/if the new API makes it in.

func NewGlobalCheckpointsRequest(t esapi.Transport) GlobalCheckpoints {
	return func(o ...func(*GlobalCheckpointsRequest)) (*esapi.Response, error) {
		var r = GlobalCheckpointsRequest{}
		for _, f := range o {
			f(&r)
		}
		return r.Do(r.ctx, t)
	}
}

// Copied from the official client
func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return strconv.FormatInt(int64(d), 10) + "nanos"
	}
	return strconv.FormatInt(int64(d)/int64(time.Millisecond), 10) + "ms"
}

type GlobalCheckpoints func(o ...func(*GlobalCheckpointsRequest)) (*esapi.Response, error)

// GlobalCheckpointsRequest configures the _fleet API global_checkpoints request.
//
type GlobalCheckpointsRequest struct {
	ctx context.Context

	Index          string
	WaitForAdvance *bool
	WaitForIndex   *bool
	Checkpoints    []int64
	Timeout        time.Duration

	Header http.Header
}

// Do executes the request and returns response or error.
//
func (r GlobalCheckpointsRequest) Do(ctx context.Context, transport esapi.Transport) (*esapi.Response, error) {
	var (
		method string
		path   strings.Builder
		params map[string]string
	)

	method = "GET"

	path.Grow(1 + len(r.Index) + len("/_fleet/global_checkpoints"))
	if len(r.Index) > 0 {
		path.WriteString("/")
		path.WriteString(r.Index)
	}
	path.WriteString("/_fleet/global_checkpoints")

	params = make(map[string]string)

	if r.WaitForAdvance != nil {
		params["wait_for_advance"] = strconv.FormatBool(*r.WaitForAdvance)
	}

	if r.WaitForIndex != nil {
		params["wait_for_index"] = strconv.FormatBool(*r.WaitForIndex)
	}

	if len(r.Checkpoints) > 0 {
		seqNo := sqn.SeqNo(r.Checkpoints)
		params["checkpoints"] = seqNo.String()
	}

	if r.Timeout != 0 {
		params["timeout"] = formatDuration(r.Timeout)
	}

	req, err := http.NewRequest(method, path.String(), nil)
	if err != nil {
		return nil, err
	}

	if len(params) > 0 {
		q := req.URL.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	if len(r.Header) > 0 {
		if len(req.Header) == 0 {
			req.Header = r.Header
		} else {
			for k, vv := range r.Header {
				for _, v := range vv {
					req.Header.Add(k, v)
				}
			}
		}
	}

	if ctx != nil {
		req = req.WithContext(ctx)
	}

	// NOTE do not close the response body here, it's handled further along (gcheckpts)
	// Closing the body within this method will cause operations that use checkpoints to fail
	// a lot of operations use checkpoints
	res, err := transport.Perform(req) //nolint:bodyclose // :(
	if err != nil {
		return nil, err
	}

	response := esapi.Response{
		StatusCode: res.StatusCode,
		Body:       res.Body,
		Header:     res.Header,
	}

	return &response, nil
}

// WithContext sets the request context.
//
func (f GlobalCheckpoints) WithContext(v context.Context) func(*GlobalCheckpointsRequest) {
	return func(r *GlobalCheckpointsRequest) {
		r.ctx = v
	}
}

// WithIndex - an index name
//
func (f GlobalCheckpoints) WithIndex(index string) func(*GlobalCheckpointsRequest) {
	return func(r *GlobalCheckpointsRequest) {
		r.Index = index
	}
}

func (f GlobalCheckpoints) WithWaitForAdvance(v bool) func(*GlobalCheckpointsRequest) {
	return func(r *GlobalCheckpointsRequest) {
		r.WaitForAdvance = &v
	}
}

func (f GlobalCheckpoints) WithWaitForIndex(v bool) func(*GlobalCheckpointsRequest) {
	return func(r *GlobalCheckpointsRequest) {
		r.WaitForIndex = &v
	}
}

func (f GlobalCheckpoints) WithCheckpoints(checkpoints []int64) func(*GlobalCheckpointsRequest) {
	return func(r *GlobalCheckpointsRequest) {
		r.Checkpoints = checkpoints
	}
}

func (f GlobalCheckpoints) WithTimeout(to time.Duration) func(*GlobalCheckpointsRequest) {
	return func(r *GlobalCheckpointsRequest) {
		r.Timeout = to
	}
}
