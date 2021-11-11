// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Code generated from specification version 7.x: DO NOT EDIT

// This is a copy of api.msearch.go file from go-elasticsearch library
// It was modified for /_fleet/_fleet_msearch experimental API,
// implemented by the custom fleet plugin https://github.com/elastic/elasticsearch/pull/73134
// This file can be removed and replaced with the official client library wrapper once it is available

package es

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/elastic/go-elasticsearch/v7/esapi"
)

// ----- API Definition -------------------------------------------------------

// FleetMsearch allows to execute several search operations in one request.
type FleetMsearch func(body io.Reader, o ...func(*FleetMsearchRequest)) (*Response, error)

// FleetMsearchRequest configures the FleetMsearch API request.
//
type FleetMsearchRequest struct {
	Index        []string
	DocumentType []string

	Body io.Reader

	CcsMinimizeRoundtrips      *bool
	MaxConcurrentSearches      *int
	MaxConcurrentShardRequests *int
	PreFilterShardSize         *int
	RestTotalHitsAsInt         *bool
	SearchType                 string
	TypedKeys                  *bool

	Pretty     bool
	Human      bool
	ErrorTrace bool
	FilterPath []string

	Header http.Header

	ctx context.Context
}

// Do executes the request and returns response or error.
//
func (r FleetMsearchRequest) Do(ctx context.Context, transport esapi.Transport) (*esapi.Response, error) {
	var (
		method string
		path   strings.Builder
		params map[string]string
	)

	method = "POST"

	path.Grow(1 + len(strings.Join(r.Index, ",")) + 1 + len(strings.Join(r.DocumentType, ",")) + 1 + len("_fleet/_fleet_msearch"))
	if len(r.Index) > 0 {
		path.WriteString("/")
		path.WriteString(strings.Join(r.Index, ","))
	}
	if len(r.DocumentType) > 0 {
		path.WriteString("/")
		path.WriteString(strings.Join(r.DocumentType, ","))
	}
	path.WriteString("/")
	path.WriteString("_fleet/_fleet_msearch")

	params = make(map[string]string)

	if r.CcsMinimizeRoundtrips != nil {
		params["ccs_minimize_roundtrips"] = strconv.FormatBool(*r.CcsMinimizeRoundtrips)
	}

	if r.MaxConcurrentSearches != nil {
		params["max_concurrent_searches"] = strconv.FormatInt(int64(*r.MaxConcurrentSearches), 10)
	}

	if r.MaxConcurrentShardRequests != nil {
		params["max_concurrent_shard_requests"] = strconv.FormatInt(int64(*r.MaxConcurrentShardRequests), 10)
	}

	if r.PreFilterShardSize != nil {
		params["pre_filter_shard_size"] = strconv.FormatInt(int64(*r.PreFilterShardSize), 10)
	}

	if r.RestTotalHitsAsInt != nil {
		params["rest_total_hits_as_int"] = strconv.FormatBool(*r.RestTotalHitsAsInt)
	}

	if r.SearchType != "" {
		params["search_type"] = r.SearchType
	}

	if r.TypedKeys != nil {
		params["typed_keys"] = strconv.FormatBool(*r.TypedKeys)
	}

	if r.Pretty {
		params["pretty"] = "true"
	}

	if r.Human {
		params["human"] = "true"
	}

	if r.ErrorTrace {
		params["error_trace"] = "true"
	}

	if len(r.FilterPath) > 0 {
		params["filter_path"] = strings.Join(r.FilterPath, ",")
	}

	req, err := newRequest(method, path.String(), r.Body)
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

	if r.Body != nil {
		req.Header[headerContentType] = headerContentTypeJSON
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

	res, err := transport.Perform(req)
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
func (f FleetMsearch) WithContext(v context.Context) func(*FleetMsearchRequest) {
	return func(r *FleetMsearchRequest) {
		r.ctx = v
	}
}

// WithIndex - a list of index names to use as default.
//
func (f FleetMsearch) WithIndex(v ...string) func(*FleetMsearchRequest) {
	return func(r *FleetMsearchRequest) {
		r.Index = v
	}
}

// WithDocumentType - a list of document types to use as default.
//
func (f FleetMsearch) WithDocumentType(v ...string) func(*FleetMsearchRequest) {
	return func(r *FleetMsearchRequest) {
		r.DocumentType = v
	}
}

// WithCcsMinimizeRoundtrips - indicates whether network round-trips should be minimized as part of cross-cluster search requests execution.
//
func (f FleetMsearch) WithCcsMinimizeRoundtrips(v bool) func(*FleetMsearchRequest) {
	return func(r *FleetMsearchRequest) {
		r.CcsMinimizeRoundtrips = &v
	}
}

// WithMaxConcurrentSearches - controls the maximum number of concurrent searches the multi search api will execute.
//
func (f FleetMsearch) WithMaxConcurrentSearches(v int) func(*FleetMsearchRequest) {
	return func(r *FleetMsearchRequest) {
		r.MaxConcurrentSearches = &v
	}
}

// WithMaxConcurrentShardRequests - the number of concurrent shard requests each sub search executes concurrently per node. this value should be used to limit the impact of the search on the cluster in order to limit the number of concurrent shard requests.
//
func (f FleetMsearch) WithMaxConcurrentShardRequests(v int) func(*FleetMsearchRequest) {
	return func(r *FleetMsearchRequest) {
		r.MaxConcurrentShardRequests = &v
	}
}

// WithPreFilterShardSize - a threshold that enforces a pre-filter roundtrip to prefilter search shards based on query rewriting if the number of shards the search request expands to exceeds the threshold. this filter roundtrip can limit the number of shards significantly if for instance a shard can not match any documents based on its rewrite method ie. if date filters are mandatory to match but the shard bounds and the query are disjoint..
//
func (f FleetMsearch) WithPreFilterShardSize(v int) func(*FleetMsearchRequest) {
	return func(r *FleetMsearchRequest) {
		r.PreFilterShardSize = &v
	}
}

// WithRestTotalHitsAsInt - indicates whether hits.total should be rendered as an integer or an object in the rest search response.
//
func (f FleetMsearch) WithRestTotalHitsAsInt(v bool) func(*FleetMsearchRequest) {
	return func(r *FleetMsearchRequest) {
		r.RestTotalHitsAsInt = &v
	}
}

// WithSearchType - search operation type.
//
func (f FleetMsearch) WithSearchType(v string) func(*FleetMsearchRequest) {
	return func(r *FleetMsearchRequest) {
		r.SearchType = v
	}
}

// WithTypedKeys - specify whether aggregation and suggester names should be prefixed by their respective types in the response.
//
func (f FleetMsearch) WithTypedKeys(v bool) func(*FleetMsearchRequest) {
	return func(r *FleetMsearchRequest) {
		r.TypedKeys = &v
	}
}

// WithPretty makes the response body pretty-printed.
//
func (f FleetMsearch) WithPretty() func(*FleetMsearchRequest) {
	return func(r *FleetMsearchRequest) {
		r.Pretty = true
	}
}

// WithHuman makes statistical values human-readable.
//
func (f FleetMsearch) WithHuman() func(*FleetMsearchRequest) {
	return func(r *FleetMsearchRequest) {
		r.Human = true
	}
}

// WithErrorTrace includes the stack trace for errors in the response body.
//
func (f FleetMsearch) WithErrorTrace() func(*FleetMsearchRequest) {
	return func(r *FleetMsearchRequest) {
		r.ErrorTrace = true
	}
}

// WithFilterPath filters the properties of the response body.
//
func (f FleetMsearch) WithFilterPath(v ...string) func(*FleetMsearchRequest) {
	return func(r *FleetMsearchRequest) {
		r.FilterPath = v
	}
}

// WithHeader adds the headers to the HTTP request.
//
func (f FleetMsearch) WithHeader(h map[string]string) func(*FleetMsearchRequest) {
	return func(r *FleetMsearchRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		for k, v := range h {
			r.Header.Add(k, v)
		}
	}
}

// WithOpaqueID adds the X-Opaque-Id header to the HTTP request.
//
func (f FleetMsearch) WithOpaqueID(s string) func(*FleetMsearchRequest) {
	return func(r *FleetMsearchRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		r.Header.Set("X-Opaque-Id", s)
	}
}

// esapi.request.go
const (
	headerContentType = "Content-Type"
)

var (
	headerContentTypeJSON = []string{"application/json"}
)

// newRequest creates an HTTP request.
//
func newRequest(method, path string, body io.Reader) (*http.Request, error) {
	return http.NewRequest(method, path, body)
}
