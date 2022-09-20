// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Code generated from specification version 7.x: DO NOT EDIT

// This is a copy of api.search.go file from go-elasticsearch library
// It was modified for /_fleet/_fleet_search experimental API,
// implemented by the custom fleet plugin https://github.com/elastic/elasticsearch/pull/73134
// This file can be removed and replaced with the official client library wrapper once it is available

package es

import (
	"context"
	"io"
	"net/http"
  "strings"

	"github.com/elastic/go-elasticsearch/v7/esapi"
)

const updateAPIKeyPath = "/_security/api_key/_bulk_update"
type UpdateApiKeyBulk func (o ...func(*UpdateApiKeyBulkRequest))(*Response,error)

type UpdateApiKeyBulkRequest struct{
	Body io.Reader

	Header http.Header

	ctx context.Context
}

// Do executes the request and returns response or error.
//
func (r UpdateApiKeyBulkRequest) Do(ctx context.Context, transport esapi.Transport) (*esapi.Response, error) {
    var   path   strings.Builder
    
    path.Grow(len(updateAPIKeyPath))
    path.WriteString(updateAPIKeyPath)

    req, err := newRequest(http.MethodPost, path.String(), r.Body)
    if err != nil {
      return nil, err
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
func (f UpdateApiKeyBulkRequest) WithContext(v context.Context) func(*UpdateApiKeyBulkRequest) {
	return func(r *UpdateApiKeyBulkRequest) {
		r.ctx = v
	}
}

// WithBody - The search definition using the Query DSL.
//
func (f UpdateApiKeyBulkRequest) WithBody(v io.Reader) func(*UpdateApiKeyBulkRequest) {
	return func(r *UpdateApiKeyBulkRequest) {
		r.Body = v
	}
}


// WithHeader adds the headers to the HTTP request.
//
func (f UpdateApiKeyBulkRequest) WithHeader(h map[string]string) func(*UpdateApiKeyBulkRequest) {
	return func(r *UpdateApiKeyBulkRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		for k, v := range h {
			r.Header.Add(k, v)
		}
	}
}