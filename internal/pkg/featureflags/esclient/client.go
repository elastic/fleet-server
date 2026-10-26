// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package esclient defines the small Elasticsearch surface the feature flags module depends on.
// Keeping the module behind this interface means it can be extracted into its own service later.
package esclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/elastic/go-elasticsearch/v9"
)

// ErrIndexNotFound is returned (possibly wrapped) when the searched index does not exist.
var ErrIndexNotFound = errors.New("index not found")

// Client is the subset of Elasticsearch used by the feature flags module.
type Client interface {
	// Search runs a search request against index and returns the raw response body.
	// It returns an error wrapping ErrIndexNotFound when the index does not exist.
	Search(ctx context.Context, index string, body []byte) ([]byte, error)
	// Bulk sends an NDJSON _bulk request and returns the raw response body.
	// Per-item failures are reported in the body, not as an error.
	Bulk(ctx context.Context, body []byte) ([]byte, error)
}

// ResponseError is an error response returned by Elasticsearch.
type ResponseError struct {
	Status int
	Type   string
	Reason string
}

func (e *ResponseError) Error() string {
	return fmt.Sprintf("elasticsearch error %d: %s: %s", e.Status, e.Type, e.Reason)
}

// Unwrap maps well known error types to sentinel errors.
func (e *ResponseError) Unwrap() error {
	if e.Type == "index_not_found_exception" {
		return ErrIndexNotFound
	}
	return nil
}

type client struct {
	es *elasticsearch.Client
}

// New returns a Client backed by the go-elasticsearch client.
func New(es *elasticsearch.Client) Client {
	return &client{es: es}
}

func (c *client) Search(ctx context.Context, index string, body []byte) ([]byte, error) {
	res, err := c.es.Search(
		c.es.Search.WithContext(ctx),
		c.es.Search.WithIndex(index),
		c.es.Search.WithBody(bytes.NewReader(body)),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	return readResponse(res.StatusCode, res.IsError(), res.Body)
}

func (c *client) Bulk(ctx context.Context, body []byte) ([]byte, error) {
	res, err := c.es.Bulk(bytes.NewReader(body), c.es.Bulk.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	return readResponse(res.StatusCode, res.IsError(), res.Body)
}

func readResponse(status int, isError bool, body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	if !isError {
		return data, nil
	}
	return nil, ParseError(status, data)
}

// ParseError converts an Elasticsearch error response body into a *ResponseError.
func ParseError(status int, data []byte) error {
	var parsed struct {
		Error json.RawMessage `json:"error"`
	}
	respErr := &ResponseError{Status: status}
	if err := json.Unmarshal(data, &parsed); err != nil || len(parsed.Error) == 0 {
		respErr.Reason = string(data)
		return respErr
	}
	var details struct {
		Type   string `json:"type"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(parsed.Error, &details); err != nil {
		// Some errors are plain strings.
		respErr.Reason = string(parsed.Error)
		return respErr
	}
	respErr.Type = details.Type
	respErr.Reason = details.Reason
	return respErr
}
