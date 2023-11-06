// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package esutil

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/rs/zerolog"
)

const (
	esErrorResourceAlreadyExists = "resource_already_exists_exception"
)

var (
	ErrResourceAlreadyExists = errors.New("resource already exists")
)

type ClientError struct {
	StatusCode int
	Type       string
	Reason     string
	err        error
}

func (e *ClientError) Error() string {
	res := fmt.Sprintf("%d - %s", e.StatusCode, e.Type)
	if e.Reason != "" {
		res += ": " + e.Reason
	}
	return res
}

func (e *ClientError) Unwrap() error {
	return e.err
}

type errorResponse struct {
	Error struct {
		Type   string `json:"type"`
		Reason string `json:"reason"`
	} `json:"error,omitempty"`
	Status int `json:"status,omitempty"`
}

func checkResponseError(res *esapi.Response) error {
	if res.StatusCode >= http.StatusBadRequest {
		resErr, err := parseResponseError(res)
		if err != nil {
			return err
		}

		cerr := &ClientError{
			StatusCode: resErr.Status,
			Type:       "request_error",
			Reason:     resErr.Error.Reason,
		}

		if resErr.Error.Type == esErrorResourceAlreadyExists ||
			strings.HasSuffix(resErr.Error.Reason, "already exists as alias") {
			cerr.err = ErrResourceAlreadyExists
		}

		if resErr.Error.Type != "" {
			cerr.Type = resErr.Error.Type
		}

		return cerr
	}
	return nil
}

func parseResponseError(res *esapi.Response) (*errorResponse, error) {
	var eres errorResponse
	if res.StatusCode >= http.StatusBadRequest {
		// Read the original body content, in case if it was a error from the cloud response
		// {"ok":false,"message":"Unknown deployment."}
		// So we can log it
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, &ClientError{
				StatusCode: res.StatusCode,
				Type:       "response_read_error",
				Reason:     err.Error(),
			}
		}

		err = json.Unmarshal(body, &eres)
		if err != nil {
			return nil, &ClientError{
				StatusCode: res.StatusCode,
				Type:       "response_parse_error",
				Reason:     string(body),
			}
		}

		// Unexpected error, probably from the cloud deployment, not elasticsearch API response
		if eres.Status == 0 {
			zerolog.Ctx(context.TODO()).Warn().
				Int("status", eres.Status).
				Str("type", eres.Error.Type).
				Str("reason", eres.Error.Reason).Msg("ES client response error")

			return nil, &ClientError{
				StatusCode: eres.Status,
				Type:       eres.Error.Type,
				Reason:     eres.Error.Reason,
			}
		}
	}
	return &eres, nil
}
