// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package esutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/rs/zerolog/log"
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

type ErrorResponse struct {
	Error struct {
		Type   string `json:"type"`
		Reason string `json:"reason"`
	} `json:"error,omitempty"`
	Status int `json:"status,omitempty"`

	err error // Wrapped error
}

func CheckResponseError(res *esapi.Response) error {
	if res.StatusCode >= http.StatusBadRequest {
		resErr, err := ParseResponseError(res)
		if err != nil {
			return err
		}

		cerr := &ClientError{
			StatusCode: resErr.Status,
			Type:       "request_error",
			Reason:     resErr.Error.Reason,
		}

		if resErr.Error.Type == esErrorResourceAlreadyExists {
			cerr.err = ErrResourceAlreadyExists
		}

		if resErr.Error.Type != "" {
			cerr.Type = resErr.Error.Type
		}

		return cerr
	}
	return nil
}

func ParseResponseError(res *esapi.Response) (*ErrorResponse, error) {
	var eres ErrorResponse
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
			log.Warn().
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
