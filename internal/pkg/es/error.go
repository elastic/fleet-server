// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package es

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/rs/zerolog"
	"io"
	"strconv"
	"strings"
)

const (
	unknownErrorType         = "unknown_error"
	timeoutErrorType         = "timeout_exception"
	indexNotFoundErrorType   = "index_not_found_exception"
	versionConflictErrorType = "version_conflict_engine_exception"
)

// TODO: Why do we have both ErrElastic and ErrorT?  Very strange.

type ErrElastic struct {
	Status int
	Type   string
	Reason string
	Cause  struct {
		Type   string
		Reason string
	}
}

func (e *ErrElastic) Unwrap() error {
	if e.Type == indexNotFoundErrorType {
		return ErrIndexNotFound
	} else if e.Type == timeoutErrorType {
		return ErrTimeout
	}

	return nil
}

func (e ErrElastic) Error() string {
	// Improved error string to account on missing empty e.Type and e.Reason
	// Otherwise were getting: "elastic fail 404::"
	msg := "elastic fail "
	var b strings.Builder
	b.Grow(len(msg) + 11 + len(e.Type) + len(e.Reason) + len(e.Cause.Type) + len(e.Cause.Reason))
	b.WriteString(msg)
	b.WriteString(strconv.Itoa(e.Status))
	if e.Type != "" {
		b.WriteString(": ")
		b.WriteString(e.Type)
	}
	if e.Reason != "" {
		b.WriteString(": ")
		b.WriteString(e.Reason)
	}
	if e.Cause.Type != "" {
		b.WriteString(": ")
		b.WriteString(e.Cause.Type)
	}
	if e.Cause.Reason != "" {
		b.WriteString(": ")
		b.WriteString(e.Cause.Reason)
	}
	return b.String()
}

var (
	ErrElasticVersionConflict = errors.New("elastic version conflict")
	ErrElasticNotFound        = errors.New("elastic not found")
	ErrInvalidBody            = errors.New("invalid body")
	ErrIndexNotFound          = errors.New("index not found")
	ErrTimeout                = errors.New("timeout")
	ErrNotFound               = errors.New("not found")

	knownErrorTypes = [3]string{
		timeoutErrorType,
		indexNotFoundErrorType,
		versionConflictErrorType,
	}

	// helps with native translation of native java exceptions
	// list possible exceptions is much broader, these we recognize.
	// all listed here: https://github.com/elastic/elasticsearch/blob/f8d1d2afa67afd1b9769751fde35f86c5ec885d9/server/src/main/java/org/elasticsearch/ElasticsearchException.java#L730
	errorTranslationMap = map[string]string{
		ErrIndexNotFound.Error():              indexNotFoundErrorType,
		"IndexNotFoundException":              indexNotFoundErrorType,
		ErrTimeout.Error():                    timeoutErrorType,
		"ElasticsearchTimeoutException":       timeoutErrorType,
		"ProcessClusterEventTimeoutException": timeoutErrorType,
		"ReceiveTimeoutTransportException":    timeoutErrorType,
		ErrElasticVersionConflict.Error():     versionConflictErrorType,
		"VersionConflictEngineException":      versionConflictErrorType,
	}
)

func TranslateError(status int, rawError json.RawMessage) error {
	if status == 200 || status == 201 {
		return nil
	}

	if len(rawError) == 0 {
		// error was omitted
		return &ErrElastic{
			Status: status,
		}
	}

	// try decoding detailed error by default
	detailedError := &ErrorT{}
	if err := json.Unmarshal(rawError, &detailedError); err == nil {
		return translateDetailedError(status, detailedError)
	}

	reason := string(rawError)
	eType := errType(reason)
	switch eType {
	case versionConflictErrorType:
		return ErrElasticVersionConflict
	default:
		return &ErrElastic{
			Status: status,
			Type:   eType,
			Reason: reason,
		}
	}
}

// ParseError attempts to interpret the response as an elastic error,
// otherwise return generic elastic error.
func ParseError(res *esapi.Response, log *zerolog.Logger) error {
	if log == nil {
		l := zerolog.Nop()
		log = &l
	}

	var e struct {
		Err json.RawMessage `json:"error"`
	}

	if res.Body != nil {
		decoder := json.NewDecoder(res.Body)

		if err := decoder.Decode(&e); err != nil {
			log.Error().Err(err).Msg("Cannot decode Elasticsearch error body")
			var b bytes.Buffer
			_, readErr := io.Copy(&b, res.Body)
			if readErr != nil {
				log.Debug().Err(readErr).Msg("Error reading error response body from Elasticsearch")
			} else {
				log.Debug().Err(err).Bytes("body", b.Bytes()).Msg("Error content")
			}

			return err
		}
	}

	return TranslateError(res.StatusCode, e.Err)
}

func errType(errBody string) string {
	for _, errCheck := range knownErrorTypes {
		if strings.Contains(errBody, errCheck) {
			return errCheck
		}
	}

	for errCheck, errType := range errorTranslationMap {
		if strings.Contains(errBody, errCheck) {
			return errType
		}
	}

	return unknownErrorType
}

func translateDetailedError(status int, e *ErrorT) error {
	if e == nil {
		return &ErrElastic{
			Status: status,
		}
	}

	var err error
	switch e.Type {
	case versionConflictErrorType:
		err = ErrElasticVersionConflict
	default:
		err = &ErrElastic{
			Status: status,
			Type:   e.Type,
			Reason: e.Reason,
			Cause: struct {
				Type   string
				Reason string
			}{
				Type:   e.Cause.Type,
				Reason: e.Cause.Reason,
			},
		}
	}

	return err
}
