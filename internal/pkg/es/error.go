// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package es

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

const unknownErrorType = "unknown error"

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
	if e.Type == "index_not_found_exception" {
		return ErrIndexNotFound
	} else if e.Type == "timeout_exception" {
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

	errorCheckQueue = [6]string{
		ErrElasticVersionConflict.Error(),
		ErrElasticNotFound.Error(),
		ErrInvalidBody.Error(),
		ErrIndexNotFound.Error(),
		ErrTimeout.Error(),
		ErrNotFound.Error(),
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
	computedErr := &ErrElastic{
		Status: status,
		Type:   errType(reason),
		Reason: reason,
	}

	return computedErr
}

func errType(errBody string) string {
	for _, errCheck := range errorCheckQueue {
		if strings.Contains(errBody, errCheck) {
			return errCheck
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
	case "version_conflict_engine_exception":
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
