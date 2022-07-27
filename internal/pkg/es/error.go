// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package es

import (
	"errors"
	"strconv"
	"strings"
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
)

func TranslateError(status int, e *ErrorT) error {
	if status == 200 || status == 201 {
		return nil
	}
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
