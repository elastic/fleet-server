// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package es

import (
	"errors"
	"fmt"
)

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
	}
	return nil
}

func (e ErrElastic) Error() string {
	return fmt.Sprintf("elastic fail %d:%s:%s", e.Status, e.Type, e.Reason)
}

var (
	ErrElasticVersionConflict = errors.New("elastic version conflict")
	ErrElasticNotFound        = errors.New("elastic not found")
	ErrInvalidBody            = errors.New("invalid body")
	ErrIndexNotFound          = errors.New("index not found")
)

func TranslateError(status int, e ErrorT) error {
	if status == 200 || status == 201 {
		return nil
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
				e.Cause.Type,
				e.Cause.Reason,
			},
		}
	}

	return err
}
