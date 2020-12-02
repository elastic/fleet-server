// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package saved

import (
	"errors"
)

var (
	ErrNoType              = errors.New("no type")
	ErrRead                = errors.New("read error")
	ErrNoId                = errors.New("no id")
	ErrAttributeUnknown    = errors.New("unknown attribute")
	ErrAttributeType       = errors.New("wrong attribute type")
	ErrBadCipherText       = errors.New("bad cipher text")
	ErrNotEncrypted        = errors.New("attribute not encrypted")
	ErrMalformedSavedObj   = errors.New("malformed saved object")
	ErrMalformedIdentifier = errors.New("malformed saved object identifier")
	ErrTypeMismatch        = errors.New("type mismatch")
	ErrSpaceMismatch       = errors.New("namespace mismatch")
)
