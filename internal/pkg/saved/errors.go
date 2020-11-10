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
