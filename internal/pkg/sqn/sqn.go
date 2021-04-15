// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package sqn

import (
	"fmt"
	"strings"
)

const UndefinedSeqNo = -1

var DefaultSeqNo = []int64{UndefinedSeqNo}

// Abstracts the array of document seq numbers
type SeqNo []int64

func (s SeqNo) String() string {
	if len(s) == 0 {
		return ""
	}
	return strings.Join(strings.Fields(strings.Trim(fmt.Sprint([]int64(s)), "[]")), ",")
}

func (s SeqNo) IsSet() bool {
	return len(s) > 0 && s[0] >= 0
}

// Returns one/first value until we get and API to get the next checkpoints on search
func (s SeqNo) Value() int64 {
	if len(s) == 0 {
		return UndefinedSeqNo
	}
	return s[0]
}

func (s SeqNo) Clone() SeqNo {
	if s == nil {
		return nil
	}

	r := make(SeqNo, len(s))
	copy(r, s)
	return r
}
