// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package sqn provides sequence numbers handling functions
package sqn

import (
	"strconv"
	"strings"
)

const UndefinedSeqNo = -1

var DefaultSeqNo = []int64{UndefinedSeqNo}

// SeqNo abstracts the array of document seq numbers.
type SeqNo []int64

// JSONString returns SeqNo as a JSON encoded array.
func (s SeqNo) JSONString() string {
	return s.toString(true)
}

// String returns SeqNo as a comma separated list.
func (s SeqNo) String() string {
	return s.toString(false)
}

func (s SeqNo) toString(withBrackets bool) string {
	if len(s) == 0 {
		if withBrackets {
			return "[]"
		} else {
			return ""
		}
	}
	var b strings.Builder

	first := strconv.FormatInt(s[0], 10)
	b.Grow(len(first)*len(s) + 2 + len(s))

	if withBrackets {
		b.WriteString("[")
	}
	b.WriteString(first)
	for i := 1; i < len(s); i++ {
		b.WriteString(",")
		b.WriteString(strconv.FormatInt(s[i], 10))
	}
	if withBrackets {
		b.WriteString("]")
	}
	return b.String()
}

// IsSet returns true when the SeqNo was initialized with a value.
func (s SeqNo) IsSet() bool {
	return len(s) > 0 && s[0] >= 0
}

// Value returns the first value in the sequence.
func (s SeqNo) Value() int64 {
	if len(s) == 0 {
		return UndefinedSeqNo
	}
	return s[0]
}

// Clone copies and returns SeqNo.
func (s SeqNo) Clone() SeqNo {
	if s == nil {
		return nil
	}

	r := make(SeqNo, len(s))
	copy(r, s)
	return r
}
