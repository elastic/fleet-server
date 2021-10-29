// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package sqn

import (
	"strconv"
	"strings"
)

const UndefinedSeqNo = -1

var DefaultSeqNo = []int64{UndefinedSeqNo}

// Abstracts the array of document seq numbers
type SeqNo []int64

func (s SeqNo) JSONString() string {
	return s.toString(true)
}

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
