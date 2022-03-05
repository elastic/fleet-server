// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dsl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/gofrs/uuid"
)

const kPrefix = "TMPL."
const kTokenSz = len(kPrefix) + 36 // len of uuid string

var (
	ErrTokenUndefined = errors.New("bound token not defined")
	ErrTokenNotFound  = errors.New("named token not found")
	ErrNotResolved    = errors.New("template not resolved")
)

type Tmpl struct {
	tmap map[string]Token
	sseq []sliceT
	bcnt int
}

type sliceT struct {
	name string
	data []byte
}

func NewTmpl() *Tmpl {
	return &Tmpl{
		tmap: make(map[string]Token),
	}
}

type Token string

func newToken() Token {
	u := uuid.Must(uuid.NewV4())
	t := fmt.Sprintf("%s%s", kPrefix, u.String())
	if len(t) != kTokenSz {
		panic("Size misalignment")
	}
	return Token(t)
}

func (t *Tmpl) Bind(name string) Token {
	token := newToken()
	t.tmap[name] = token
	return token
}

func (t *Tmpl) Resolve(n *Node) error {
	d, err := json.Marshal(n)
	if err != nil {
		return err
	}

	var sliceSeq []sliceT

	// Reverse name->token map
	rmap := make(map[Token]string, len(t.tmap))
	for name, token := range t.tmap {
		rmap[token] = name
	}

	// O(n) Scan d for each token;
	src := string(d)
	var sum int

	matches := make(map[Token]struct{})
	for v := strings.Index(src, kPrefix); v != -1; v = strings.Index(src, kPrefix) {

		var slice sliceT

		if v > 0 && src[v-1] == '"' && len(src) >= v+kTokenSz+1 && src[v+kTokenSz] == '"' {
			token := Token(src[v : v+kTokenSz])

			// Do we know about this token?
			if name, ok := rmap[token]; ok {

				matches[token] = struct{}{}
				slice.name = name
				slice.data = []byte(src[:v-1])
				src = src[v+kTokenSz+1:]
			}
		}

		// If we did not find a match, append up to index; this allows other strings with kPrefix to work.
		if slice.name == "" {
			slice.data = []byte(src[:v])
			src = src[v:]
		}

		sum += len(src)
		sliceSeq = append(sliceSeq, slice)
	}

	// Append slice for any remainder
	if len(src) > 0 {
		sum += len(src)
		sliceSeq = append(sliceSeq, sliceT{
			data: []byte(src),
		})
	}

	if len(matches) != len(rmap) {
		return ErrTokenUndefined
	}

	t.sseq = sliceSeq
	t.bcnt = sum
	return nil
}

func (t *Tmpl) MustResolve(n *Node) *Tmpl {
	err := t.Resolve(n)
	if err != nil {
		panic(err)
	}
	return t
}

// Convenience function to avoid map when only one token
func (t *Tmpl) RenderOne(name string, v interface{}) ([]byte, error) {
	d, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	m := map[string][]byte{name: d}
	return t.render(m, len(d))
}

func (t *Tmpl) Render(m map[string]interface{}) ([]byte, error) {

	// Marshal all targets, get byte count
	marshalMap := make(map[string][]byte, len(m))
	var sum int

	for name, v := range m {
		d, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		sum += len(d)
		marshalMap[name] = d
	}

	return t.render(marshalMap, sum)
}

func (t *Tmpl) MustRender(m map[string]interface{}) []byte {
	b, err := t.Render(m)
	if err != nil {
		panic(err)
	}
	return b
}

func (t *Tmpl) render(m map[string][]byte, sum int) ([]byte, error) {
	if t.sseq == nil {
		return nil, ErrNotResolved
	}

	// Allocate buffer for result
	var buf bytes.Buffer
	buf.Grow(sum + t.bcnt)

	// O(n) Iterate through sequences, render as expected
	for _, s := range t.sseq {
		buf.Write(s.data)
		if s.name != "" {
			d, ok := m[s.name]
			if !ok {
				return nil, ErrTokenNotFound
			}
			buf.Write(d)
		}
	}

	return buf.Bytes(), nil
}
