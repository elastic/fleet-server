// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dsl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/gofrs/uuid/v5"
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

// namedBytes pairs a token name with its marshaled value, used in renderPairs
// to avoid map allocations on the hot render path.
type namedBytes struct {
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

		sum += len(slice.data)
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

// RenderOne is a convenience function when only one token needs substitution.
// It uses a stack-allocated [1]namedBytes to avoid a heap map allocation.
func (t *Tmpl) RenderOne(name string, v any) ([]byte, error) {
	d, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var pair [1]namedBytes
	pair[0] = namedBytes{name, d}
	return t.renderPairs(pair[:], len(d))
}

func (t *Tmpl) Render(m map[string]any) ([]byte, error) {
	pairs := make([]namedBytes, 0, len(m)*2)
	var sum int

	for name, v := range m {
		d, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		sum += len(d)
		pairs = append(pairs, namedBytes{name, d})
	}

	return t.renderPairs(pairs, sum)
}

func (t *Tmpl) MustRender(m map[string]any) []byte {
	b, err := t.Render(m)
	if err != nil {
		panic(err)
	}
	return b
}

// renderPairs writes the resolved template into a bytes.Buffer, substituting
// named tokens via a linear scan over pairs (O(n*m) where n is the number of
// template slices and m is the number of tokens; both are small for all
// templates in this codebase).
func (t *Tmpl) renderPairs(pairs []namedBytes, sum int) ([]byte, error) {
	if t.sseq == nil {
		return nil, ErrNotResolved
	}

	var buf bytes.Buffer
	buf.Grow(sum + t.bcnt)

	for _, s := range t.sseq {
		buf.Write(s.data)
		if s.name != "" {
			var found bool
			for _, p := range pairs {
				if p.name == s.name {
					buf.Write(p.data)
					found = true
					break
				}
			}
			if !found {
				return nil, ErrTokenNotFound
			}
		}
	}

	return buf.Bytes(), nil
}
