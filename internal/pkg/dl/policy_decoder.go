// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf8"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

// minSharedLen is the length, in bytes, below which a string value is not worth sharing.
//
// Sharing only pays off when the memory saved by dropping a duplicate is bigger than what the
// table spends remembering the string (a string header, an interface value and map overhead), and
// that cost is paid for every distinct string, including the many short identifiers and flags that
// never repeat enough to matter. Long strings are where the duplicated bytes are (for example
// osquery queries), so only those are tracked. This also keeps the table, and with it the memory
// used while decoding, small when the policies share little.
var minSharedLen = 64

// maxSharedStrings caps how many distinct values, and separately how many distinct keys, a
// PolicyDecoder remembers. It bounds the table's own memory when a batch holds very many distinct
// strings (a search can return thousands of policies). Once the cap is reached, strings already in
// the table are still shared and new ones are decoded as usual.
var maxSharedStrings = 1 << 16

// PolicyDecoder decodes policy documents like es.HitT.Unmarshal does, except that equal long string
// values and equal map keys are shared as they are decoded, across every document the decoder
// decodes.
//
// Why: the policy monitor keeps the decoded form of every policy in memory, and policies of one
// deployment often repeat large parts of their content (for example the same osquery pack queries
// in many policies). encoding/json allocates a new copy of every string it reads, so each repeat
// is a full extra copy. Sharing afterwards would free that memory only once the whole batch had
// been decoded, so all the duplicates would still exist at the same time and peak memory would not
// drop. Here a string that has been seen before is looked up straight from the source bytes, which
// does not allocate, so a duplicate never gets a second copy.
//
// How: encoding/json decodes everything in a policy except its inputs, which hold nearly all of the
// content. The inputs are decoded by a small parser (see parser) that produces the same values
// encoding/json would for an `any` (map[string]any, []any, string, float64, bool, nil) and shares
// strings while doing so. Tests compare the result with encoding/json's, including a fuzz test.
//
// A decoder has no locking and is meant for one batch of documents decoded together, which are then
// kept together; use a new decoder for the next batch. Sharing does not outlive the decoder, so
// strings in a later batch are not shared with copies held from an earlier one.
type PolicyDecoder struct {
	values map[string]any
	keys   map[string]string
}

// NewPolicyDecoder returns a decoder with an empty sharing table.
func NewPolicyDecoder() *PolicyDecoder {
	return &PolicyDecoder{values: map[string]any{}, keys: map[string]string{}}
}

// policyDoc and policyData mirror model.Policy and model.PolicyData, replacing only the field that
// holds most of a policy's content (the inputs). encoding/json uses the shallowest field of a given
// name, so these fields hide the embedded ones and everything else decodes as usual. model.Policy is
// generated from the schema, so it is embedded here instead of being changed.
type policyDoc struct {
	model.Policy
	Data *policyData `json:"data"`
}

type policyData struct {
	model.PolicyData
	Inputs *sharedInputs `json:"inputs,omitempty"`
}

// sharedInputs decodes the inputs array with the PolicyDecoder's parser instead of encoding/json.
// encoding/json hands UnmarshalJSON the exact bytes of the value, which it has already checked are
// valid JSON.
type sharedInputs struct {
	dec   *PolicyDecoder
	items []map[string]any
}

func (s *sharedInputs) UnmarshalJSON(b []byte) error {
	items, err := s.dec.decodeInputs(b)
	s.items = items
	return err
}

// Decode decodes hit into p, like hit.Unmarshal(p) but sharing strings with the other documents this
// decoder has decoded.
func (d *PolicyDecoder) Decode(hit es.HitT, p *model.Policy) error {
	doc := policyDoc{Data: &policyData{Inputs: &sharedInputs{dec: d}}}
	if err := json.Unmarshal(hit.Source, &doc); err != nil {
		return err
	}
	*p = doc.Policy
	if doc.Data != nil {
		data := doc.Data.PolicyData
		if doc.Data.Inputs != nil {
			data.Inputs = doc.Data.Inputs.items
		}
		p.Data = &data
	}
	p.ESInitialize(hit.ID, hit.SeqNo, hit.Version)
	return nil
}

func (d *PolicyDecoder) decodeInputs(b []byte) ([]map[string]any, error) {
	p := parser{dec: d, b: b}
	p.skipSpace()
	if p.eof() {
		return nil, errUnexpectedEnd
	}
	if p.b[p.i] == 'n' {
		return nil, p.literal(literalNull)
	}
	if p.b[p.i] != '[' {
		return nil, fmt.Errorf("inputs: expected an array at offset %d", p.i)
	}
	p.i++
	items := []map[string]any{}
	p.skipSpace()
	if !p.eof() && p.b[p.i] == ']' {
		return items, nil
	}
	for {
		p.skipSpace()
		if p.eof() {
			return nil, errUnexpectedEnd
		}
		if p.b[p.i] == 'n' {
			if err := p.literal(literalNull); err != nil {
				return nil, err
			}
			items = append(items, nil)
		} else {
			m, err := p.object()
			if err != nil {
				return nil, err
			}
			items = append(items, m)
		}
		p.skipSpace()
		if p.eof() {
			return nil, errUnexpectedEnd
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case ']':
			return items, nil
		default:
			return nil, fmt.Errorf("inputs: unexpected %q at offset %d", p.b[p.i], p.i)
		}
	}
}

const literalNull = "null"

var errUnexpectedEnd = errors.New("unexpected end of JSON input")

// parser reads already validated JSON (encoding/json checks the whole document before it calls
// UnmarshalJSON) into the same Go values encoding/json produces for an `any`: map[string]any,
// []any, string, float64, bool and nil. It still returns an error instead of panicking if it meets
// input that is not valid.
type parser struct {
	dec *PolicyDecoder
	b   []byte
	i   int
}

func (p *parser) eof() bool { return p.i >= len(p.b) }

func (p *parser) skipSpace() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) literal(word string) error {
	if !bytes.HasPrefix(p.b[p.i:], []byte(word)) {
		return fmt.Errorf("expected %q at offset %d", word, p.i)
	}
	p.i += len(word)
	return nil
}

func (p *parser) value() (any, error) {
	p.skipSpace()
	if p.eof() {
		return nil, errUnexpectedEnd
	}
	switch c := p.b[p.i]; c {
	case '{':
		return p.object()
	case '[':
		return p.array()
	case '"':
		raw, quoted, escaped, err := p.str()
		if err != nil {
			return nil, err
		}
		return p.dec.value(raw, quoted, escaped), nil
	case 't':
		return true, p.literal("true")
	case 'f':
		return false, p.literal("false")
	case 'n':
		return nil, p.literal(literalNull)
	default:
		return p.number()
	}
}

func (p *parser) object() (map[string]any, error) {
	if p.eof() || p.b[p.i] != '{' {
		return nil, fmt.Errorf("expected an object at offset %d", p.i)
	}
	p.i++
	m := map[string]any{}
	p.skipSpace()
	if !p.eof() && p.b[p.i] == '}' {
		p.i++
		return m, nil
	}
	for {
		p.skipSpace()
		if p.eof() || p.b[p.i] != '"' {
			return nil, fmt.Errorf("expected a key at offset %d", p.i)
		}
		raw, quoted, escaped, err := p.str()
		if err != nil {
			return nil, err
		}
		key := p.dec.key(raw, quoted, escaped)
		p.skipSpace()
		if p.eof() || p.b[p.i] != ':' {
			return nil, fmt.Errorf("expected ':' at offset %d", p.i)
		}
		p.i++
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		m[key] = v
		p.skipSpace()
		if p.eof() {
			return nil, errUnexpectedEnd
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return m, nil
		default:
			return nil, fmt.Errorf("unexpected %q at offset %d", p.b[p.i], p.i)
		}
	}
}

func (p *parser) array() ([]any, error) {
	p.i++ // '['
	arr := []any{}
	p.skipSpace()
	if !p.eof() && p.b[p.i] == ']' {
		p.i++
		return arr, nil
	}
	for {
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
		p.skipSpace()
		if p.eof() {
			return nil, errUnexpectedEnd
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return arr, nil
		default:
			return nil, fmt.Errorf("unexpected %q at offset %d", p.b[p.i], p.i)
		}
	}
}

// str reads the string starting at p.i. It returns the bytes between the quotes, the bytes
// including the quotes (needed to unquote strings with escapes) and whether there were escapes.
// Most strings have no escapes, so it first tries a fast path made of two vectorized byte searches;
// scanning byte by byte made decoding about 30% slower.
func (p *parser) str() (raw, quoted []byte, escaped bool, err error) {
	start := p.i
	// Fast path: most strings have no escapes. Find the closing quote and check that nothing
	// before it is a backslash, both with vectorized byte searches.
	if q := bytes.IndexByte(p.b[start+1:], '"'); q >= 0 && bytes.IndexByte(p.b[start+1:start+1+q], '\\') < 0 {
		p.i = start + 1 + q + 1
		return p.b[start+1 : p.i-1], p.b[start:p.i], false, nil
	}
	p.i++ // opening quote
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case '\\':
			escaped = true
			p.i += 2
		case '"':
			p.i++
			return p.b[start+1 : p.i-1], p.b[start:p.i], escaped, nil
		default:
			p.i++
		}
	}
	return nil, nil, false, errUnexpectedEnd
}

func (p *parser) number() (any, error) {
	start := p.i
	for p.i < len(p.b) {
		c := p.b[p.i]
		if (c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E' {
			p.i++
			continue
		}
		break
	}
	f, err := strconv.ParseFloat(string(p.b[start:p.i]), 64)
	if err != nil {
		return nil, fmt.Errorf("number %q: %w", p.b[start:p.i], err)
	}
	return f, nil
}

// unquote decodes a JSON string with escapes (or invalid UTF-8) the way encoding/json does, so that
// the rare strings that are not plain text get exactly the value encoding/json would give them.
func unquote(quoted []byte) string {
	var s string
	_ = json.Unmarshal(quoted, &s) // quoted was validated by encoding/json already
	return s
}

// value returns the string as an `any`, sharing it when it is long enough. The table stores the
// `any` rather than the string, so handing out a shared value does not allocate to box it again.
func (d *PolicyDecoder) value(raw, quoted []byte, escaped bool) any {
	if escaped || !utf8.Valid(raw) {
		s := unquote(quoted)
		if len(s) < minSharedLen {
			return s
		}
		if v, ok := d.values[s]; ok {
			return v
		}
		var boxed any = s
		if len(d.values) < maxSharedStrings {
			d.values[s] = boxed
		}
		return boxed
	}
	if len(raw) < minSharedLen {
		return string(raw)
	}
	if v, ok := d.values[string(raw)]; ok { // no allocation when the string is already known
		return v
	}
	s := string(raw)
	var boxed any = s
	if len(d.values) < maxSharedStrings {
		d.values[s] = boxed
	}
	return boxed
}

// key returns the map key, shared with every other occurrence.
func (d *PolicyDecoder) key(raw, quoted []byte, escaped bool) string {
	if escaped || !utf8.Valid(raw) {
		return unquote(quoted)
	}
	if k, ok := d.keys[string(raw)]; ok {
		return k
	}
	k := string(raw)
	if len(d.keys) < maxSharedStrings {
		d.keys[k] = k
	}
	return k
}
