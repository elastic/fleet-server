// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package eql

import (
	"errors"
	"strconv"
)

var (
	errSyntax   = errors.New("syntax error")
	errTooDeep  = errors.New("expression nested too deeply")
	errTooLarge = errors.New("expression too large")
)

const (
	maxDepth = 64
	maxLen   = 4096
)

type node any

type (
	litNode  struct{ v any } // constant, array or dict literal
	varEntry struct {
		name  string // variable name; empty for a constant
		value any    // constant value when name is empty
	}
	varNode  struct{ entries []varEntry } // ${a|b|'c'}
	evarNode struct{}                     // $${...}, always an error in a condition
	notNode  struct{ x node }
	binNode  struct {
		op   tokenKind
		l, r node
	}
	funcNode struct{} // function call; never evaluated here
)

// Binary operator precedence, following the order of the alternatives in the
// grammar's left-recursive exp rule: each operator has its own level and is
// left-associative. A higher number binds tighter.
var binaryPrec = map[tokenKind]int{
	tMul: 13, tDiv: 13, tMod: 13,
	tAdd: 12, tSub: 12,
	tEQ:  10,
	tNEQ: 9,
	tLTE: 8,
	tGTE: 7,
	tLT:  6,
	tGT:  5,
	tAnd: 4,
	tOr:  3,
}

// precNot is the level of the prefix NOT alternative, between AddSub and EQ.
const precNot = 11

type parser struct {
	toks  []token
	pos   int
	depth int
}

func parse(s string) (node, error) {
	if s == "" {
		return nil, errSyntax
	}
	if len(s) > maxLen {
		return nil, errTooLarge
	}
	toks, err := lex(s)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	n, err := p.exp(0)
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tEOF {
		return nil, errSyntax
	}
	return n, nil
}

func (p *parser) peek() token { return p.toks[p.pos] }

func (p *parser) next() token {
	t := p.toks[p.pos]
	if t.kind != tEOF {
		p.pos++
	}
	return t
}

func (p *parser) expect(k tokenKind) error {
	if p.next().kind != k {
		return errSyntax
	}
	return nil
}

func (p *parser) exp(minPrec int) (node, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxDepth {
		return nil, errTooDeep
	}

	left, err := p.primary()
	if err != nil {
		return nil, err
	}
	for {
		op := p.peek().kind
		prec, ok := binaryPrec[op]
		if !ok || prec < minPrec {
			return left, nil
		}
		p.next()
		right, err := p.exp(prec + 1)
		if err != nil {
			return nil, err
		}
		left = binNode{op: op, l: left, r: right}
	}
}

func (p *parser) primary() (node, error) {
	t := p.next()
	switch t.kind {
	case tLPar:
		n, err := p.exp(0)
		if err != nil {
			return nil, err
		}
		return n, p.expect(tRPar)
	case tNot:
		n, err := p.exp(precNot)
		if err != nil {
			return nil, err
		}
		return notNode{x: n}, nil
	case tTrue, tFalse, tSText, tDText, tFloat, tNumber:
		v, err := constantValue(t)
		if err != nil {
			return nil, err
		}
		return litNode{v: v}, nil
	case tBeginVar:
		entries, err := p.variableExp()
		if err != nil {
			return nil, err
		}
		return varNode{entries: entries}, p.expect(tRDict)
	case tBeginEVar:
		if _, err := p.variableExp(); err != nil {
			return nil, err
		}
		return evarNode{}, p.expect(tRDict)
	case tName:
		if err := p.expect(tLPar); err != nil {
			return nil, err
		}
		if p.peek().kind != tRPar {
			if err := p.arguments(); err != nil {
				return nil, err
			}
		}
		return funcNode{}, p.expect(tRPar)
	case tLArr:
		arr := []any{}
		if p.peek().kind != tRArr {
			for {
				v, err := constantValue(p.next())
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
				if p.peek().kind != tComma {
					break
				}
				p.next()
			}
		}
		return litNode{v: arr}, p.expect(tRArr)
	case tLDict:
		dict := map[string]any{}
		if p.peek().kind != tRDict {
			for {
				k := p.next()
				var key string
				switch k.kind {
				case tName:
					key = k.text
				case tSText, tDText:
					key = unquote(k.text)
				default:
					return nil, errSyntax
				}
				if err := p.expect(tColon); err != nil {
					return nil, err
				}
				v, err := constantValue(p.next())
				if err != nil {
					return nil, err
				}
				dict[key] = v
				if p.peek().kind != tComma {
					break
				}
				p.next()
			}
		}
		return litNode{v: dict}, p.expect(tRDict)
	}
	return nil, errSyntax
}

func (p *parser) arguments() error {
	for {
		if _, err := p.exp(0); err != nil {
			return err
		}
		if p.peek().kind != tComma {
			return nil
		}
		p.next()
	}
}

// variableExp: variable ('|' variable)*, where variable is NAME, VNAME or a constant.
func (p *parser) variableExp() ([]varEntry, error) {
	var entries []varEntry
	for {
		t := p.next()
		switch t.kind {
		case tName, tVName:
			entries = append(entries, varEntry{name: t.text})
		default:
			v, err := constantValue(t)
			if err != nil {
				return nil, err
			}
			entries = append(entries, varEntry{value: v})
		}
		if p.peek().kind != tPipe {
			return entries, nil
		}
		p.next()
	}
}

func constantValue(t token) (any, error) {
	switch t.kind {
	case tSText, tDText:
		return unquote(t.text), nil
	case tTrue:
		return true, nil
	case tFalse:
		return false, nil
	case tNumber:
		i, err := strconv.Atoi(t.text)
		if err != nil {
			return nil, errSyntax
		}
		return i, nil
	case tFloat:
		f, err := strconv.ParseFloat(t.text, 64)
		if err != nil {
			return nil, errSyntax
		}
		return f, nil
	}
	return nil, errSyntax
}

// unquote strips the surrounding quotes, as the agent's toStr does.
func unquote(s string) string {
	if len(s) <= 2 {
		return ""
	}
	return s[1 : len(s)-1]
}
