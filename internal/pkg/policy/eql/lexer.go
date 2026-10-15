// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package eql

import (
	"errors"
	"strings"
)

type tokenKind int

// Token kinds in the priority order of Elastic Agent's ANTLR lexer
// (elastic-agent internal/pkg/eql/Eql.g4): on equal match length the earlier
// kind wins. The implicit parser literals ('|', ',', ':') come first.
const (
	tPipe tokenKind = iota
	tComma
	tColon
	tEQ
	tNEQ
	tGT
	tLT
	tGTE
	tLTE
	tAdd
	tSub
	tMul
	tDiv
	tMod
	tAnd
	tOr
	tTrue
	tFalse
	tFloat
	tNumber
	tWhitespace
	tNot
	tName
	tVName
	tSText
	tDText
	tLPar
	tRPar
	tLArr
	tRArr
	tLDict
	tRDict
	tBeginEVar
	tBeginVar
	tEOF
)

type token struct {
	kind tokenKind
	text string
}

var errLex = errors.New("unrecognized token")

var literalTokens = []struct {
	kind  tokenKind
	texts []string
}{
	{tPipe, []string{"|"}},
	{tComma, []string{","}},
	{tColon, []string{":"}},
	{tEQ, []string{"=="}},
	{tNEQ, []string{"!="}},
	{tGT, []string{">"}},
	{tLT, []string{"<"}},
	{tGTE, []string{">="}},
	{tLTE, []string{"<="}},
	{tAdd, []string{"+"}},
	{tSub, []string{"-"}},
	{tMul, []string{"*"}},
	{tDiv, []string{"/"}},
	{tMod, []string{"%"}},
	{tAnd, []string{"and", "AND"}},
	{tOr, []string{"or", "OR"}},
	{tTrue, []string{"true", "TRUE"}},
	{tFalse, []string{"false", "FALSE"}},
	{tNot, []string{"NOT", "not"}},
	{tLPar, []string{"("}},
	{tRPar, []string{")"}},
	{tLArr, []string{"["}},
	{tRArr, []string{"]"}},
	{tLDict, []string{"{"}},
	{tRDict, []string{"}"}},
	{tBeginEVar, []string{"$${"}},
	{tBeginVar, []string{"${"}},
}

// lex splits s into tokens, dropping whitespace. Any character the agent's
// lexer would reject is an error.
func lex(s string) ([]token, error) {
	var out []token
	for i := 0; i < len(s); {
		kind, n := longestMatch(s[i:])
		if n == 0 {
			return nil, errLex
		}
		if kind != tWhitespace {
			out = append(out, token{kind: kind, text: s[i : i+n]})
		}
		i += n
	}
	return append(out, token{kind: tEOF}), nil
}

func longestMatch(s string) (tokenKind, int) {
	best, bestLen := tEOF, 0
	consider := func(kind tokenKind, n int) {
		if n > bestLen || (n == bestLen && n > 0 && kind < best) {
			best, bestLen = kind, n
		}
	}
	for _, lt := range literalTokens {
		for _, text := range lt.texts {
			if strings.HasPrefix(s, text) {
				consider(lt.kind, len(text))
			}
		}
	}
	consider(tFloat, matchFloat(s))
	consider(tNumber, matchNumber(s))
	consider(tWhitespace, matchRun(s, isWhitespace))
	consider(tName, matchName(s))
	consider(tVName, matchVName(s))
	consider(tSText, matchQuoted(s, '\''))
	consider(tDText, matchQuoted(s, '"'))
	return best, bestLen
}

func isDigit(c byte) bool      { return c >= '0' && c <= '9' }
func isWhitespace(c byte) bool { return c == ' ' || c == '\r' || c == '\n' || c == '\t' }
func isNameStart(c byte) bool  { return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isNameChar(c byte) bool   { return isNameStart(c) || isDigit(c) }
func isVNameChar(c byte) bool  { return isNameChar(c) || c == '-' || c == '/' }

func matchRun(s string, ok func(byte) bool) int {
	n := 0
	for n < len(s) && ok(s[n]) {
		n++
	}
	return n
}

// NUMBER: [\-]? [0-9]+
func matchNumber(s string) int {
	sign := 0
	if strings.HasPrefix(s, "-") {
		sign = 1
	}
	n := matchRun(s[sign:], isDigit)
	if n == 0 {
		return 0
	}
	return sign + n
}

// FLOAT: [\-]? [0-9]+ '.' [0-9]+
func matchFloat(s string) int {
	n := matchNumber(s)
	if n == 0 || n >= len(s) || s[n] != '.' {
		return 0
	}
	frac := matchRun(s[n+1:], isDigit)
	if frac == 0 {
		return 0
	}
	return n + 1 + frac
}

// NAME: [a-zA-Z_] [a-zA-Z0-9_]*
func matchName(s string) int {
	if len(s) == 0 || !isNameStart(s[0]) {
		return 0
	}
	return 1 + matchRun(s[1:], isNameChar)
}

// VNAME: [a-zA-Z0-9_\-/]+ ('.' [a-zA-Z0-9_\-/]+)*
func matchVName(s string) int {
	n := matchRun(s, isVNameChar)
	if n == 0 {
		return 0
	}
	for n < len(s) && s[n] == '.' {
		seg := matchRun(s[n+1:], isVNameChar)
		if seg == 0 {
			break
		}
		n += 1 + seg
	}
	return n
}

// matchQuoted matches STEXT (single quotes) and DTEXT (double quotes): no
// escapes, and no CR, LF or closing quote inside.
func matchQuoted(s string, q byte) int {
	if len(s) == 0 || s[0] != q {
		return 0
	}
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case q:
			return i + 1
		case '\r', '\n':
			return 0
		}
	}
	return 0
}
