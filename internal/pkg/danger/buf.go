// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package danger

// Effectively golang's string builder with a Reset option

import (
	"unicode/utf8"
)

type Buf struct {
	buf []byte
}

func (b *Buf) Bytes() []byte {
	return b.buf
}

func (b *Buf) Set(s []byte) {
	b.buf = s
}

func (b *Buf) Len() int { return len(b.buf) }

func (b *Buf) Cap() int { return cap(b.buf) }

func (b *Buf) Reset() {
	b.buf = b.buf[:0]
}

func (b *Buf) grow(n int) {
	buf := make([]byte, len(b.buf), 2*cap(b.buf)+n)
	copy(buf, b.buf)
	b.buf = buf
}

func (b *Buf) Grow(n int) {
	if n < 0 {
		panic("danger.Buf.Grow: negative count")
	}
	if cap(b.buf)-len(b.buf) < n {
		b.grow(n)
	}
}

// Write appends the contents of p to b's buffer.
// Write always returns len(p), nil.
func (b *Buf) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p...)
	return len(p), nil
}

// WriteByte appends the byte c to b's buffer.
// The returned error is always nil.
func (b *Buf) WriteByte(c byte) error {
	b.buf = append(b.buf, c)
	return nil
}

// WriteRune appends the UTF-8 encoding of Unicode code point r to b's buffer.
// It returns the length of r and a nil error.
func (b *Buf) WriteRune(r rune) (int, error) {
	if r < utf8.RuneSelf {
		b.buf = append(b.buf, byte(r))
		return 1, nil
	}
	l := len(b.buf)
	if cap(b.buf)-l < utf8.UTFMax {
		b.grow(utf8.UTFMax)
	}
	n := utf8.EncodeRune(b.buf[l:l+utf8.UTFMax], r)
	b.buf = b.buf[:l+n]
	return n, nil
}

// WriteString appends the contents of s to b's buffer.
// It returns the length of s and a nil error.
func (b *Buf) WriteString(s string) (int, error) {
	b.buf = append(b.buf, s...)
	return len(s), nil
}
