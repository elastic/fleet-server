// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package ok contains cases that must not trigger dslcheck.
package ok

import "example.com/dslcheck-testdata/stub"

func Exactly8() {
	tmpl := stub.NewTmpl()
	tmpl.Bind("a")
	tmpl.Bind("b")
	tmpl.Bind("c")
	tmpl.Bind("d")
	tmpl.Bind("e")
	tmpl.Bind("f")
	tmpl.Bind("g")
	tmpl.Bind("h")
}

func OneToken() {
	tmpl := stub.NewTmpl()
	tmpl.Bind("x")
}

func TwoTemplates() {
	t1 := stub.NewTmpl()
	t2 := stub.NewTmpl()
	t1.Bind("a")
	t1.Bind("b")
	t1.Bind("c")
	t1.Bind("d")
	t1.Bind("e")
	t2.Bind("a")
	t2.Bind("b")
	t2.Bind("c")
	t2.Bind("d")
	t2.Bind("e")
}
