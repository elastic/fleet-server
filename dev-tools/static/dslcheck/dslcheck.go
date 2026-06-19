// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package dslcheck defines a go vet analyzer that reports *Tmpl variables
// that call Bind more times than renderPairsCap allows within a single function
// body. Exceeding the limit causes a panic in MustResolve at program startup.
package dslcheck

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const (
	dslPkgPath = "github.com/elastic/fleet-server/v7/internal/pkg/dsl"

	// fallbackRenderPairsCap is used when the dsl package is not a direct import
	// of the package under analysis (e.g., test stubs without the full module).
	fallbackRenderPairsCap = 8
)

// Analyzer reports *Tmpl variables with more than renderPairsCap Bind() calls
// in a single function body.
var Analyzer = &analysis.Analyzer{
	Name:     "dslcheck",
	Doc:      "reports dsl.Tmpl variables with more than renderPairsCap Bind() calls in one function",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
	renderCap := readRenderPairsCap(pass)
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	nodeFilter := []ast.Node{
		(*ast.FuncDecl)(nil),
		(*ast.FuncLit)(nil),
	}

	insp.Preorder(nodeFilter, func(n ast.Node) {
		var body *ast.BlockStmt
		switch fn := n.(type) {
		case *ast.FuncDecl:
			if fn.Body == nil {
				return
			}
			body = fn.Body
		case *ast.FuncLit:
			body = fn.Body
		}
		checkBody(pass, body, renderCap)
	})

	return nil, nil
}

// readRenderPairsCap looks up the renderPairsCap constant in the dsl package
// scope. It checks pass.Pkg itself (when analyzing dsl) and then its direct
// imports. Returns fallbackRenderPairsCap when the dsl package is not found.
func readRenderPairsCap(pass *analysis.Pass) int {
	var dslPkg *types.Package
	if pass.Pkg.Path() == dslPkgPath {
		dslPkg = pass.Pkg
	} else {
		for _, imp := range pass.Pkg.Imports() {
			if imp.Path() == dslPkgPath {
				dslPkg = imp
				break
			}
		}
	}
	if dslPkg == nil {
		return fallbackRenderPairsCap
	}
	obj := dslPkg.Scope().Lookup("renderPairsCap")
	if obj == nil {
		return fallbackRenderPairsCap
	}
	c, ok := obj.(*types.Const)
	if !ok {
		return fallbackRenderPairsCap
	}
	v, ok := constant.Int64Val(c.Val())
	if !ok {
		return fallbackRenderPairsCap
	}
	return int(v)
}

func checkBody(pass *analysis.Pass, body *ast.BlockStmt, renderCap int) {
	type callInfo struct {
		count int
		pos   []token.Pos
	}
	counts := make(map[types.Object]*callInfo)

	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Bind" {
			return true
		}
		if !isTmplPointer(pass, sel.X) {
			return true
		}
		obj := objectOf(pass, sel.X)
		if obj == nil {
			return true
		}
		if counts[obj] == nil {
			counts[obj] = &callInfo{}
		}
		ci := counts[obj]
		ci.count++
		ci.pos = append(ci.pos, call.Pos())
		return true
	})

	for obj, ci := range counts {
		if ci.count > renderCap {
			pass.Reportf(ci.pos[renderCap],
				"%s has %d Bind() calls in this function; renderPairsCap is %d",
				obj.Name(), ci.count, renderCap)
		}
	}
}

// isTmplPointer reports whether expr has type *Tmpl. The package path is not
// checked so that test stubs work without importing the full fleet-server module.
func isTmplPointer(pass *analysis.Pass, expr ast.Expr) bool {
	t := pass.TypesInfo.TypeOf(expr)
	if t == nil {
		return false
	}
	ptr, ok := t.(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := ptr.Elem().(*types.Named)
	if !ok {
		return false
	}
	return named.Obj().Name() == "Tmpl"
}

func objectOf(pass *analysis.Pass, expr ast.Expr) types.Object {
	id, ok := expr.(*ast.Ident)
	if !ok {
		return nil
	}
	return pass.TypesInfo.ObjectOf(id)
}
