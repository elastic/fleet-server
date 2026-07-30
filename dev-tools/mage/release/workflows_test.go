// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"strings"
	"testing"
)

func TestLabelHelpers(t *testing.T) {
	if got := backportLabel("9.6"); got != "backport-9.6" {
		t.Fatalf("backportLabel = %q", got)
	}

	labels := prAMainLabels("9.6")
	if !contains(labels, mergeLabelFFDay) || !contains(labels, "backport-9.6") {
		t.Fatalf("prAMainLabels = %v", labels)
	}
	if contains(labels, mergeLabelAfterImages) {
		t.Fatal("PR-A must not include merge:3-after-images (PR-C omitted)")
	}

	if !contains(prBReleaseLabels(), mergeLabelAfterBranch) {
		t.Fatal("PR-B missing merge:2-after-branch")
	}
	if !contains(prDNextPatchLabels(), mergeLabelAfterRelease) {
		t.Fatal("PR-D missing merge:4-after-release")
	}
	if !contains(patchBeforeBuildPRLabels(), mergeLabelBeforeBuild) {
		t.Fatal("patch PR-A missing merge:1-before-build")
	}
}

func TestPRBodiesMentionFleetScope(t *testing.T) {
	cfg := &ReleaseConfig{
		CurrentRelease:          "9.6.0",
		NextRelease:             "9.6.1",
		NextProjectMinorVersion: "9.7.0",
		BaseBranch:              "main",
		ReleaseBranch:           "9.6",
	}

	if !strings.Contains(prAMainBody(cfg), "version/version.go") {
		t.Fatal("PR-A body missing version.go mention")
	}
	if !strings.Contains(prBReleaseBody(cfg), "no docs/test-env") {
		t.Fatal("PR-B body should note missing docs/test-env")
	}
	if !strings.Contains(prDNextPatchBody(cfg), "9.6.1") {
		t.Fatal("PR-D body missing next patch")
	}
	if !strings.Contains(patchBeforeBuildPRBody("9.6.1"), "often empty") {
		t.Fatal("patch PR-A body should note often-empty PR")
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
