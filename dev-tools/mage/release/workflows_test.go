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
	if !contains(patchVersionBumpLabels(), mergeLabelAfterRelease) {
		t.Fatal("patch bump labels missing merge:4-after-release")
	}
	if contains(patchVersionBumpLabels(), "docs") {
		t.Fatal("patch bump must not include docs label")
	}
}

func TestPRBodiesMentionFleetScope(t *testing.T) {
	cfg := &ReleaseConfig{
		CurrentRelease:          "9.6.1",
		LatestRelease:           "9.6.0",
		NextRelease:             "9.6.2",
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
	body := patchVersionBumpBody(cfg)
	if !strings.Contains(body, "to 9.6.1") {
		t.Fatal("patch bump body missing landing version 9.6.1")
	}
	if strings.Contains(body, "Merge after the release of") {
		t.Fatal("patch bump body must not park with Merge-after-release wording")
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
