// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	devtools "github.com/elastic/fleet-server/v7/dev-tools/mage"
	"github.com/google/go-github/v68/github"
)

func TestReleaseIssueTitle(t *testing.T) {
	got := releaseIssueTitle("9.4.1")
	want := "[RELEASE 9.4.1] Instructions & Checklist"
	if got != want {
		t.Fatalf("releaseIssueTitle() = %q, want %q", got, want)
	}
}

func TestIsMajorMinorRelease(t *testing.T) {
	minor, err := devtools.ParseReleaseVersion(testVersion950)
	require.NoError(t, err)
	if !isMajorMinorRelease(&minor) {
		t.Fatal("expected 9.5.0 to be treated as major/minor")
	}
	patch, err := devtools.ParseReleaseVersion("9.5.1")
	require.NoError(t, err)
	if isMajorMinorRelease(&patch) {
		t.Fatal("expected 9.5.1 not to be treated as major/minor")
	}
}

func TestVersionMentioned(t *testing.T) {
	if !versionMentioned("[Release] Update version to 9.4.1", "9.4.1") {
		t.Fatal("exact version in title should match")
	}
	if versionMentioned("[Release] Update version to 9.4.10", "9.4.1") {
		t.Fatal("9.4.1 must not match 9.4.10")
	}
	if !versionMentioned("Add Fleet Server 9.4.1 release notes", "9.4.1") {
		t.Fatal("docs PR title should match")
	}
}

func TestBuildReleaseIssueBodyMajorMinorSection(t *testing.T) {
	minorBody := buildReleaseIssueBody(true, nil, nil)
	if !strings.Contains(minorBody, "### Only For Major/Minor Releases") {
		t.Fatal("minor release body should include major/minor section")
	}
	if !strings.Contains(minorBody, globalReleaseTrackerURL) {
		t.Fatal("body should link the global tracker")
	}
	if !strings.Contains(minorBody, "elastic/fleet-server/labels/release") {
		t.Fatal("body should link fleet-server release label")
	}

	patchBody := buildReleaseIssueBody(false, nil, nil)
	if strings.Contains(patchBody, "### Only For Major/Minor Releases") {
		t.Fatal("patch body should omit major/minor section")
	}
}

func TestMergePRURLsSortsAndDedups(t *testing.T) {
	got := mergePRURLs(
		[]string{testPRURL20, testPRURL10},
		[]string{testPRURL10, testPRURL15},
	)
	want := []string{
		testPRURL10,
		testPRURL15,
		testPRURL20,
	}
	if len(got) != len(want) {
		t.Fatalf("mergePRURLs() len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("mergePRURLs()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestExtractPRCheckboxes(t *testing.T) {
	body := `
## PRs

- [x] ` + testPRURL10 + `
- [ ] ` + testPRURL11 + `
`
	got := extractPRCheckboxes(body)
	if !got[testPRURL10] {
		t.Fatal("checked PR should be true")
	}
	if got[testPRURL11] {
		t.Fatal("unchecked PR should be false")
	}
}

func TestMergeReleaseIssueBodyAddsMissingPRsAndPreservesChecks(t *testing.T) {
	existing := `Global tracker: https://github.com/elastic/ingest-dev/issues/8866

# Release Checklist

- [x] Find the Fleet Server release PRs

## PRs

- [x] ` + testPRURL10 + `
- [ ] ` + testPRURL11 + `
`
	updated, changed := mergeReleaseIssueBody(existing, false, []string{
		testPRURL11,
		testPRURL12,
	})
	if !changed {
		t.Fatal("adding a missing PR should mark the body changed")
	}
	if !strings.Contains(updated, "- [x] "+testPRURL10) {
		t.Fatal("existing checked PR must stay checked")
	}
	if !strings.Contains(updated, "- [ ] "+testPRURL11) {
		t.Fatal("existing unchecked PR stays unchecked")
	}
	if !strings.Contains(updated, "- [ ] "+testPRURL12) {
		t.Fatal("new PR should be appended unchecked")
	}
	if !strings.Contains(updated, "- [x] Find the Fleet Server release PRs") {
		t.Fatal("non-PR checklist state must be preserved")
	}

	_, changedAgain := mergeReleaseIssueBody(updated, false, []string{
		testPRURL10,
		testPRURL11,
		testPRURL12,
	})
	if changedAgain {
		t.Fatal("second merge with same PRs should be a no-op")
	}
}

func TestMergeReleaseIssueBodyAddsTrackerWhenMissing(t *testing.T) {
	existing := `# Release Checklist

## PRs

- [ ] https://github.com/elastic/fleet-server/pull/10
`
	updated, changed := mergeReleaseIssueBody(existing, false, []string{testPRURL10})
	if !changed {
		t.Fatal("missing global tracker should trigger an update")
	}
	if !strings.HasPrefix(strings.TrimSpace(updated), "Global tracker: "+globalReleaseTrackerURL) {
		t.Fatalf("tracker link should be prepended, got prefix %q", updated[:min(80, len(updated))])
	}
}

func TestMergeReleaseIssueBodyPreservesTrailingSections(t *testing.T) {
	existing := `Global tracker: https://github.com/elastic/ingest-dev/issues/8866

# Release Checklist

- [ ] Find the Fleet Server release PRs

## PRs

- [x] ` + testPRURL10 + `

## Notes

Operator note: keep this section.
`
	updated, changed := mergeReleaseIssueBody(existing, false, []string{
		testPRURL10,
		testPRURL11,
	})
	if !changed {
		t.Fatal("adding a missing PR should mark the body changed")
	}
	if !strings.Contains(updated, "- [ ] "+testPRURL11) {
		t.Fatal("new PR should be appended")
	}
	if !strings.Contains(updated, "## Notes") {
		t.Fatal("trailing ## Notes section must be preserved")
	}
	if !strings.Contains(updated, "Operator note: keep this section.") {
		t.Fatal("trailing notes text must be preserved")
	}

	again, changedAgain := mergeReleaseIssueBody(updated, false, []string{
		testPRURL10,
		testPRURL11,
	})
	if changedAgain {
		t.Fatal("second merge with same PRs should be a no-op")
	}
	if !strings.Contains(again, "## Notes") {
		t.Fatal("trailing section must remain after no-op merge")
	}
}

func TestEnsureReleaseIssueTrackerDryRun(t *testing.T) {
	cfg := &ReleaseConfig{
		NextRelease: "9.4.1",
		DryRun:      true,
	}
	pr := &github.PullRequest{HTMLURL: new("https://github.com/elastic/fleet-server/pull/99")}
	require.NoError(t, EnsureReleaseIssueTracker(cfg, []*github.PullRequest{pr}))
}

func TestWarnEnsureReleaseIssueTrackerDoesNotPanicOnError(t *testing.T) {
	warnEnsureReleaseIssueTracker(&ReleaseConfig{}, nil)
}

func TestPrURLsFromPullRequestsSkipsNil(t *testing.T) {
	got := prURLsFromPullRequests([]*github.PullRequest{
		nil,
		{HTMLURL: new("https://github.com/elastic/fleet-server/pull/1")},
	})
	if len(got) != 1 || got[0] != "https://github.com/elastic/fleet-server/pull/1" {
		t.Fatalf("unexpected URLs: %v", got)
	}
}
