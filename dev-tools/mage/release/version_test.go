// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import "testing"

func TestSelectLatestReleaseBefore(t *testing.T) {
	versions := []string{"9.4.0", "9.4.3", "9.5.0", "v9.3.2", "8.19.1", "not-a-version"}
	got, err := selectLatestReleaseBefore(versions, "9.5.0")
	if err != nil {
		t.Fatalf("selectLatestReleaseBefore() error = %v", err)
	}
	if got != "9.4.3" {
		t.Errorf("selectLatestReleaseBefore() = %s, want 9.4.3", got)
	}
}

func TestParseSemverRejectsSignedComponents(t *testing.T) {
	for _, version := range []string{"-1.0.0", "+9.6.0", "9.-1.0", "9.6.+1", "9.foo.0"} {
		if _, err := parseSemver(version); err == nil {
			t.Errorf("parseSemver(%q) expected error", version)
		}
	}
	got, err := parseSemver("9.6.0")
	if err != nil {
		t.Fatalf("parseSemver(9.6.0) error = %v", err)
	}
	if got.String() != "9.6.0" {
		t.Errorf("parseSemver(9.6.0) = %s, want 9.6.0", got.String())
	}
}

func TestBranchVersionFromRelease(t *testing.T) {
	got, err := branchVersionFromRelease("9.5.0")
	if err != nil {
		t.Fatalf("branchVersionFromRelease(9.5.0) error = %v", err)
	}
	if got != "9.5" {
		t.Errorf("branchVersionFromRelease(9.5.0) = %q, want 9.5", got)
	}
	got, err = branchVersionFromRelease("9.5")
	if err != nil {
		t.Fatalf("branchVersionFromRelease(9.5) error = %v", err)
	}
	if got != "9.5" {
		t.Errorf("branchVersionFromRelease(9.5) = %q, want 9.5", got)
	}
	for _, version := range []string{"9.foo", "9.foo.0", "-1.2", "9.+1.0"} {
		if _, err := branchVersionFromRelease(version); err == nil {
			t.Errorf("branchVersionFromRelease(%q) expected error", version)
		}
	}
}
