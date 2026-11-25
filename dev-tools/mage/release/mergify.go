// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"
	"os"
	"strings"
)

// UpdateMergify adds a new backport rule to .mergify.yml.
// It appends the rule as text so existing comments and formatting are preserved.
func UpdateMergify(version string) error {
	mergifyFile := mergifyYMLPath

	content, err := os.ReadFile(mergifyFile)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", mergifyFile, err)
	}

	branchVersion, err := branchVersionFromRelease(version)
	if err != nil {
		return err
	}

	labelCondition := fmt.Sprintf("label=backport-%s", branchVersion)
	if mergifyHasExactLabelCondition(string(content), labelCondition) {
		printf("Backport rule for %s already exists\n", branchVersion)
		return nil
	}

	ruleName := fmt.Sprintf("backport patches to %s branch", branchVersion)
	newRule := fmt.Sprintf(`  - name: %s
    conditions:
      - %s
      - %s
    actions:
      backport:
        branches:
          - "%s"
`, ruleName, prStateMerged, labelCondition, branchVersion)

	trimmed := strings.TrimRight(string(content), "\n")
	updated := trimmed + "\n" + newRule

	if err := writeRepoFile(mergifyFile, []byte(updated)); err != nil {
		return fmt.Errorf("failed to write %s: %w", mergifyFile, err)
	}

	printf("Added backport rule for %s to %s\n", branchVersion, mergifyFile)
	return nil
}

// mergifyHasExactLabelCondition reports whether content already contains
// labelCondition as a full token (so label=backport-9.1 does not match
// label=backport-9.10).
func mergifyHasExactLabelCondition(content, labelCondition string) bool {
	for start := 0; start < len(content); {
		i := strings.Index(content[start:], labelCondition)
		if i < 0 {
			return false
		}
		abs := start + i
		end := abs + len(labelCondition)
		if end == len(content) || content[end] < '0' || content[end] > '9' {
			return true
		}
		start = abs + 1
	}
	return false
}
