// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// UpdateMergify adds a new backport rule to .mergify.yml.
func UpdateMergify(version string) error {
	mergifyFile := ".mergify.yml"

	content, err := os.ReadFile(mergifyFile)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", mergifyFile, err)
	}

	var config map[string]interface{}
	if err := yaml.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("failed to parse %s: %w", mergifyFile, err)
	}

	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return fmt.Errorf("invalid version format: %s (expected X.Y.Z)", version)
	}
	branchVersion := fmt.Sprintf("%s.%s", parts[0], parts[1])

	rules, ok := config["pull_request_rules"].([]interface{})
	if !ok {
		return fmt.Errorf("pull_request_rules not found or invalid format")
	}

	label := fmt.Sprintf("backport-%s", branchVersion)
	if mergifyHasBackportRule(rules, branchVersion, label) {
		fmt.Printf("Backport rule for %s already exists\n", branchVersion)
		return nil
	}

	newRule := map[string]interface{}{
		"name": fmt.Sprintf("backport patches to %s branch", branchVersion),
		"conditions": []interface{}{
			"merged",
			fmt.Sprintf("label=%s", label),
		},
		"actions": map[string]interface{}{
			"backport": map[string]interface{}{
				"branches": []interface{}{branchVersion},
			},
		},
	}

	rules = append(rules, newRule)
	config["pull_request_rules"] = rules

	output, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	err = writeRepoFile(mergifyFile, output)
	if err != nil {
		return fmt.Errorf("failed to write %s: %w", mergifyFile, err)
	}

	fmt.Printf("Added backport rule for %s to %s\n", branchVersion, mergifyFile)
	return nil
}

// mergifyHasBackportRule reports whether pull_request_rules already contains a
// backport rule for branchVersion. Matching is exact (label condition, rule name,
// or backport branch) so prefixes like "9.1" do not match "9.10".
func mergifyHasBackportRule(rules []interface{}, branchVersion, label string) bool {
	labelCond := fmt.Sprintf("label=%s", label)
	expectedName := fmt.Sprintf("backport patches to %s branch", branchVersion)

	for _, rule := range rules {
		ruleMap, ok := rule.(map[string]interface{})
		if !ok {
			continue
		}
		if name, ok := ruleMap["name"].(string); ok && name == expectedName {
			return true
		}
		if conditions, ok := ruleMap["conditions"].([]interface{}); ok {
			for _, c := range conditions {
				if s, ok := c.(string); ok && s == labelCond {
					return true
				}
			}
		}
		actions, ok := ruleMap["actions"].(map[string]interface{})
		if !ok {
			continue
		}
		backport, ok := actions["backport"].(map[string]interface{})
		if !ok {
			continue
		}
		branches, ok := backport["branches"].([]interface{})
		if !ok {
			continue
		}
		for _, b := range branches {
			if s, ok := b.(string); ok && s == branchVersion {
				return true
			}
		}
	}
	return false
}
