// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const versionGoPath = "version/version.go"

var defaultVersionPattern = regexp.MustCompile(`const DefaultVersion = "([^"]+)"`)

// ReadFleetVersion returns DefaultVersion from version/version.go.
func ReadFleetVersion() (string, error) {
	content, err := os.ReadFile(versionGoPath)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", versionGoPath, err)
	}
	match := defaultVersionPattern.FindSubmatch(content)
	if match == nil {
		return "", fmt.Errorf("version pattern not found in %s", versionGoPath)
	}
	return string(match[1]), nil
}

func validateRepoRelativePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path must not be empty")
	}
	if filepath.IsAbs(path) {
		return "", fmt.Errorf("absolute path not allowed: %s", path)
	}

	cleaned := filepath.Clean(path)
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes repository root: %s", path)
	}

	return cleaned, nil
}

func isReleaseWritablePath(path string) bool {
	switch filepath.ToSlash(path) {
	case versionGoPath, ".mergify.yml":
		return true
	default:
		return false
	}
}

func writeRepoFile(relPath string, content []byte) error {
	safePath, err := validateRepoRelativePath(relPath)
	if err != nil {
		return err
	}

	if !isReleaseWritablePath(safePath) {
		return fmt.Errorf("unsupported file path: %s", relPath)
	}

	return os.WriteFile(safePath, content, 0o644) //nolint:gosec // safePath is validated and allowlisted for release automation files
}

// UpdateVersion updates the version in version/version.go.
func UpdateVersion(newVersion string) error {
	versionFile, err := validateRepoRelativePath(versionGoPath)
	if err != nil {
		return err
	}

	content, err := os.ReadFile(versionFile)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", versionFile, err)
	}

	re := regexp.MustCompile(`(const\s+DefaultVersion\s*=\s*)"[^"]+"`)
	contentStr := string(content)
	alreadyAtVersion := regexp.MustCompile(`const\s+DefaultVersion\s*=\s*"` + regexp.QuoteMeta(newVersion) + `"`)
	if alreadyAtVersion.MatchString(contentStr) {
		fmt.Printf("Version already set to %s in %s\n", newVersion, versionFile)
		return nil
	}

	newContent := re.ReplaceAllString(contentStr, `${1}"`+newVersion+`"`)
	if newContent == contentStr {
		return fmt.Errorf("version pattern not found in %s", versionFile)
	}

	if err := writeRepoFile(versionFile, []byte(newContent)); err != nil {
		return fmt.Errorf("failed to write %s: %w", versionFile, err)
	}

	fmt.Printf("Updated version to %s in %s\n", newVersion, versionFile)
	return nil
}
