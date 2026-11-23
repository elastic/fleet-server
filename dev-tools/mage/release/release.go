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

	devtools "github.com/elastic/fleet-server/v7/dev-tools/mage"
)

const (
	versionGoPath  = "version/version.go"
	mergifyYMLPath = ".mergify.yml"
)

var defaultVersionPattern = regexp.MustCompile(`const DefaultVersion = "([^"]+)"`)

// readFleetVersion returns DefaultVersion from version/version.go.
func readFleetVersion() (string, error) {
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
	case versionGoPath, mergifyYMLPath:
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
	parsed, err := devtools.ParseReleaseVersion(newVersion)
	if err != nil {
		return err
	}
	newVersion = parsed.String()

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
		printf("Version already set to %s in %s\n", newVersion, versionFile)
		return nil
	}

	newContent := re.ReplaceAllString(contentStr, `${1}"`+newVersion+`"`)
	if newContent == contentStr {
		return fmt.Errorf("version pattern not found in %s", versionFile)
	}

	if err := writeRepoFile(versionFile, []byte(newContent)); err != nil {
		return fmt.Errorf("failed to write %s: %w", versionFile, err)
	}

	printf("Updated version to %s in %s\n", newVersion, versionFile)
	return nil
}
