// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateVersion(t *testing.T) {
	tests := []struct {
		name        string
		initial     string
		newVersion  string
		wantErr     bool
		wantContent string
	}{
		{
			name:        "update version successfully",
			initial:     `const DefaultVersion = "9.4.0"`,
			newVersion:  "9.5.0",
			wantErr:     false,
			wantContent: `const DefaultVersion = "9.5.0"`,
		},
		{
			name:        "update with different spacing",
			initial:     `const  DefaultVersion  =  "9.4.0"`,
			newVersion:  "9.5.0",
			wantErr:     false,
			wantContent: `const  DefaultVersion  =  "9.5.0"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			versionDir := filepath.Join(tmpDir, "version")
			err := os.Mkdir(versionDir, 0o755)
			if err != nil {
				t.Fatalf("failed to create version dir: %v", err)
			}

			versionFile := filepath.Join(versionDir, "version.go")
			initialContent := `// Copyright header

package version

` + tt.initial + `
`
			err = os.WriteFile(versionFile, []byte(initialContent), 0o644)
			if err != nil {
				t.Fatalf("failed to write initial file: %v", err)
			}

			origDir, _ := os.Getwd()
			defer func() {
				_ = os.Chdir(origDir)
			}()
			if err := os.Chdir(tmpDir); err != nil {
				t.Fatalf("failed to change to temp directory: %v", err)
			}

			err = UpdateVersion(tt.newVersion)

			if (err != nil) != tt.wantErr {
				t.Errorf("UpdateVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				content, err := os.ReadFile(versionFile)
				if err != nil {
					t.Fatalf("failed to read updated file: %v", err)
				}

				if !strings.Contains(string(content), tt.wantContent) {
					t.Errorf("UpdateVersion() content = %s, want to contain %s", string(content), tt.wantContent)
				}
			}
		})
	}
}

func TestUpdateVersionIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	versionDir := filepath.Join(tmpDir, "version")
	err := os.Mkdir(versionDir, 0o755)
	if err != nil {
		t.Fatalf("failed to create version dir: %v", err)
	}

	versionFile := filepath.Join(versionDir, "version.go")
	initialContent := `package version

const DefaultVersion = "9.4.0"
`
	err = os.WriteFile(versionFile, []byte(initialContent), 0o644)
	if err != nil {
		t.Fatalf("failed to write initial file: %v", err)
	}

	origDir, _ := os.Getwd()
	defer func() {
		_ = os.Chdir(origDir)
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change to temp directory: %v", err)
	}

	err = UpdateVersion("9.5.0")
	if err != nil {
		t.Fatalf("first UpdateVersion() failed: %v", err)
	}

	content1, err := os.ReadFile(versionFile)
	if err != nil {
		t.Fatalf("failed to read file after first update: %v", err)
	}

	err = UpdateVersion("9.5.0")
	if err != nil {
		t.Fatalf("second UpdateVersion() failed: %v", err)
	}

	content2, err := os.ReadFile(versionFile)
	if err != nil {
		t.Fatalf("failed to read file after second update: %v", err)
	}

	if string(content1) != string(content2) {
		t.Error("UpdateVersion() is not idempotent - content changed on second run")
	}
}

func TestUpdateMergify(t *testing.T) {
	tmpDir := t.TempDir()
	mergifyFile := filepath.Join(tmpDir, ".mergify.yml")

	initialContent := `pull_request_rules:
  - name: backport patches to 9.3 branch
    conditions:
      - merged
      - label=backport-9.3
    actions:
      backport:
        branches:
          - "9.3"
`
	err := os.WriteFile(mergifyFile, []byte(initialContent), 0o644)
	if err != nil {
		t.Fatalf("failed to write initial file: %v", err)
	}

	origDir, _ := os.Getwd()
	defer func() {
		_ = os.Chdir(origDir)
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change to temp directory: %v", err)
	}

	err = UpdateMergify("9.5.0")
	if err != nil {
		t.Fatalf("UpdateMergify() failed: %v", err)
	}

	content, err := os.ReadFile(mergifyFile)
	if err != nil {
		t.Fatalf("failed to read updated file: %v", err)
	}

	contentStr := string(content)
	if !strings.Contains(contentStr, "backport patches to 9.5 branch") {
		t.Errorf("UpdateMergify() missing rule name for 9.5")
	}
	if !strings.Contains(contentStr, "9.3") {
		t.Error("UpdateMergify() removed existing rules")
	}
}

func TestUpdateMergifyIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	mergifyFile := filepath.Join(tmpDir, ".mergify.yml")

	initialContent := `pull_request_rules:
  - name: backport patches to 9.5 branch
    conditions:
      - merged
      - label=backport-9.5
    actions:
      backport:
        branches:
          - "9.5"
`
	err := os.WriteFile(mergifyFile, []byte(initialContent), 0o644)
	if err != nil {
		t.Fatalf("failed to write initial file: %v", err)
	}

	origDir, _ := os.Getwd()
	defer func() {
		_ = os.Chdir(origDir)
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change to temp directory: %v", err)
	}

	err = UpdateMergify("9.5.0")
	if err != nil {
		t.Fatalf("first UpdateMergify() failed: %v", err)
	}

	content1, _ := os.ReadFile(mergifyFile)

	err = UpdateMergify("9.5.0")
	if err != nil {
		t.Fatalf("second UpdateMergify() failed: %v", err)
	}

	content2, _ := os.ReadFile(mergifyFile)

	if string(content1) != string(content2) {
		t.Error("UpdateMergify() is not idempotent - content changed on second run")
	}
}
