// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build mage

package main

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
			name:        "update to snapshot version",
			initial:     `const DefaultVersion = "9.4.0"`,
			newVersion:  "9.5.0-SNAPSHOT",
			wantErr:     false,
			wantContent: `const DefaultVersion = "9.5.0-SNAPSHOT"`,
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
			// Create temp directory and file
			tmpDir := t.TempDir()
			versionDir := filepath.Join(tmpDir, "version")
			err := os.Mkdir(versionDir, 0755)
			if err != nil {
				t.Fatalf("failed to create version dir: %v", err)
			}

			versionFile := filepath.Join(versionDir, "version.go")
			initialContent := `// Copyright header

package version

` + tt.initial + `
`
			err = os.WriteFile(versionFile, []byte(initialContent), 0644)
			if err != nil {
				t.Fatalf("failed to write initial file: %v", err)
			}

			// Save current dir and change to temp dir
			origDir, _ := os.Getwd()
			defer os.Chdir(origDir)
			os.Chdir(tmpDir)

			// Run UpdateVersion
			r := Release{}
			err = r.UpdateVersion(tt.newVersion)

			if (err != nil) != tt.wantErr {
				t.Errorf("UpdateVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify file content
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

func TestUpdateMergify(t *testing.T) {
	tests := []struct {
		name         string
		version      string
		wantErr      bool
		wantBranch   string
		wantLabel    string
		shouldAppend bool
	}{
		{
			name:         "add new backport rule",
			version:      "9.5.0",
			wantErr:      false,
			wantBranch:   "9.5",
			wantLabel:    "backport-9.5",
			shouldAppend: true,
		},
		{
			name:         "version with patch",
			version:      "10.0.1",
			wantErr:      false,
			wantBranch:   "10.0",
			wantLabel:    "backport-10.0",
			shouldAppend: true,
		},
		{
			name:    "invalid version format",
			version: "9",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp directory and file
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
			err := os.WriteFile(mergifyFile, []byte(initialContent), 0644)
			if err != nil {
				t.Fatalf("failed to write initial file: %v", err)
			}

			// Save current dir and change to temp dir
			origDir, _ := os.Getwd()
			defer os.Chdir(origDir)
			os.Chdir(tmpDir)

			// Run UpdateMergify
			r := Release{}
			err = r.UpdateMergify(tt.version)

			if (err != nil) != tt.wantErr {
				t.Errorf("UpdateMergify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.shouldAppend {
				// Verify file content
				content, err := os.ReadFile(mergifyFile)
				if err != nil {
					t.Fatalf("failed to read updated file: %v", err)
				}

				contentStr := string(content)

				// Check that the new rule was added
				expectedName := "backport patches to " + tt.wantBranch + " branch"
				if !strings.Contains(contentStr, expectedName) {
					t.Errorf("UpdateMergify() missing rule name: %s", expectedName)
				}

				if !strings.Contains(contentStr, tt.wantLabel) {
					t.Errorf("UpdateMergify() missing label: %s", tt.wantLabel)
				}

				if !strings.Contains(contentStr, `"`+tt.wantBranch+`"`) {
					t.Errorf("UpdateMergify() missing branch: %s", tt.wantBranch)
				}

				// Verify old rule is still there
				if !strings.Contains(contentStr, "9.3") {
					t.Error("UpdateMergify() removed existing rules")
				}
			}
		})
	}
}

func TestUpdateMergify_Idempotent(t *testing.T) {
	// Create temp directory and file
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
	err := os.WriteFile(mergifyFile, []byte(initialContent), 0644)
	if err != nil {
		t.Fatalf("failed to write initial file: %v", err)
	}

	// Save current dir and change to temp dir
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(tmpDir)

	// Run UpdateMergify twice with same version
	r := Release{}
	err = r.UpdateMergify("9.5.0")
	if err != nil {
		t.Fatalf("first UpdateMergify() failed: %v", err)
	}

	// Get content after first run
	content1, _ := os.ReadFile(mergifyFile)

	err = r.UpdateMergify("9.5.0")
	if err != nil {
		t.Fatalf("second UpdateMergify() failed: %v", err)
	}

	// Get content after second run
	content2, _ := os.ReadFile(mergifyFile)

	// Content should be identical (idempotent)
	if string(content1) != string(content2) {
		t.Error("UpdateMergify() is not idempotent - content changed on second run")
	}

	// Should only have one rule for 9.5
	count := strings.Count(string(content2), "backport patches to 9.5 branch")
	if count != 1 {
		t.Errorf("UpdateMergify() created %d rules for 9.5, want 1", count)
	}
}

func TestLoadReleaseConfigFromEnv(t *testing.T) {
	tests := []struct {
		name      string
		envVars   map[string]string
		wantErr   bool
		wantCheck func(*testing.T, *ReleaseConfig)
	}{
		{
			name: "all env vars set",
			envVars: map[string]string{
				"CURRENT_RELEASE": "9.5.0",
				"BASE_BRANCH":     "main",
				"PROJECT_OWNER":   "elastic",
				"PROJECT_REPO":    "fleet-server",
			},
			wantErr: false,
			wantCheck: func(t *testing.T, cfg *ReleaseConfig) {
				if cfg.Version != "9.5.0" {
					t.Errorf("Version = %s, want 9.5.0", cfg.Version)
				}
				if cfg.ReleaseBranch != "9.5" {
					t.Errorf("ReleaseBranch = %s, want 9.5", cfg.ReleaseBranch)
				}
				if cfg.BaseBranch != "main" {
					t.Errorf("BaseBranch = %s, want main", cfg.BaseBranch)
				}
			},
		},
		{
			name: "defaults applied",
			envVars: map[string]string{
				"CURRENT_RELEASE": "10.0.0",
			},
			wantErr: false,
			wantCheck: func(t *testing.T, cfg *ReleaseConfig) {
				if cfg.BaseBranch != "main" {
					t.Errorf("BaseBranch = %s, want main (default)", cfg.BaseBranch)
				}
				if cfg.Owner != "elastic" {
					t.Errorf("Owner = %s, want elastic (default)", cfg.Owner)
				}
				if cfg.Repo != "fleet-server" {
					t.Errorf("Repo = %s, want fleet-server (default)", cfg.Repo)
				}
			},
		},
		{
			name:    "missing CURRENT_RELEASE",
			envVars: map[string]string{},
			wantErr: true,
		},
		{
			name: "invalid version format",
			envVars: map[string]string{
				"CURRENT_RELEASE": "9",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear env and set test values
			os.Clearenv()
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			cfg, err := loadReleaseConfigFromEnv()

			if (err != nil) != tt.wantErr {
				t.Errorf("loadReleaseConfigFromEnv() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.wantCheck != nil {
				tt.wantCheck(t, cfg)
			}
		})
	}
}

func TestPrepareNext(t *testing.T) {
	// Create temp directory and file
	tmpDir := t.TempDir()
	versionDir := filepath.Join(tmpDir, "version")
	err := os.Mkdir(versionDir, 0755)
	if err != nil {
		t.Fatalf("failed to create version dir: %v", err)
	}

	versionFile := filepath.Join(versionDir, "version.go")
	initialContent := `package version

const DefaultVersion = "9.4.0"
`
	err = os.WriteFile(versionFile, []byte(initialContent), 0644)
	if err != nil {
		t.Fatalf("failed to write initial file: %v", err)
	}

	// Save current dir and change to temp dir
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(tmpDir)

	// Set env var
	os.Setenv("CURRENT_RELEASE", "9.4.0")

	// Run PrepareNext
	r := Release{}
	err = r.PrepareNext()
	if err != nil {
		t.Fatalf("PrepareNext() failed: %v", err)
	}

	// Verify version was incremented
	content, err := os.ReadFile(versionFile)
	if err != nil {
		t.Fatalf("failed to read updated file: %v", err)
	}

	expectedVersion := "9.5.0"
	if !strings.Contains(string(content), expectedVersion) {
		t.Errorf("PrepareNext() = %s, want %s", string(content), expectedVersion)
	}
}
