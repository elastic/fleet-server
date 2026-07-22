// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"os"
	"testing"
)

func TestInferLatestRelease(t *testing.T) {
	tests := []struct {
		name    string
		current string
		want    string
		wantErr bool
	}{
		{name: "patch release", current: "9.6.2", want: "9.6.1"},
		{name: "x.y.0 returns empty", current: "9.6.0", want: ""},
		{name: "invalid version", current: "9.6", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := inferLatestRelease(tt.current)
			if (err != nil) != tt.wantErr {
				t.Fatalf("inferLatestRelease() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("inferLatestRelease() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInferNextRelease(t *testing.T) {
	got, err := inferNextRelease("9.6.0")
	if err != nil {
		t.Fatalf("inferNextRelease() failed: %v", err)
	}
	if got != "9.6.1" {
		t.Fatalf("inferNextRelease() = %q, want 9.6.1", got)
	}
}

func TestInferNextProjectMinorVersion(t *testing.T) {
	got, err := inferNextProjectMinorVersion("9.6.0")
	if err != nil {
		t.Fatalf("inferNextProjectMinorVersion() failed: %v", err)
	}
	if got != "9.7.0" {
		t.Fatalf("inferNextProjectMinorVersion() = %q, want 9.7.0", got)
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	tests := []struct {
		name      string
		envVars   map[string]string
		wantErr   bool
		wantCheck func(*testing.T, *ReleaseConfig)
	}{
		{
			name: "defaults applied",
			envVars: map[string]string{
				"CURRENT_RELEASE": "9.6.0",
			},
			wantErr: false,
			wantCheck: func(t *testing.T, cfg *ReleaseConfig) {
				if cfg.ReleaseBranch != "9.6" {
					t.Errorf("ReleaseBranch = %s, want 9.6", cfg.ReleaseBranch)
				}
				if cfg.NextRelease != "9.6.1" {
					t.Errorf("NextRelease = %s, want 9.6.1", cfg.NextRelease)
				}
				if cfg.NextProjectMinorVersion != "9.7.0" {
					t.Errorf("NextProjectMinorVersion = %s, want 9.7.0", cfg.NextProjectMinorVersion)
				}
				if cfg.ProjectOwner != "elastic" {
					t.Errorf("ProjectOwner = %s, want elastic", cfg.ProjectOwner)
				}
				if cfg.ProjectRepo != "fleet-server" {
					t.Errorf("ProjectRepo = %s, want fleet-server", cfg.ProjectRepo)
				}
				if cfg.DryRun {
					t.Error("DryRun should be false by default")
				}
			},
		},
		{
			name: "dry run only with literal true",
			envVars: map[string]string{
				"CURRENT_RELEASE": "9.6.0",
				"DRY_RUN":         "true",
			},
			wantCheck: func(t *testing.T, cfg *ReleaseConfig) {
				if !cfg.DryRun {
					t.Error("DryRun should be true")
				}
			},
		},
		{
			name: "dry run rejects 1",
			envVars: map[string]string{
				"CURRENT_RELEASE": "9.6.0",
				"DRY_RUN":         "1",
			},
			wantCheck: func(t *testing.T, cfg *ReleaseConfig) {
				if cfg.DryRun {
					t.Error("DryRun should be false for DRY_RUN=1")
				}
			},
		},
		{
			name:    "missing CURRENT_RELEASE",
			envVars: map[string]string{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Clearenv()
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			cfg, err := LoadConfigFromEnv()
			if (err != nil) != tt.wantErr {
				t.Fatalf("LoadConfigFromEnv() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && tt.wantCheck != nil {
				tt.wantCheck(t, cfg)
			}
		})
	}
}

func TestEnsureLatestReleaseNoopWhenSet(t *testing.T) {
	cfg := &ReleaseConfig{CurrentRelease: "9.6.1", LatestRelease: "9.6.0"}
	if err := cfg.EnsureLatestRelease(); err != nil {
		t.Fatalf("EnsureLatestRelease() unexpected error: %v", err)
	}
	if cfg.LatestRelease != "9.6.0" {
		t.Fatalf("LatestRelease = %q, want 9.6.0", cfg.LatestRelease)
	}
}
