// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func createTestGitRepo(t *testing.T) (*GitRepo, string) {
	t.Helper()

	tmpDir := t.TempDir()

	repo, err := git.PlainInit(tmpDir, false)
	if err != nil {
		t.Fatalf("failed to init repo: %v", err)
	}

	w, err := repo.Worktree()
	if err != nil {
		t.Fatalf("failed to get worktree: %v", err)
	}

	testFile := filepath.Join(tmpDir, "README.md")
	err = os.WriteFile(testFile, []byte("# Test Repo"), 0o644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err = w.Add("README.md")
	if err != nil {
		t.Fatalf("failed to add file: %v", err)
	}

	_, err = w.Commit("Initial commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test User",
			Email: "test@example.com",
		},
	})
	if err != nil {
		t.Fatalf("failed to create initial commit: %v", err)
	}

	return &GitRepo{repo: repo}, tmpDir
}

func TestCreateBranchIdempotent(t *testing.T) {
	gitRepo, _ := createTestGitRepo(t)

	err := gitRepo.CreateBranch("9.5")
	if err != nil {
		t.Fatalf("first CreateBranch() failed: %v", err)
	}

	branch, err := gitRepo.GetCurrentBranch()
	if err != nil {
		t.Fatalf("GetCurrentBranch() failed: %v", err)
	}
	if branch != "9.5" {
		t.Fatalf("expected branch 9.5, got %s", branch)
	}

	err = gitRepo.CreateBranch("9.5")
	if err != nil {
		t.Fatalf("second CreateBranch() failed: %v", err)
	}

	branch, err = gitRepo.GetCurrentBranch()
	if err != nil {
		t.Fatalf("GetCurrentBranch() after second call failed: %v", err)
	}
	if branch != "9.5" {
		t.Errorf("CreateBranch() is not idempotent - on branch %s, want 9.5", branch)
	}
}

func TestCommitAllNoChanges(t *testing.T) {
	gitRepo, _ := createTestGitRepo(t)

	err := gitRepo.CommitAll("Empty commit", "Test Author", "test@example.com")
	if err != nil {
		t.Errorf("CommitAll() with no changes error = %v", err)
	}
}

func TestSetRemoteURLIdempotent(t *testing.T) {
	gitRepo, _ := createTestGitRepo(t)
	remoteURL := "https://github.com/test/repo.git"

	err := gitRepo.SetRemoteURL("origin", remoteURL)
	if err != nil {
		t.Fatalf("first SetRemoteURL() failed: %v", err)
	}

	err = gitRepo.SetRemoteURL("origin", remoteURL)
	if err != nil {
		t.Fatalf("second SetRemoteURL() failed: %v", err)
	}

	remote, err := gitRepo.repo.Remote("origin")
	if err != nil {
		t.Fatalf("failed to get remote: %v", err)
	}
	if len(remote.Config().URLs) == 0 || remote.Config().URLs[0] != remoteURL {
		t.Errorf("SetRemoteURL() URL = %v, want %s", remote.Config().URLs, remoteURL)
	}
}
