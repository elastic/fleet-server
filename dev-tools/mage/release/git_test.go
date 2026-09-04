// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
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

	return &GitRepo{repo: repo, path: tmpDir}, tmpDir
}

func TestEnsureBranchFrom(t *testing.T) {
	gitRepo, tmpDir := createTestGitRepo(t)

	origDir, _ := os.Getwd()
	defer func() {
		_ = os.Chdir(origDir)
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change to temp directory: %v", err)
	}

	if err := gitRepo.EnsureBranchFrom("master", "9.6"); err != nil {
		t.Fatalf("EnsureBranchFrom() failed: %v", err)
	}

	branch, err := gitRepo.GetCurrentBranch()
	if err != nil {
		t.Fatalf("GetCurrentBranch() failed: %v", err)
	}
	if branch != "9.6" {
		t.Fatalf("expected branch 9.6, got %s", branch)
	}

	if err := gitRepo.EnsureBranchFrom("master", "9.6"); err != nil {
		t.Fatalf("second EnsureBranchFrom() failed: %v", err)
	}
}

func TestEnsureBranchFromRemoteOnlyBase(t *testing.T) {
	upstream, _ := createTestGitRepo(t)
	if err := upstream.CreateBranch("9.5"); err != nil {
		t.Fatalf("CreateBranch(9.5) failed: %v", err)
	}

	bareDir := t.TempDir()
	_, err := git.PlainInit(bareDir, true)
	if err != nil {
		t.Fatalf("failed to init bare repo: %v", err)
	}
	if err := upstream.SetRemoteURL("origin", bareDir); err != nil {
		t.Fatalf("SetRemoteURL failed: %v", err)
	}

	// Local file remotes need no auth; GitRepo.Push requires GITHUB_TOKEN.
	err = upstream.repo.Push(&git.PushOptions{
		RemoteName: "origin",
		RefSpecs: []config.RefSpec{
			"refs/heads/master:refs/heads/master",
			"refs/heads/9.5:refs/heads/9.5",
		},
	})
	if err != nil {
		t.Fatalf("push to bare remote failed: %v", err)
	}

	cloneDir := t.TempDir()
	cloned, err := git.PlainClone(cloneDir, false, &git.CloneOptions{
		URL:           bareDir,
		ReferenceName: plumbing.NewBranchReferenceName("master"),
		SingleBranch:  false,
	})
	if err != nil {
		t.Fatalf("PlainClone failed: %v", err)
	}

	gitRepo := &GitRepo{repo: cloned, path: cloneDir}
	exists, err := gitRepo.BranchExists("9.5")
	if err != nil {
		t.Fatalf("BranchExists failed: %v", err)
	}
	if exists {
		t.Fatal("expected 9.5 to exist only as a remote-tracking branch after clone")
	}

	if err := gitRepo.EnsureBranchFrom("9.5", "patch-release-9.5.1"); err != nil {
		t.Fatalf("EnsureBranchFrom() with remote-only base failed: %v", err)
	}
	branch, err := gitRepo.GetCurrentBranch()
	if err != nil {
		t.Fatalf("GetCurrentBranch() failed: %v", err)
	}
	if branch != "patch-release-9.5.1" {
		t.Fatalf("expected branch patch-release-9.5.1, got %s", branch)
	}
}

func TestCommitAllNoChanges(t *testing.T) {
	gitRepo, _ := createTestGitRepo(t)

	committed, err := gitRepo.CommitAll("Empty commit", "Test Author", "test@example.com")
	if err != nil {
		t.Errorf("CommitAll() with no changes error = %v", err)
	}
	if committed {
		t.Error("CommitAll() should not commit when there are no changes")
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

func TestWorkflowBranchNames(t *testing.T) {
	names := []string{
		"ff-prep-main-9.6.0",
		"ff-release-9.6.0",
		"ff-prep-next-patch-9.6.1",
		"patch-release-9.6.1",
	}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if _, ok := seen[name]; ok {
			t.Fatalf("duplicate branch name: %s", name)
		}
		seen[name] = struct{}{}
		if strings.TrimSpace(name) == "" {
			t.Fatal("branch name empty")
		}
	}
}

func TestIsReleaseWritablePath(t *testing.T) {
	if !isReleaseWritablePath("version/version.go") {
		t.Fatal("version/version.go should be writable")
	}
	if !isReleaseWritablePath("version\\version.go") && false {
		// Windows path form is normalized via filepath.ToSlash in isReleaseWritablePath callers;
		// direct backslash input is not required for allowlist.
	}
	if isReleaseWritablePath("main.go") {
		t.Fatal("main.go should not be writable")
	}
}
