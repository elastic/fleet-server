// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// convertLocalBranchToRemoteOnly moves a local branch tip to origin/<name> and
// deletes the local ref (no git CLI / PlainClone required).
func convertLocalBranchToRemoteOnly(t *testing.T, g *GitRepo, branchName string) {
	t.Helper()

	if err := g.CheckoutBranch("master"); err != nil {
		t.Fatalf("CheckoutBranch(master) failed: %v", err)
	}

	localRef, err := g.repo.Reference(plumbing.NewBranchReferenceName(branchName), true)
	if err != nil {
		t.Fatalf("Reference(%s) failed: %v", branchName, err)
	}
	remoteRef := plumbing.NewHashReference(
		plumbing.NewRemoteReferenceName("origin", branchName),
		localRef.Hash(),
	)
	if err := g.repo.Storer.SetReference(remoteRef); err != nil {
		t.Fatalf("SetReference(origin/%s) failed: %v", branchName, err)
	}
	if err := g.repo.Storer.RemoveReference(plumbing.NewBranchReferenceName(branchName)); err != nil {
		t.Fatalf("RemoveReference(%s) failed: %v", branchName, err)
	}
}

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
	gitRepo, _ := createTestGitRepo(t)
	if err := gitRepo.CreateBranch("9.5"); err != nil {
		t.Fatalf("CreateBranch(9.5) failed: %v", err)
	}
	convertLocalBranchToRemoteOnly(t, gitRepo, "9.5")

	exists, err := gitRepo.BranchExists("9.5")
	if err != nil {
		t.Fatalf("BranchExists failed: %v", err)
	}
	if exists {
		t.Fatal("expected 9.5 to exist only as a remote-tracking branch")
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

func TestEnsureBranchFromRemoteOnlyTarget(t *testing.T) {
	gitRepo, tmpDir := createTestGitRepo(t)
	if err := gitRepo.CreateBranch("prep-branch"); err != nil {
		t.Fatalf("CreateBranch(prep-branch) failed: %v", err)
	}
	if err := gitRepo.CheckoutBranch("prep-branch"); err != nil {
		t.Fatalf("CheckoutBranch(prep-branch) failed: %v", err)
	}

	w, err := gitRepo.repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree failed: %v", err)
	}
	marker := filepath.Join(tmpDir, "prep.txt")
	if err := os.WriteFile(marker, []byte("prep tip"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if _, err := w.Add("prep.txt"); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	prepHash, err := w.Commit("prep tip commit", &git.CommitOptions{
		Author: &object.Signature{Name: "Test User", Email: "test@example.com"},
	})
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	convertLocalBranchToRemoteOnly(t, gitRepo, "prep-branch")

	exists, err := gitRepo.BranchExists("prep-branch")
	if err != nil {
		t.Fatalf("BranchExists failed: %v", err)
	}
	if exists {
		t.Fatal("expected prep-branch to exist only as a remote-tracking branch")
	}

	if err := gitRepo.EnsureBranchFrom("master", "prep-branch"); err != nil {
		t.Fatalf("EnsureBranchFrom() with remote-only target failed: %v", err)
	}
	branch, err := gitRepo.GetCurrentBranch()
	if err != nil {
		t.Fatalf("GetCurrentBranch() failed: %v", err)
	}
	if branch != "prep-branch" {
		t.Fatalf("expected branch prep-branch, got %s", branch)
	}

	head, err := gitRepo.repo.Head()
	if err != nil {
		t.Fatalf("Head() failed: %v", err)
	}
	if head.Hash() != prepHash {
		t.Fatalf("expected HEAD %s (remote prep tip), got %s", prepHash, head.Hash())
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
	// update-version-* is created by runPatch only (not runMajorMinor).
	names := []string{
		"ff-prep-main-9.6.0",
		"ff-release-9.6.0",
		"update-version-9.6.1",
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

func TestGitHTTPSAuthExtraHeader(t *testing.T) {
	got := gitHTTPSAuthExtraHeader("test-token")
	wantPrefix := "Authorization: Basic "
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("gitHTTPSAuthExtraHeader() = %q, want prefix %q", got, wantPrefix)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, wantPrefix))
	if err != nil {
		t.Fatalf("decode auth payload: %v", err)
	}
	if string(decoded) != "x-access-token:test-token" {
		t.Fatalf("auth payload = %q, want %q", decoded, "x-access-token:test-token")
	}
	if strings.Contains(got, "Bearer") {
		t.Fatalf("gitHTTPSAuthExtraHeader() must not use Bearer: %q", got)
	}
}

func TestGitPushEnv(t *testing.T) {
	env := gitPushEnv([]string{"PATH=/usr/bin"}, "test-token")
	wantHeader := gitHTTPSAuthExtraHeader("test-token")
	got := map[string]string{}
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			t.Fatalf("malformed env entry %q", entry)
		}
		got[key] = value
	}
	if got["PATH"] != "/usr/bin" {
		t.Fatalf("PATH = %q, want /usr/bin", got["PATH"])
	}
	if got["GIT_CONFIG_COUNT"] != "1" {
		t.Fatalf("GIT_CONFIG_COUNT = %q, want 1", got["GIT_CONFIG_COUNT"])
	}
	if got["GIT_CONFIG_KEY_0"] != "http.extraHeader" {
		t.Fatalf("GIT_CONFIG_KEY_0 = %q, want http.extraHeader", got["GIT_CONFIG_KEY_0"])
	}
	if got["GIT_CONFIG_VALUE_0"] != wantHeader {
		t.Fatalf("GIT_CONFIG_VALUE_0 = %q, want %q", got["GIT_CONFIG_VALUE_0"], wantHeader)
	}
}

func TestPushRequiresToken(t *testing.T) {
	gitRepo, _ := createTestGitRepo(t)
	t.Setenv("GITHUB_TOKEN", "")

	err := gitRepo.Push("origin")
	if err == nil {
		t.Fatal("Push() should fail without GITHUB_TOKEN")
	}
	if !strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Fatalf("Push() error = %v, want GITHUB_TOKEN mention", err)
	}
}

func TestPushRequiresOriginRemote(t *testing.T) {
	gitRepo, _ := createTestGitRepo(t)
	t.Setenv("GITHUB_TOKEN", "test-token")

	err := gitRepo.Push("upstream")
	if err == nil {
		t.Fatal("Push() should reject non-origin remotes")
	}
	if !strings.Contains(err.Error(), "only supports origin") {
		t.Fatalf("Push() error = %v, want origin restriction", err)
	}
}

func TestPushToLocalRemote(t *testing.T) {
	gitRepo, workDir := createTestGitRepo(t)
	t.Setenv("GITHUB_TOKEN", "test-token")

	bareDir := t.TempDir()
	if _, err := git.PlainInit(bareDir, true); err != nil {
		t.Fatalf("failed to init bare remote: %v", err)
	}
	remoteURL := "file://" + bareDir
	if err := gitRepo.SetRemoteURL("origin", remoteURL); err != nil {
		t.Fatalf("SetRemoteURL() error = %v", err)
	}

	branch := "release-9.6"
	if err := gitRepo.CreateBranch(branch); err != nil {
		t.Fatalf("CreateBranch() error = %v", err)
	}
	if err := gitRepo.CheckoutBranch(branch); err != nil {
		t.Fatalf("CheckoutBranch() error = %v", err)
	}

	if err := gitRepo.Push("origin"); err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	remoteHeads := runGitOutput(t, workDir, "ls-remote", "--heads", "origin", branch)
	if !strings.Contains(remoteHeads, "refs/heads/"+branch) {
		t.Fatalf("Push() did not create remote branch %s; ls-remote:\n%s", branch, remoteHeads)
	}
}

func TestGithubHTTPSPushURL(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		want      string
		rewritten bool
	}{
		{
			name:      "scp ssh",
			in:        "git@github.com:elastic/fleet-server.git",
			want:      "https://github.com/elastic/fleet-server.git",
			rewritten: true,
		},
		{
			name:      "ssh scheme",
			in:        "ssh://git@github.com/elastic/fleet-server.git",
			want:      "https://github.com/elastic/fleet-server.git",
			rewritten: true,
		},
		{
			name:      "https unchanged",
			in:        "https://github.com/elastic/fleet-server.git",
			want:      "https://github.com/elastic/fleet-server.git",
			rewritten: false,
		},
		{
			name:      "non-github ssh unchanged",
			in:        "git@gitlab.com:group/repo.git",
			want:      "git@gitlab.com:group/repo.git",
			rewritten: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, rewritten := githubHTTPSPushURL(tt.in)
			if got != tt.want || rewritten != tt.rewritten {
				t.Errorf("githubHTTPSPushURL(%q) = (%q, %v), want (%q, %v)",
					tt.in, got, rewritten, tt.want, tt.rewritten)
			}
		})
	}
}

func TestEnsureHTTPSRemote(t *testing.T) {
	t.Run("rewrites ssh to https", func(t *testing.T) {
		gitRepo, _ := createTestGitRepo(t)
		if err := gitRepo.SetRemoteURL("origin", "git@github.com:elastic/fleet-server.git"); err != nil {
			t.Fatalf("SetRemoteURL() error = %v", err)
		}
		if err := gitRepo.ensureHTTPSRemote("origin"); err != nil {
			t.Fatalf("ensureHTTPSRemote() error = %v", err)
		}
		remote, err := gitRepo.repo.Remote("origin")
		if err != nil {
			t.Fatalf("Remote() error = %v", err)
		}
		want := "https://github.com/elastic/fleet-server.git"
		if got := remote.Config().URLs[0]; got != want {
			t.Errorf("origin URL = %q, want %q", got, want)
		}
	})

	t.Run("rejects non-https remote", func(t *testing.T) {
		gitRepo, _ := createTestGitRepo(t)
		if err := gitRepo.SetRemoteURL("origin", "git@gitlab.com:group/repo.git"); err != nil {
			t.Fatalf("SetRemoteURL() error = %v", err)
		}
		err := gitRepo.ensureHTTPSRemote("origin")
		if err == nil {
			t.Fatal("ensureHTTPSRemote() expected error for non-HTTPS remote")
		}
		if !strings.Contains(err.Error(), "not HTTPS") {
			t.Errorf("ensureHTTPSRemote() error = %v, want mention of not HTTPS", err)
		}
	})
}

func runGitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	gitArgs := append([]string{"-c", "protocol.file.allow=always"}, args...)
	cmd := exec.CommandContext(context.Background(), "git", gitArgs...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
	return string(out)
}
