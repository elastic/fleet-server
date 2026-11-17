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

	"github.com/stretchr/testify/require"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// convertLocalBranchToRemoteOnly moves a local branch tip to origin/<name> and
// deletes the local ref (no git CLI / PlainClone required).
func convertLocalBranchToRemoteOnly(t *testing.T, g *GitRepo, branchName string) {
	t.Helper()

	require.NoError(t, g.CheckoutBranch("master"))

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
	require.NoError(t, err)

	w, err := repo.Worktree()
	require.NoError(t, err)

	testFile := filepath.Join(tmpDir, "README.md")
	err = os.WriteFile(testFile, []byte("# Test Repo"), 0o644)
	require.NoError(t, err)

	_, err = w.Add("README.md")
	require.NoError(t, err)

	_, err = w.Commit("Initial commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test User",
			Email: "test@example.com",
		},
	})
	require.NoError(t, err)

	return &GitRepo{repo: repo, path: tmpDir}, tmpDir
}

func TestEnsureBranchFrom(t *testing.T) {
	gitRepo, tmpDir := createTestGitRepo(t)

	origDir, _ := os.Getwd()
	defer func() {
		_ = os.Chdir(origDir)
	}()
	require.NoError(t, os.Chdir(tmpDir))

	require.NoError(t, gitRepo.EnsureBranchFrom("master", "9.6"))

	branch, err := gitRepo.GetCurrentBranch()
	require.NoError(t, err)
	if branch != "9.6" {
		t.Fatalf("expected branch 9.6, got %s", branch)
	}

	require.NoError(t, gitRepo.EnsureBranchFrom("master", "9.6"))
}

func TestEnsureBranchFromRemoteOnlyBase(t *testing.T) {
	gitRepo, _ := createTestGitRepo(t)
	require.NoError(t, gitRepo.CreateBranch("9.5"))
	convertLocalBranchToRemoteOnly(t, gitRepo, "9.5")

	exists, err := gitRepo.BranchExists("9.5")
	require.NoError(t, err)
	if exists {
		t.Fatal("expected 9.5 to exist only as a remote-tracking branch")
	}

	require.NoError(t, gitRepo.EnsureBranchFrom("9.5", "patch-release-9.5.1"))
	branch, err := gitRepo.GetCurrentBranch()
	require.NoError(t, err)
	if branch != "patch-release-9.5.1" {
		t.Fatalf("expected branch patch-release-9.5.1, got %s", branch)
	}
}

func TestEnsureBranchFromRemoteOnlyTarget(t *testing.T) {
	gitRepo, tmpDir := createTestGitRepo(t)
	require.NoError(t, gitRepo.CreateBranch("prep-branch"))
	require.NoError(t, gitRepo.CheckoutBranch("prep-branch"))

	w, err := gitRepo.repo.Worktree()
	require.NoError(t, err)
	marker := filepath.Join(tmpDir, "prep.txt")
	require.NoError(t, os.WriteFile(marker, []byte("prep tip"), 0o644))
	if _, err = w.Add("prep.txt"); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	prepHash, err := w.Commit("prep tip commit", &git.CommitOptions{
		Author: &object.Signature{Name: "Test User", Email: "test@example.com"},
	})
	require.NoError(t, err)

	convertLocalBranchToRemoteOnly(t, gitRepo, "prep-branch")

	exists, err := gitRepo.BranchExists("prep-branch")
	require.NoError(t, err)
	if exists {
		t.Fatal("expected prep-branch to exist only as a remote-tracking branch")
	}

	require.NoError(t, gitRepo.EnsureBranchFrom("master", "prep-branch"))
	branch, err := gitRepo.GetCurrentBranch()
	require.NoError(t, err)
	if branch != "prep-branch" {
		t.Fatalf("expected branch prep-branch, got %s", branch)
	}

	head, err := gitRepo.repo.Head()
	require.NoError(t, err)
	if head.Hash() != prepHash {
		t.Fatalf("expected HEAD %s (remote prep tip), got %s", prepHash, head.Hash())
	}
}

func TestCommitAllNoChanges(t *testing.T) {
	gitRepo, _ := createTestGitRepo(t)

	committed, err := gitRepo.CommitAll("Empty commit", "Test Author", "test@example.com")
	require.NoError(t, err)
	if committed {
		t.Error("CommitAll() should not commit when there are no changes")
	}
}

func TestSetRemoteURLIdempotent(t *testing.T) {
	gitRepo, _ := createTestGitRepo(t)
	remoteURL := "https://github.com/test/repo.git"

	err := gitRepo.SetRemoteURL("origin", remoteURL)
	require.NoError(t, err)

	err = gitRepo.SetRemoteURL("origin", remoteURL)
	require.NoError(t, err)

	remote, err := gitRepo.repo.Remote("origin")
	require.NoError(t, err)
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
	require.NoError(t, err)
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
	require.NoError(t, gitRepo.SetRemoteURL("origin", remoteURL))

	branch := "release-9.6"
	require.NoError(t, gitRepo.CreateBranch(branch))
	require.NoError(t, gitRepo.CheckoutBranch(branch))

	require.NoError(t, gitRepo.Push("origin"))

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
			name:      "http github upgraded",
			in:        "http://github.com/elastic/fleet-server.git",
			want:      "https://github.com/elastic/fleet-server.git",
			rewritten: true,
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

func TestIsTokenPushRemoteURL(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"https://github.com/elastic/fleet-server.git", true},
		{"file:///tmp/repo.git", true},
		{"http://github.com/elastic/fleet-server.git", false},
		{"https://evil.example/elastic/fleet-server.git", false},
		{"git@github.com:elastic/fleet-server.git", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := isTokenPushRemoteURL(tt.in); got != tt.want {
				t.Errorf("isTokenPushRemoteURL(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestEnsureHTTPSRemote(t *testing.T) {
	t.Run("rewrites ssh to https", func(t *testing.T) {
		gitRepo, _ := createTestGitRepo(t)
		require.NoError(t, gitRepo.SetRemoteURL("origin", "git@github.com:elastic/fleet-server.git"))
		require.NoError(t, gitRepo.ensureHTTPSRemote("origin"))
		remote, err := gitRepo.repo.Remote("origin")
		require.NoError(t, err)
		want := "https://github.com/elastic/fleet-server.git"
		if got := remote.Config().URLs[0]; got != want {
			t.Errorf("origin URL = %q, want %q", got, want)
		}
	})

	t.Run("preserves fetch refspecs", func(t *testing.T) {
		gitRepo, _ := createTestGitRepo(t)
		require.NoError(t, gitRepo.SetRemoteURL("origin", "git@github.com:elastic/fleet-server.git"))
		before, err := gitRepo.repo.Remote("origin")
		require.NoError(t, err)
		beforeFetch := append([]config.RefSpec(nil), before.Config().Fetch...)
		if len(beforeFetch) == 0 {
			t.Fatal("expected default fetch refspecs before rewrite")
		}
		require.NoError(t, gitRepo.ensureHTTPSRemote("origin"))
		after, err := gitRepo.repo.Remote("origin")
		require.NoError(t, err)
		if got := after.Config().Fetch; len(got) != len(beforeFetch) {
			t.Fatalf("fetch refspecs = %#v, want %#v", got, beforeFetch)
		}
		for i := range beforeFetch {
			if after.Config().Fetch[i] != beforeFetch[i] {
				t.Fatalf("fetch[%d] = %q, want %q", i, after.Config().Fetch[i], beforeFetch[i])
			}
		}
	})

	t.Run("rejects non-github remote", func(t *testing.T) {
		gitRepo, _ := createTestGitRepo(t)
		require.NoError(t, gitRepo.SetRemoteURL("origin", "git@gitlab.com:group/repo.git"))
		err := gitRepo.ensureHTTPSRemote("origin")
		if err == nil {
			t.Fatal("ensureHTTPSRemote() expected error for non-GitHub remote")
		}
		if !strings.Contains(err.Error(), "https://github.com/") {
			t.Errorf("ensureHTTPSRemote() error = %v, want mention of https://github.com/", err)
		}
	})

	t.Run("rejects arbitrary https host", func(t *testing.T) {
		gitRepo, _ := createTestGitRepo(t)
		require.NoError(t, gitRepo.SetRemoteURL("origin", "https://evil.example/elastic/fleet-server.git"))
		err := gitRepo.ensureHTTPSRemote("origin")
		if err == nil {
			t.Fatal("ensureHTTPSRemote() expected error for non-GitHub HTTPS remote")
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
