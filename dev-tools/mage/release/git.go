// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
)

const (
	// pushTimeout bounds native git push so Buildkite jobs fail fast instead of
	// hanging until the step timeout (go-git push stalls on reference clones).
	pushTimeout = 10 * time.Minute
	// gitConfigTimeout bounds local git config reads/writes used when rewriting remotes.
	gitConfigTimeout = 30 * time.Second
	// worktreeCmdTimeout bounds git checkout/status/add/commit/merge-base used
	// instead of go-git on Buildkite reference clones. go-git Status/Checkout
	// can take tens of minutes on large trees with object alternates.
	worktreeCmdTimeout = 10 * time.Minute
)

// gitRepo wraps go-git Repository with helper methods.
type gitRepo struct {
	repo *git.Repository
	path string
}

// openRepo opens a git repository at the specified path.
func openRepo(path string) (*gitRepo, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	return &gitRepo{
		repo: repo,
		path: path,
	}, nil
}

// branchExists reports whether a local branch exists.
func (g *gitRepo) branchExists(branchName string) (bool, error) {
	_, err := g.repo.Reference(plumbing.NewBranchReferenceName(branchName), true)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return false, nil
	}
	return false, fmt.Errorf("failed to check branch %s: %w", branchName, err)
}

// createBranch creates a new branch from the current HEAD.
func (g *gitRepo) createBranch(branchName string) error {
	exists, err := g.branchExists(branchName)
	if err != nil {
		return err
	}
	if exists {
		printf("Branch already exists: %s\n", branchName)
		return nil
	}

	headRef, err := g.repo.Head()
	if err != nil {
		return fmt.Errorf("failed to get HEAD: %w", err)
	}

	refName := plumbing.NewBranchReferenceName(branchName)
	ref := plumbing.NewHashReference(refName, headRef.Hash())

	err = g.repo.Storer.SetReference(ref)
	if err != nil {
		return fmt.Errorf("failed to create branch %s: %w", branchName, err)
	}

	printf("Created branch: %s\n", branchName)
	return nil
}

// ensureBranchFrom checks out baseBranch (creating a local branch from origin when
// needed), then ensures branchName exists — reusing a local or origin/<branchName>
// tip when present, otherwise creating it from the current base tip.
func (g *gitRepo) ensureBranchFrom(baseBranch, branchName string) error {
	if err := g.ensureBranch(baseBranch); err != nil {
		return fmt.Errorf("failed to checkout base branch %s: %w", baseBranch, err)
	}
	return g.ensureBranch(branchName)
}

// ensureBranch checks out an existing local or remote branch, or creates it from HEAD.
func (g *gitRepo) ensureBranch(branchName string) error {
	if err := g.ensureExistingBranch(branchName); err == nil {
		return nil
	} else if !errors.Is(err, errBranchNotFound) {
		return err
	}

	if err := g.createBranch(branchName); err != nil {
		return err
	}
	return g.checkoutBranch(branchName)
}

var errBranchNotFound = errors.New("branch not found locally or on origin")

// ensureExistingBranch checks out a branch that already exists locally or as
// origin/<name>. It does not create a branch from HEAD when the ref is missing.
func (g *gitRepo) ensureExistingBranch(branchName string) error {
	exists, err := g.branchExists(branchName)
	if err != nil {
		return err
	}
	if exists {
		return g.checkoutBranch(branchName)
	}

	remoteRef, err := g.repo.Reference(plumbing.NewRemoteReferenceName("origin", branchName), true)
	if err == nil {
		localRef := plumbing.NewHashReference(plumbing.NewBranchReferenceName(branchName), remoteRef.Hash())
		if err := g.repo.Storer.SetReference(localRef); err != nil {
			return fmt.Errorf("failed to create local branch %s from origin: %w", branchName, err)
		}
		printf("Created local branch from origin: %s\n", branchName)
		return g.checkoutBranch(branchName)
	}
	if !errors.Is(err, plumbing.ErrReferenceNotFound) {
		return fmt.Errorf("failed to check remote branch %s: %w", branchName, err)
	}
	return fmt.Errorf("%w: %s", errBranchNotFound, branchName)
}

// runGit runs git in the repository path with a deadline (Buildkite-safe).
func (g *gitRepo) runGit(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = g.path
	return cmd.CombinedOutput()
}

// checkoutBranch checks out an existing branch via the git CLI.
// go-git Checkout is avoided: with Buildkite reference clones it can take tens
// of minutes on large trees.
func (g *gitRepo) checkoutBranch(branchName string) error {
	currentBranch, err := g.getCurrentBranch()
	if err == nil && currentBranch == branchName {
		printf("Already on branch: %s\n", branchName)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), worktreeCmdTimeout)
	defer cancel()

	output, err := g.runGit(ctx, "checkout", branchName)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("failed to checkout branch %s: timed out after %s: %w", branchName, worktreeCmdTimeout, err)
		}
		return fmt.Errorf("failed to checkout branch %s: %w: %s", branchName, err, strings.TrimSpace(string(output)))
	}

	printf("Checked out branch: %s\n", branchName)
	return nil
}

// commitAll stages all changes and creates a commit via the git CLI.
// go-git AddGlob/Status/Commit are avoided for the same reference-clone cost as
// checkoutBranch.
func (g *gitRepo) commitAll(message, authorName, authorEmail string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), worktreeCmdTimeout)
	defer cancel()

	if output, err := g.runGit(ctx, "add", "-A"); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return false, fmt.Errorf("failed to stage changes: timed out after %s: %w", worktreeCmdTimeout, err)
		}
		return false, fmt.Errorf("failed to stage changes: %w: %s", err, strings.TrimSpace(string(output)))
	}

	statusOut, err := g.runGit(ctx, "status", "--porcelain")
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return false, fmt.Errorf("failed to get status: timed out after %s: %w", worktreeCmdTimeout, err)
		}
		return false, fmt.Errorf("failed to get status: %w: %s", err, strings.TrimSpace(string(statusOut)))
	}
	if len(strings.TrimSpace(string(statusOut))) == 0 {
		println("No changes to commit")
		return false, nil
	}

	commitOut, err := g.runGit(ctx,
		"-c", "user.name="+authorName,
		"-c", "user.email="+authorEmail,
		"commit",
		"--author", authorName+" <"+authorEmail+">",
		"-m", message,
	)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return false, fmt.Errorf("failed to commit: timed out after %s: %w", worktreeCmdTimeout, err)
		}
		return false, fmt.Errorf("failed to commit: %w: %s", err, strings.TrimSpace(string(commitOut)))
	}

	hashOut, err := g.runGit(ctx, "rev-parse", "HEAD")
	if err != nil {
		return false, fmt.Errorf("failed to read commit hash: %w: %s", err, strings.TrimSpace(string(hashOut)))
	}
	printf("Created commit: %s\n", strings.TrimSpace(string(hashOut)))
	return true, nil
}

// hasCommitsAheadOf reports whether HEAD has commits not reachable from baseBranch.
// Behind/equal: merge-base is HEAD → not ahead. Ahead/diverged: merge-base is not HEAD.
// Uses the git CLI so mixed CLI commits and reference-clone object stores do not
// hit go-git MergeBase "object not found" failures.
func (g *gitRepo) hasCommitsAheadOf(baseBranch string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), worktreeCmdTimeout)
	defer cancel()

	if _, err := g.runGit(ctx, "show-ref", "--verify", "--quiet", "refs/heads/"+baseBranch); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return false, fmt.Errorf(
				"failed to verify base branch %s: timed out after %s: %w",
				baseBranch, worktreeCmdTimeout, err,
			)
		}
		// Missing local branch: treat as ahead (prior go-git ErrReferenceNotFound).
		return true, nil
	}

	headOut, err := g.runGit(ctx, "rev-parse", "HEAD")
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return false, fmt.Errorf("failed to get HEAD: timed out after %s: %w", worktreeCmdTimeout, err)
		}
		return false, fmt.Errorf("failed to get HEAD: %w: %s", err, strings.TrimSpace(string(headOut)))
	}
	baseOut, err := g.runGit(ctx, "rev-parse", baseBranch)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return false, fmt.Errorf(
				"failed to get base branch %s: timed out after %s: %w",
				baseBranch, worktreeCmdTimeout, err,
			)
		}
		return false, fmt.Errorf(
			"failed to get base branch %s: %w: %s",
			baseBranch, err, strings.TrimSpace(string(baseOut)),
		)
	}
	headHash := strings.TrimSpace(string(headOut))
	baseHash := strings.TrimSpace(string(baseOut))
	if headHash == baseHash {
		return false, nil
	}

	mbOut, err := g.runGit(ctx, "merge-base", "HEAD", baseBranch)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return false, fmt.Errorf(
				"failed to compare commits with %s: timed out after %s: %w",
				baseBranch, worktreeCmdTimeout, err,
			)
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			// No common ancestor → treat as ahead (diverged / unrelated).
			return true, nil
		}
		return false, fmt.Errorf(
			"failed to compare commits with %s: %w: %s",
			baseBranch, err, strings.TrimSpace(string(mbOut)),
		)
	}
	if strings.TrimSpace(string(mbOut)) == headHash {
		return false, nil
	}
	return true, nil
}

// githubHTTPSPushURL converts SSH-style and plaintext GitHub remotes to HTTPS so
// token-authenticated pushes can use HTTPS. Existing https://github.com URLs are
// unchanged. Returns the URL to use and whether it was rewritten.
func githubHTTPSPushURL(remoteURL string) (string, bool) {
	u := strings.TrimSpace(remoteURL)
	switch {
	case strings.HasPrefix(u, "https://github.com/"):
		return u, false
	case strings.HasPrefix(u, "http://github.com/"):
		return "https://github.com/" + strings.TrimPrefix(u, "http://github.com/"), true
	case strings.HasPrefix(u, "git@github.com:"):
		return "https://github.com/" + strings.TrimPrefix(u, "git@github.com:"), true
	case strings.HasPrefix(u, "ssh://git@github.com"):
		rest := strings.TrimPrefix(u, "ssh://git@github.com")
		rest = strings.TrimPrefix(rest, ":22")
		rest = strings.TrimPrefix(rest, "/")
		return "https://github.com/" + rest, true
	default:
		return u, false
	}
}

// ensureHTTPSRemote rewrites GitHub remotes to HTTPS when needed.
// Fetch `url` and `pushurl` entries are read and written separately via the git
// CLI so pushurl precedence is preserved (go-git's RemoteConfig flattens both
// into URLs and marshals them all back as url keys).
func (g *gitRepo) ensureHTTPSRemote(remoteName string) error {
	if _, err := g.repo.Remote(remoteName); err != nil {
		return fmt.Errorf("failed to get remote %s: %w", remoteName, err)
	}

	urls, err := g.gitConfigGetAll(fmt.Sprintf("remote.%s.url", remoteName))
	if err != nil {
		return err
	}
	pushURLs, err := g.gitConfigGetAll(fmt.Sprintf("remote.%s.pushurl", remoteName))
	if err != nil {
		return err
	}
	if len(urls) == 0 && len(pushURLs) == 0 {
		return fmt.Errorf("remote %s has no URLs", remoteName)
	}

	newURLs, rewrittenURLs, err := rewriteTokenPushURLs(remoteName, urls)
	if err != nil {
		return err
	}
	newPushURLs, rewrittenPush, err := rewriteTokenPushURLs(remoteName, pushURLs)
	if err != nil {
		return err
	}
	if !rewrittenURLs && !rewrittenPush {
		return nil
	}
	if err := g.replaceRemoteURLConfig(remoteName, newURLs, newPushURLs); err != nil {
		return fmt.Errorf("failed to set HTTPS remote for token push: %w", err)
	}
	return nil
}

// rewriteTokenPushURLs converts each remote URL to a token-safe HTTPS form.
func rewriteTokenPushURLs(remoteName string, urls []string) ([]string, bool, error) {
	if len(urls) == 0 {
		return nil, false, nil
	}
	out := make([]string, len(urls))
	rewrittenAny := false
	for i, u := range urls {
		httpsURL, rewritten := githubHTTPSPushURL(u)
		if !isTokenPushRemoteURL(httpsURL) {
			return nil, false, fmt.Errorf("remote %s URL %q is not https://github.com/ or file://; token push requires a trusted GitHub HTTPS remote", remoteName, u)
		}
		out[i] = httpsURL
		if rewritten {
			rewrittenAny = true
		}
	}
	return out, rewrittenAny, nil
}

func (g *gitRepo) gitConfigGetAll(key string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitConfigTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "config", "--get-all", key)
	cmd.Dir = g.path
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, fmt.Errorf("git config --get-all %s: %w: %s", key, err, strings.TrimSpace(string(out)))
	}
	text := strings.TrimSuffix(string(out), "\n")
	if text == "" {
		return nil, nil
	}
	return strings.Split(text, "\n"), nil
}

func (g *gitRepo) gitConfigUnsetAll(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), gitConfigTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "config", "--unset-all", key)
	cmd.Dir = g.path
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		// Exit 5: key not found / nothing to unset.
		if errors.As(err, &exitErr) && (exitErr.ExitCode() == 1 || exitErr.ExitCode() == 5) {
			return nil
		}
		return fmt.Errorf("git config --unset-all %s: %w: %s", key, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (g *gitRepo) gitConfigAdd(key, value string) error {
	ctx, cancel := context.WithTimeout(context.Background(), gitConfigTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "config", "--add", key, value)
	cmd.Dir = g.path
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git config --add %s: %w: %s", key, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// replaceRemoteURLConfig rewrites remote url and pushurl keys without touching fetchspecs.
func (g *gitRepo) replaceRemoteURLConfig(remoteName string, urls, pushURLs []string) error {
	urlKey := fmt.Sprintf("remote.%s.url", remoteName)
	pushKey := fmt.Sprintf("remote.%s.pushurl", remoteName)
	if err := g.gitConfigUnsetAll(urlKey); err != nil {
		return err
	}
	if err := g.gitConfigUnsetAll(pushKey); err != nil {
		return err
	}
	for _, u := range urls {
		if err := g.gitConfigAdd(urlKey, u); err != nil {
			return err
		}
	}
	for _, u := range pushURLs {
		if err := g.gitConfigAdd(pushKey, u); err != nil {
			return err
		}
	}
	printf("Updated remote %s urls=%s pushurls=%s\n", remoteName, strings.Join(urls, ", "), strings.Join(pushURLs, ", "))
	return nil
}

// isTokenPushRemoteURL reports whether the remote URL can be used with a
// token-authenticated git push. Only https://github.com/ remotes and file://
// (local tests) are accepted so the token is not sent over plaintext HTTP or to
// arbitrary hosts.
func isTokenPushRemoteURL(u string) bool {
	return strings.HasPrefix(u, "https://github.com/") ||
		strings.HasPrefix(u, "file://")
}

// gitHTTPSAuthExtraHeader returns a git http.extraHeader value for GitHub
// HTTPS pushes. Git-over-HTTPS rejects Bearer for App/Vault tokens; use Basic
// with x-access-token (same scheme as observability-robots ingest-release-smoke).
//
// Caught by ingest-release-smoke build 8:
// https://buildkite.com/elastic/observability-robots-ingest-release-smoke/builds/8
func gitHTTPSAuthExtraHeader(token string) string {
	auth := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	return "Authorization: Basic " + auth
}

// gitPushEnv adds a process-local http.extraHeader via GIT_CONFIG_* so the
// token never appears in argv (keeps gosec G204 clean and out of process lists).
func gitPushEnv(baseEnv []string, token string) []string {
	return append(append([]string{}, baseEnv...),
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.extraHeader",
		"GIT_CONFIG_VALUE_0="+gitHTTPSAuthExtraHeader(token),
	)
}

// push pushes the current branch to the remote.
// It uses the git CLI (not go-git) so Buildkite reference clones can pack and
// upload objects from shared mirrors; go-git push hangs in that layout.
func (g *gitRepo) push(remoteName, token string) error {
	if token == "" {
		return fmt.Errorf("GitHub token is required for pushing")
	}
	if remoteName != "origin" {
		return fmt.Errorf("unsupported remote %q; release push only supports origin", remoteName)
	}

	if err := g.ensureHTTPSRemote(remoteName); err != nil {
		return err
	}

	currentBranch, err := g.getCurrentBranch()
	if err != nil {
		return err
	}

	printf("Pushing branch %s to remote origin via git CLI...\n", currentBranch)

	ctx, cancel := context.WithTimeout(context.Background(), pushTimeout)
	defer cancel()

	// Literal argv only (gosec G204). Auth is injected through GIT_CONFIG_* so
	// the token is not passed as a command-line argument. `git push origin HEAD`
	// updates the remote branch that matches the current local branch name.
	cmd := exec.CommandContext(ctx, "git", "push", "origin", "HEAD")
	cmd.Dir = g.path
	cmd.Env = gitPushEnv(os.Environ(), token)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("failed to push: timed out after %s: %w", pushTimeout, err)
		}
		return fmt.Errorf("failed to push: %w: %s", err, strings.TrimSpace(string(output)))
	}

	printf("Pushed branch %s to remote: origin\n", currentBranch)
	return nil
}

// getCurrentBranch returns the name of the current branch.
func (g *gitRepo) getCurrentBranch() (string, error) {
	headRef, err := g.repo.Head()
	if err != nil {
		return "", fmt.Errorf("failed to get HEAD: %w", err)
	}

	if !headRef.Name().IsBranch() {
		return "", fmt.Errorf("HEAD is not a branch")
	}

	return headRef.Name().Short(), nil
}

// isClean reports whether the working directory has no uncommitted changes.
// Uses git status --porcelain; go-git Status is too slow on Buildkite reference
// clones of large trees.
func (g *gitRepo) isClean() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), worktreeCmdTimeout)
	defer cancel()

	output, err := g.runGit(ctx, "status", "--porcelain")
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return false, fmt.Errorf("failed to get status: timed out after %s: %w", worktreeCmdTimeout, err)
		}
		return false, fmt.Errorf("failed to get status: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return len(strings.TrimSpace(string(output))) == 0, nil
}

// setRemoteURL sets the primary URL for origin (release push only uses origin).
func (g *gitRepo) setRemoteURL(url string) error {
	return g.setRemoteURLs("origin", []string{url})
}

// setRemoteURLs replaces all remote URLs (fetch + pushurl entries).
// When the remote already exists, fetch refspecs are preserved so later
// git fetch origin keeps working after an SSH→HTTPS rewrite.
func (g *gitRepo) setRemoteURLs(remoteName string, urls []string) error {
	if len(urls) == 0 {
		return fmt.Errorf("remote %s requires at least one URL", remoteName)
	}
	remote, err := g.repo.Remote(remoteName)
	if errors.Is(err, git.ErrRemoteNotFound) {
		_, err = g.repo.CreateRemote(&config.RemoteConfig{
			Name: remoteName,
			URLs: urls,
		})
		if err != nil {
			return fmt.Errorf("failed to create remote: %w", err)
		}
		printf("Created remote %s: %s\n", remoteName, strings.Join(urls, ", "))
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get remote: %w", err)
	}

	fetch := append([]config.RefSpec(nil), remote.Config().Fetch...)

	err = g.repo.DeleteRemote(remoteName)
	if err != nil {
		return fmt.Errorf("failed to delete remote: %w", err)
	}

	_, err = g.repo.CreateRemote(&config.RemoteConfig{
		Name:  remoteName,
		URLs:  urls,
		Fetch: fetch,
	})
	if err != nil {
		return fmt.Errorf("failed to recreate remote: %w", err)
	}

	printf("Updated remote %s: %s\n", remoteName, strings.Join(urls, ", "))
	return nil
}
