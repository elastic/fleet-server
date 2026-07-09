// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/google/go-github/v68/github"
)

// GitHubClient wraps the GitHub API client.
type GitHubClient struct {
	client *github.Client
	ctx    context.Context
}

// NewGitHubClient creates a new GitHub client with authentication.
func NewGitHubClient(token string) *GitHubClient {
	return &GitHubClient{
		client: github.NewClient(nil).WithAuthToken(token),
		ctx:    context.Background(),
	}
}

// NewGitHubClientFromEnv creates a GitHub client using GITHUB_TOKEN env var.
func NewGitHubClientFromEnv() (*GitHubClient, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN environment variable not set")
	}
	return NewGitHubClient(token), nil
}

// PROptions contains options for creating a pull request.
type PROptions struct {
	Owner string
	Repo  string
	Title string
	Head  string
	Base  string
	Body  string
}

// FindOpenPR returns an open pull request matching head and base, or nil if none exists.
func (gh *GitHubClient) FindOpenPR(owner, repo, head, base string) (*github.PullRequest, error) {
	headRef := fmt.Sprintf("%s:%s", owner, head)
	prs, _, err := gh.client.PullRequests.List(gh.ctx, owner, repo, &github.PullRequestListOptions{
		State: "open",
		Head:  headRef,
		Base:  base,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list pull requests: %w", err)
	}
	if len(prs) == 0 {
		return nil, nil
	}
	return prs[0], nil
}

// CreatePR creates a new pull request.
// If an open pull request already exists for the same head and base, it is returned instead.
func (gh *GitHubClient) CreatePR(opts PROptions, dryRun bool) (*github.PullRequest, error) {
	if dryRun {
		fmt.Printf("  [DRY RUN] Would create PR:\n")
		fmt.Printf("    Title: %s\n", opts.Title)
		fmt.Printf("    Head: %s\n", opts.Head)
		fmt.Printf("    Base: %s\n", opts.Base)
		return nil, nil
	}

	existing, err := gh.FindOpenPR(opts.Owner, opts.Repo, opts.Head, opts.Base)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		fmt.Printf("  Pull request already exists: #%d %s\n", existing.GetNumber(), existing.GetHTMLURL())
		return existing, nil
	}

	pr, _, err := gh.client.PullRequests.Create(gh.ctx, opts.Owner, opts.Repo, &github.NewPullRequest{
		Title: github.String(opts.Title),
		Head:  github.String(opts.Head),
		Base:  github.String(opts.Base),
		Body:  github.String(opts.Body),
	})
	if err != nil {
		var ghErr *github.ErrorResponse
		if errors.As(err, &ghErr) && ghErr.Response != nil && ghErr.Response.StatusCode == 422 {
			existing, findErr := gh.FindOpenPR(opts.Owner, opts.Repo, opts.Head, opts.Base)
			if findErr == nil && existing != nil {
				fmt.Printf("  Pull request already exists: #%d %s\n", existing.GetNumber(), existing.GetHTMLURL())
				return existing, nil
			}
		}
		return nil, fmt.Errorf("failed to create PR: %w", err)
	}

	fmt.Printf("✓ Created PR #%d: %s\n", pr.GetNumber(), pr.GetHTMLURL())
	return pr, nil
}
