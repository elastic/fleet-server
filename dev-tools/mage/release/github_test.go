// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/google/go-github/v68/github"
)

const (
	testAPIPullsPath    = "/repos/elastic/fleet-server/pulls"
	testAPIReleasesPath = "/repos/elastic/fleet-server/releases"
	testAPITagsPath     = "/repos/elastic/fleet-server/tags"
)

func newTestGitHubClient(t *testing.T, handler http.Handler) *gitHubClient {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client := github.NewClient(server.Client())
	baseURL, err := url.Parse(server.URL + "/")
	require.NoError(t, err)
	client.BaseURL = baseURL
	client.UploadURL = baseURL

	return &gitHubClient{
		client: client,
		ctx:    context.Background(),
	}
}

func TestCreatePRIdempotent(t *testing.T) {
	createCalls := 0
	existingPR := &github.PullRequest{
		Number:  new(42),
		HTMLURL: new("https://github.com/elastic/fleet-server/pull/42"),
		Head: &github.PullRequestBranch{
			Ref: new("9.5"),
		},
		Base: &github.PullRequestBranch{
			Ref: new("main"),
		},
		State: new("open"),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == testAPIPullsPath:
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode([]*github.PullRequest{existingPR}); err != nil {
				t.Errorf("failed to encode PR list response: %v", err)
			}
		case r.Method == http.MethodPost && r.URL.Path == testAPIPullsPath:
			createCalls++
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = fmt.Fprint(w, `{"message":"Validation Failed","errors":[{"message":"A pull request already exists for elastic:9.5."}]}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})

	ghClient := newTestGitHubClient(t, handler)
	opts := prOptions{
		Owner: releasesLookupOwner,
		Repo:  releasesLookupRepo,
		Title: "[Release][9.5.0] Prepare release branch",
		Head:  "9.5",
		Base:  testBaseBranch,
		Body:  "Release PR body",
	}

	pr, err := ghClient.createPR(opts)
	require.NoError(t, err)

	if pr.GetNumber() != 42 {
		t.Errorf("createPR() number = %d, want 42", pr.GetNumber())
	}
	if createCalls != 0 {
		t.Errorf("createPR() called create API %d times, want 0", createCalls)
	}

	pr2, err := ghClient.createPR(opts)
	require.NoError(t, err)
	if pr2.GetNumber() != pr.GetNumber() {
		t.Errorf("createPR() second call number = %d, want %d", pr2.GetNumber(), pr.GetNumber())
	}
	if createCalls != 0 {
		t.Errorf("createPR() called create API %d times after second call, want 0", createCalls)
	}
}

func TestLatestReleaseBeforeUsesReleasesWhenPresent(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == testAPIReleasesPath:
			w.Header().Set("Content-Type", "application/json")
			releases := []*github.RepositoryRelease{
				{TagName: new("v9.5.1")},
				{TagName: new("v9.4.3")},
				{TagName: new("v8.19.1")},
			}
			if err := json.NewEncoder(w).Encode(releases); err != nil {
				t.Errorf("failed to encode releases: %v", err)
			}
		case r.Method == http.MethodGet && r.URL.Path == testAPITagsPath:
			t.Errorf("ListTags should not be called when releases exist")
			http.NotFound(w, r)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})

	ghClient := newTestGitHubClient(t, handler)
	got, err := ghClient.latestReleaseBefore(releasesLookupOwner, releasesLookupRepo, "9.6.0")
	require.NoError(t, err)
	if got != "9.5.1" {
		t.Errorf("latestReleaseBefore() = %q, want 9.5.1", got)
	}
}

func TestLatestReleaseBeforeFallsBackToTagsWhenReleasesEmpty(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == testAPIReleasesPath:
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode([]*github.RepositoryRelease{}); err != nil {
				t.Errorf("failed to encode empty releases: %v", err)
			}
		case r.Method == http.MethodGet && r.URL.Path == testAPITagsPath:
			w.Header().Set("Content-Type", "application/json")
			tags := []*github.RepositoryTag{
				{Name: new("v9.4.4")},
				{Name: new("v9.4.3")},
				{Name: new("v9.3.8")},
				{Name: new("v8.19.1")},
				{Name: new("not-a-version")},
			}
			if err := json.NewEncoder(w).Encode(tags); err != nil {
				t.Errorf("failed to encode tags: %v", err)
			}
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})

	ghClient := newTestGitHubClient(t, handler)
	got, err := ghClient.latestReleaseBefore(releasesLookupOwner, releasesLookupRepo, "9.6.0")
	require.NoError(t, err)
	if got != "9.4.4" {
		t.Errorf("latestReleaseBefore() = %q, want 9.4.4", got)
	}
}

func TestCreatePRCreatesWhenNoneExists(t *testing.T) {
	createCalls := 0
	newPR := &github.PullRequest{
		Number:  new(99),
		HTMLURL: new("https://github.com/elastic/fleet-server/pull/99"),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == testAPIPullsPath:
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode([]*github.PullRequest{}); err != nil {
				t.Errorf("failed to encode empty PR list response: %v", err)
			}
		case r.Method == http.MethodPost && r.URL.Path == testAPIPullsPath:
			createCalls++
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(newPR); err != nil {
				t.Errorf("failed to encode create PR response: %v", err)
			}
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})

	ghClient := newTestGitHubClient(t, handler)
	pr, err := ghClient.createPR(prOptions{
		Owner: releasesLookupOwner,
		Repo:  releasesLookupRepo,
		Title: "New release PR",
		Head:  testReleaseBranch,
		Base:  testBaseBranch,
		Body:  testPRBody,
	})
	require.NoError(t, err)
	if pr.GetNumber() != 99 {
		t.Errorf("createPR() number = %d, want 99", pr.GetNumber())
	}
	if createCalls != 1 {
		t.Errorf("createPR() called create API %d times, want 1", createCalls)
	}
}

func TestSplitPRReviewers(t *testing.T) {
	users, teams := splitPRReviewers([]string{
		testReviewerTeam,
		"some-user",
		" elastic/other-team ",
		"",
		"  ",
		"solo",
	})
	if got, want := strings.Join(users, ","), "some-user,solo"; got != want {
		t.Errorf("users = %q, want %q", got, want)
	}
	if got, want := strings.Join(teams, ","), "elastic-agent-control-plane,other-team"; got != want {
		t.Errorf("teams = %q, want %q", got, want)
	}
}

func TestCreatePRRequestsTeamReviewers(t *testing.T) {
	newPR := &github.PullRequest{
		Number:  new(7),
		HTMLURL: new("https://github.com/elastic/fleet-server/pull/7"),
	}
	var reviewersBody github.ReviewersRequest

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == testAPIPullsPath:
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode([]*github.PullRequest{}); err != nil {
				t.Errorf("failed to encode empty PR list response: %v", err)
			}
		case r.Method == http.MethodPost && r.URL.Path == testAPIPullsPath:
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(newPR); err != nil {
				t.Errorf("failed to encode create PR response: %v", err)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/repos/elastic/fleet-server/pulls/7/requested_reviewers":
			if err := json.NewDecoder(r.Body).Decode(&reviewersBody); err != nil {
				t.Errorf("failed to decode reviewers request: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(newPR); err != nil {
				t.Errorf("failed to encode reviewers response: %v", err)
			}
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})

	ghClient := newTestGitHubClient(t, handler)
	_, err := ghClient.createPR(prOptions{
		Owner:     releasesLookupOwner,
		Repo:      releasesLookupRepo,
		Title:     "Release PR",
		Head:      testFFPrepMainBranch,
		Base:      testBaseBranch,
		Body:      testPRBody,
		Reviewers: []string{testReviewerTeam, testReviewerAlice},
	})
	require.NoError(t, err)
	if len(reviewersBody.Reviewers) != 1 || reviewersBody.Reviewers[0] != testReviewerAlice {
		t.Errorf("Reviewers = %v, want [alice]", reviewersBody.Reviewers)
	}
	if len(reviewersBody.TeamReviewers) != 1 || reviewersBody.TeamReviewers[0] != "elastic-agent-control-plane" {
		t.Errorf("TeamReviewers = %v, want [elastic-agent-control-plane]", reviewersBody.TeamReviewers)
	}
}
