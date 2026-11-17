// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

// Shared test literals for goconst across release package tests.
const (
	testAuthorEmail       = "test@example.com"
	testAuthorName        = "Test User"
	testBaseBranch        = "main"
	testDefaultVersion940 = `const DefaultVersion = "9.4.0"`
	testDefaultVersion950 = `const DefaultVersion = "9.5.0"`
	testFFPrepMainBranch  = "ff-prep-main-9.6.0"
	testGitHubHTTPS       = "https://github.com/elastic/fleet-server.git"
	testGitHubHTTP        = "http://github.com/elastic/fleet-server.git"
	testGitHubSSH         = "git@github.com:elastic/fleet-server.git"
	testGitLabSSH         = "git@gitlab.com:group/repo.git"
	testInvalidFooPatch   = "9.foo.0"
	testPRBody            = "body"
	testPRURL10           = "https://github.com/elastic/fleet-server/pull/10"
	testPRURL11           = "https://github.com/elastic/fleet-server/pull/11"
	testPRURL12           = "https://github.com/elastic/fleet-server/pull/12"
	testPRURL15           = "https://github.com/elastic/fleet-server/pull/15"
	testReleaseBranch     = "9.6"
	testReviewerAlice     = "alice"
	testReviewerTeam      = "elastic/elastic-agent-control-plane"
	testVersion940        = "9.4.0"
	testVersion943        = "9.4.3"
	testVersion950        = "9.5.0"
	testVersionXY         = "9.5"
)
