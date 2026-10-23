// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import "github.com/elastic/fleet-server/v7/internal/pkg/bulk"

type queryOption struct {
	indexName string
	bulkOpts  []bulk.Opt
	policyID  string
}

// Option for the operation being made
type Option func(opt *queryOption)

// WithIndexName adjust the index name for the operation
//
// Used really only for testing to use generated input names
func WithIndexName(name string) Option {
	return func(opt *queryOption) {
		opt.indexName = name
	}
}

// WithPolicyID restricts QueryLatestPolicies to the policy with the given ID.
//
// Without it, QueryLatestPolicies returns the latest revision of every policy.
func WithPolicyID(policyID string) Option {
	return func(opt *queryOption) {
		opt.policyID = policyID
	}
}

// WithBulkOpts passes additional bulk.Opt values to the underlying bulker call.
func WithBulkOpts(opts ...bulk.Opt) Option {
	return func(o *queryOption) {
		o.bulkOpts = append(o.bulkOpts, opts...)
	}
}

func newOption(defaultIndex string, opts ...Option) queryOption {
	o := queryOption{indexName: defaultIndex}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}
