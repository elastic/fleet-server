// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

type queryOption struct {
	indexName string
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

func newOption(defaultIndex string, opts ...Option) queryOption {
	o := queryOption{indexName: defaultIndex}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}
