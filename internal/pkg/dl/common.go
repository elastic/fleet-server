// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

type queryOption struct {
	indexName string
}

type Option func(opt *queryOption)

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
