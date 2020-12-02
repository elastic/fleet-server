// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package saved

type optionsT struct {
	Id         string
	Space      string
	Overwrite  bool
	Flush      bool
	Refresh    bool
	References []string
}

func (c optionsT) Validate() error {
	// TODO: validate Space
	// TODO: validate Id
	// TODO: validate References
	return nil
}

type Option func(*optionsT)

func WithId(id string) Option {
	return func(opt *optionsT) {
		opt.Id = id
	}
}

func WithSpace(space string) Option {
	return func(opt *optionsT) {
		opt.Space = space
	}
}

func WithOverwrite() Option {
	return func(opt *optionsT) {
		opt.Overwrite = true
	}
}

func WithFlush() Option {
	return func(opt *optionsT) {
		opt.Flush = true
	}
}

func WithRefresh() Option {
	return func(opt *optionsT) {
		opt.Refresh = true
	}
}

func WithRefs(refs []string) Option {
	return func(opt *optionsT) {
		opt.References = refs
	}
}

func processOpts(options ...Option) (opts optionsT, err error) {
	for _, optF := range options {
		optF(&opts)
	}

	err = opts.Validate()
	return
}

func validateType(ty string) error {
	// TODO: check for invalidate runes
	if ty == "" {
		return ErrNoType
	}
	return nil
}

func validateId(id string) error {
	// TODO: check for invalidate runes
	if id == "" {
		return ErrNoId
	}
	return nil
}
