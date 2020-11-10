// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

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
