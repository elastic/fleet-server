// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package saved

import (
	"github.com/mitchellh/mapstructure"
	"reflect"
)

type Fields map[string]interface{}

func NewFields(src interface{}) Fields {
	t := reflect.TypeOf(src)
	v := reflect.ValueOf(src)

	if t.Kind() == reflect.Ptr {
		v = v.Elem()
		t = reflect.TypeOf(v.Interface())
	}

	nFields := v.NumField()

	m := make(Fields, nFields)

	for i := 0; i < nFields; i++ {
		key, opts := deriveFieldKey(t.Field(i))

		if key == "-" || (opts.Contains("omitempty") && isEmptyValue(v.Field(i))) {
			continue
		}

		m[key] = v.Field(i).Interface()
	}

	return m
}

func (f Fields) MapInterface(dst interface{}) error {

	config := &mapstructure.DecoderConfig{
		TagName: TagJSON,
		Result:  dst,
	}

	decoder, err := mapstructure.NewDecoder(config)
	if err != nil {
		return err
	}

	return decoder.Decode(f)
}
