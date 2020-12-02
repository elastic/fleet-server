// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package saved

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"unicode"
)

const (
	TagSaved   = "saved"
	TagAad     = "aad"
	TagEncrypt = "encrypt"
	TagJSON    = "json"
)

type tagOptions string

// From golang JSON code
func parseTag(tag string) (string, tagOptions) {
	if idx := strings.Index(tag, ","); idx != -1 {
		return tag[:idx], tagOptions(tag[idx+1:])
	}
	return tag, tagOptions("")
}

// From golang JSON code
func (o tagOptions) Contains(optionName string) bool {
	if len(o) == 0 {
		return false
	}
	s := string(o)
	for s != "" {
		var next string
		i := strings.Index(s, ",")
		if i >= 0 {
			s, next = s[:i], s[i+1:]
		}
		if s == optionName {
			return true
		}
		s = next
	}
	return false
}

// From golang JSON code
func isValidTag(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case strings.ContainsRune("!#$%&()*+-./:<=>?@[]^_{|}~ ", c):
			// Backslash and quote chars are reserved, but
			// otherwise any punctuation chars are allowed
			// in a tag name.
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			return false
		}
	}
	return true
}

// From golang JSON code
func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	}
	return false
}

func deriveFieldKey(field reflect.StructField) (string, tagOptions) {

	// Use json tag if available, otherwise lowercase name
	tag := field.Tag.Get(TagJSON)
	key, opts := parseTag(tag)

	if !isValidTag(key) {
		key = strings.ToLower(field.Name)
	}

	var out bytes.Buffer
	json.HTMLEscape(&out, []byte(key))

	return out.String(), opts
}

func gatherAAD(src interface{}) (Fields, Fields) {
	t := reflect.TypeOf(src)
	v := reflect.ValueOf(src)

	if t.Kind() == reflect.Ptr {
		v = v.Elem()
		t = reflect.TypeOf(v.Interface())
	}

	aad := make(Fields)
	encrypt := make(Fields)

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// Get the field tag value
		tag := field.Tag.Get(TagSaved)

		switch tag {
		case TagAad:
			key, _ := deriveFieldKey(field)
			aad[key] = v.Field(i).Interface()
		case TagEncrypt:
			key, _ := deriveFieldKey(field)
			encrypt[key] = v.Field(i).Interface()
		case "", "-":
		default:
			panic(fmt.Sprintf("Unknown tag %s:\"%s\"", TagSaved, tag))
		}
	}

	return aad, encrypt
}

func isEncrypted(src interface{}) bool {
	t := reflect.TypeOf(src)

	if t.Kind() == reflect.Ptr {
		v := reflect.ValueOf(src).Elem().Interface()
		t = reflect.TypeOf(v)
	}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// Get the field tag value
		tag := field.Tag.Get(TagSaved)

		switch tag {
		case TagEncrypt:
			return true
		case TagAad, "", "-":
		default:
			panic(fmt.Sprintf("Unknown tag %s:\"%s\"", TagSaved, tag))
		}
	}

	return false
}

func (m *mgr) encode(ty, id, space string, src interface{}) ([]byte, error) {
	if !isEncrypted(src) {
		return json.Marshal(src)
	}

	// scan for aad
	aadSet, encryptSet := gatherAAD(src)

	aad, err := deriveAAD(ty, id, space, aadSet)
	if err != nil {
		return nil, err
	}

	if err := encryptFields([]byte(m.key), aad, encryptSet); err != nil {
		return nil, err
	}

	fields := NewFields(src)

	for k, v := range encryptSet {
		fields[k] = v
	}

	return json.Marshal(fields)
}

func (m *mgr) decode(ty, id, space string, data []byte, dst interface{}) error {

	if err := json.Unmarshal(data, dst); err != nil {
		return err
	}

	if !isEncrypted(dst) {
		return nil
	}

	fields := NewFields(dst)

	// scan for aad, this will return empty values, but we need the keys
	aadSet, encryptSet := gatherAAD(dst)

	// Fix up aadSet with actual values retrieved from JSON
	for k, _ := range aadSet {
		aadSet[k] = fields[k]
	}

	aad, err := deriveAAD(ty, id, space, aadSet)
	if err != nil {
		return err
	}

	// Fix up encryptSet with actual values retrieved from JSON
	for k, _ := range encryptSet {
		encryptSet[k] = fields[k]
	}

	if err := decryptFields([]byte(m.key), aad, encryptSet); err != nil {
		return err
	}

	// Overlay encrypted values on fields
	for k, v := range encryptSet {
		fields[k] = v
	}

	return fields.MapInterface(dst)
}
