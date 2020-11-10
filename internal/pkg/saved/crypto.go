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

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"golang.org/x/crypto/pbkdf2"
)

const (
	tagLen           = 16
	keyLengthInBytes = 32
	keyIterations    = 10000
)

func encryptFields(key, aad []byte, fields Fields) error {

	for k, v := range fields {
		ciphertext, err := encrypt(key, aad, v)

		if err != nil {
			return err
		}
		fields[k] = ciphertext
	}

	return nil
}

func decryptFields(key, aad []byte, fields Fields) error {

	for k, v := range fields {
		ciphertext, ok := v.(string)
		if !ok {
			return ErrBadCipherText
		}

		v, err := decrypt(key, aad, ciphertext)

		if err != nil {
			return err
		}
		fields[k] = v
	}

	return nil
}

// see: https://github.com/elastic/node-crypto/blob/master/src/crypto.ts#L119
func encrypt(key, aad []byte, v interface{}) (string, error) {

	plaintext, err := json.Marshal(v)
	if err != nil {
		return "", err
	}

	// Generate random data for iv and salt
	nonce, err := newNonce()
	if err != nil {
		return "", err
	}

	dk := deriveKey(key, nonce.salt())

	block, err := aes.NewCipher(dk)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCMWithTagSize(block, tagLen)
	if err != nil {
		return "", err
	}

	ciphertext := aesgcm.Seal(nil, nonce.iv(), plaintext, aad)

	// Expects binary buffer [salt, iv, tag, encrypted]
	// goland slaps the tag on the back of the slice, so we have to reorg a bit
	tagOffset := len(ciphertext) - tagLen

	buf := bytes.Buffer{}
	buf.Grow(ivLen + saltLen + len(ciphertext))
	// Write salt:iv
	buf.Write(nonce.both())
	// Write tag
	buf.Write(ciphertext[tagOffset:])
	// Write cipher text
	buf.Write(ciphertext[:tagOffset])

	payload := base64.StdEncoding.EncodeToString(buf.Bytes())
	return payload, nil
}

func decrypt(key, aad []byte, cipherText string) (interface{}, error) {

	ciphertext, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}

	// expects header [salt, iv, tag, encrypted]
	if len(ciphertext) <= saltLen+ivLen+tagLen {
		return nil, ErrBadCipherText
	}

	tagOffset := saltLen + ivLen
	dataOffset := tagOffset + tagLen

	salt := ciphertext[:saltLen]
	iv := ciphertext[saltLen:tagOffset]
	tag := ciphertext[tagOffset:dataOffset]
	data := ciphertext[dataOffset:]

	dk := deriveKey(key, salt)

	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCMWithTagSize(block, tagLen)
	if err != nil {
		return nil, err
	}

	// aesgcm expects the tag to be after the ciphertext
	buf := bytes.Buffer{}
	buf.Grow(len(data) + len(tag))
	buf.Write(data)
	buf.Write(tag)

	plaintext, err := aesgcm.Open(nil, iv, buf.Bytes(), aad)
	if err != nil {
		return nil, err
	}

	// plaintext is raw JSON, decode
	var v interface{}
	err = json.Unmarshal(plaintext, &v)
	return v, err
}

func deriveKey(key, salt []byte) []byte {

	return pbkdf2.Key(
		[]byte(key),
		salt,
		keyIterations,
		keyLengthInBytes,
		sha512.New,
	)
}

// Emulate Additional Authenticated Data (AAD) generation in Kibana
// Effectively stable_stringify([ {namespace}, type, id, attributesAAD]);
//
func deriveAAD(ty, id, space string, attrs map[string]interface{}) ([]byte, error) {
	/*
		if len(attrs) == 0 {
			log.Debug().Str("type", ty).Str("id", id).Str("space", space).Msg("No AAD; that seems wrong.")
		}
	*/

	v := []interface{}{space, ty, id, attrs}

	if space == "" {
		v = v[1:]
	}

	// This MUST be stable; and 1x1 with what javascript stringify is doing.
	// Milage may vary; we may have to implement this manually depending on types and formatting.
	return json.Marshal(v)
}
