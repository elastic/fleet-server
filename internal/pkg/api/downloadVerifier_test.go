// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/openpgp"        //nolint:staticcheck // crypto/openpgp is only receiving security updates.
	"golang.org/x/crypto/openpgp/armor"  //nolint:staticcheck // crypto/openpgp is only receiving security updates.
	"golang.org/x/crypto/openpgp/errors" //nolint:staticcheck // crypto/openpgp is only receiving security updates.
)

const (
	pkg = "Hello, World!"
	sha = "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387 package"
)

func prepPackageAndSHA(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "package")
	err := os.WriteFile(path, []byte(pkg), 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(path+".sha512", []byte(sha), 0600)
	if err != nil {
		t.Fatal(err)
	}

	return path
}

func prepPGP(t *testing.T, path string) []byte {
	t.Helper()
	// sign file with new key
	e, err := openpgp.NewEntity("testing", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ascF, err := os.Create(path + ".asc")
	if err != nil {
		t.Fatal(err)
	}
	err = openpgp.ArmoredDetachSign(ascF, e, f, nil)
	if err != nil {
		t.Fatal(err)
	}

	// output public key
	var b bytes.Buffer
	w, err := armor.Encode(&b, openpgp.PublicKeyType, make(map[string]string))
	if err != nil {
		t.Fatal(err)
	}
	err = e.Serialize(w)
	if err != nil {
		t.Fatal(err)
	}
	err = w.Close()
	if err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestVerify(t *testing.T) {
	t.Run("sha512 verification succeeds", func(t *testing.T) {
		path := prepPackageAndSHA(t)

		v := &verifier{}
		err := v.Verify(path)
		assert.NoError(t, err)
	})

	t.Run("sha512 verification fails", func(t *testing.T) {
		path := prepPackageAndSHA(t)
		err := os.WriteFile(path+".sha512", []byte("deadbeef package"), 0600)
		if err != nil {
			t.Fatal(err)
		}

		v := &verifier{}
		err = v.Verify(path)
		assert.ErrorIs(t, err, ErrChecksumMismatch)
	})

	t.Run("gpg verification succeeds", func(t *testing.T) {
		path := prepPackageAndSHA(t)
		pgp := prepPGP(t, path)

		v := &verifier{pgp}
		err := v.Verify(path)
		assert.NoError(t, err)
	})

	t.Run("gpg verification fails", func(t *testing.T) {
		path := prepPackageAndSHA(t)
		pgp := prepPGP(t, path)
		_ = prepPGP(t, path) // generate a new pub key + asc sig, but we use the old one so it does not match

		v := &verifier{pgp}
		err := v.Verify(path)
		assert.ErrorIs(t, err, errors.ErrUnknownIssuer)
	})

	t.Run("gpg pub key invalid", func(t *testing.T) {
		path := prepPackageAndSHA(t)
		_ = prepPGP(t, path)

		v := &verifier{[]byte("badKey")}
		err := v.Verify(path)
		armorErr := errors.InvalidArgumentError("test") // just need this error type for comparison
		assert.ErrorAs(t, err, &armorErr)
	})
}
