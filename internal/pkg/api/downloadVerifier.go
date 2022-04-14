// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"bufio"
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/openpgp" //nolint:staticcheck // crypto/openpgp is only receiving security updates.
)

var ErrChecksumMismatch = fmt.Errorf("checksum mismatch")

// Verifier interface is used to verify downloaded packages.
type Verifier interface {
	Verify(path string) error
}

type verifier struct {
	pgp []byte
}

// NewVerifier returns a Verifier that uses the associated pgp key.
func NewVerifier(pgp []byte) Verifier {
	return &verifier{pgp}
}

// Verify will verify the package on path with the associated .sha512 and .asc files
// If no pgp key is provided .asc verification is skipped
func (v *verifier) Verify(path string) error {
	err := v.verifySHA512Hash(path)
	if err != nil {
		return fmt.Errorf("unable to verify sha512 for %q: %w", path, err)
	}
	// no pgp key will skip verification process
	if len(v.pgp) == 0 {
		return nil
	}
	err = v.verifyGPGSignature(path)
	if err != nil {
		return fmt.Errorf("unable to verify asc for %q: %w", path, err)
	}
	return nil
}

// verifySHA512Hash will compute the SHA512 of the package on path and compare it with the associated .sha512 file.
func (v *verifier) verifySHA512Hash(path string) error {
	expect, err := readSHA512(path)
	if err != nil {
		return err
	}

	path = filepath.Clean(path)
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer closeFile(f)

	hash := sha512.New()
	if _, err := io.Copy(hash, f); err != nil {
		return err
	}
	sum := hex.EncodeToString(hash.Sum(nil))

	if expect != sum {
		return ErrChecksumMismatch
	}
	return nil
}

// readSHA512 reads the checksum of the package on path from the associated .sha512 file
//
// logic is copied from the verifier in elastic-agent (pkg/artifact/download/verfifier.go).
func readSHA512(path string) (string, error) {
	f, err := os.Open(path + ".sha512")
	if err != nil {
		return "", err
	}
	defer closeFile(f)

	filename := filepath.Base(path)
	var sum string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) != 2 {
			// Ignore malformed.
			continue
		}

		lineFilename := strings.TrimLeft(parts[1], "*")
		if lineFilename != filename {
			// Continue looking for a match.
			continue
		}

		sum = parts[0]
	}

	if len(sum) == 0 {
		return "", fmt.Errorf("checksum for %q was not found in %q", filename, path+".sha512")
	}
	return sum, nil
}

// verifyGPGSignature verifies the GPG signature of a package.
// It accepts the path to the package to verify, and finds the .asc in the same directory.
// The verifier provides the public key.
// logic copied from elastic-agent (pkg/artifact/download/verifier.go).
func (v *verifier) verifyGPGSignature(path string) error {
	kr, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(v.pgp))
	if err != nil {
		return fmt.Errorf("failed to read armored key ring: %w", err)
	}

	asc, err := os.Open(path + ".asc")
	if err != nil {
		return err
	}
	defer closeFile(asc)

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer closeFile(f)

	_, err = openpgp.CheckArmoredDetachedSignature(kr, f, asc)
	return err
}
