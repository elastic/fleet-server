// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// validatecerts is a script to ensure that certs used in e2e tests can be parsed by tlscommon
package main

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: go run ./dev-tools/e2e/validatecerts.go [CERT_DIR]")
	}

	var (
		certDir  = os.Args[1]
		caFile   = filepath.Join(certDir, "e2e-test-ca.crt")
		certFile = filepath.Join(certDir, "fleet-server.crt")
		keyFile  = filepath.Join(certDir, "fleet-server.key")
		passFile = filepath.Join(certDir, "passphrase")
	)

	config := tlscommon.Config{
		CAs: []string{
			caFile,
		},
		Certificate: tlscommon.CertificateConfig{
			Certificate:    certFile,
			Key:            keyFile,
			PassphrasePath: passFile,
		},
	}

	_, err := tlscommon.LoadTLSConfig(&config)
	if err != nil {
		log.Print(err)
		passphrase, err := os.ReadFile(passFile)
		if err != nil {
			log.Fatal(err)
		}
		keyPEM, err := tlscommon.ReadPEMFile(logp.NewLogger("certs"), keyFile, string(passphrase))
		if err != nil {
			log.Fatal("reading pem:", err)
		}

		keyDER, _ := pem.Decode(keyPEM)
		log.Print("Key DER Block Type: ", keyDER.Type)

		_, err = x509.ParsePKCS1PrivateKey(keyDER.Bytes)
		if err != nil {
			log.Print("parsing PKCS1: ", err)
		}

		_, err = x509.ParsePKCS8PrivateKey(keyDER.Bytes)
		if err != nil {
			log.Print("parsing PKCS8: ", err)
		}

		_, err = x509.ParseECPrivateKey(keyDER.Bytes)
		if err != nil {
			log.Print("parsing EC: ", err)
		}

		log.Fatal()
	}
}
