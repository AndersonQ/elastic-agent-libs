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

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/elastic/elastic-agent-libs/testing/certutil"
)

func main() {
	var caPath, caKeyPath, dest, name, ipList string
	flag.StringVar(&caPath, "ca", "",
		"File path for CA in PEM format")
	flag.StringVar(&caKeyPath, "ca-key", "",
		"File path for the CA key in PEM format")
	flag.StringVar(&caKeyPath, "dest", "",
		"Directory to save the generated files")
	flag.StringVar(&name, "name", "localhost",
		"used as \"distinguished name\" and \"Subject Alternate Name values\" for the child certificate")
	flag.StringVar(&ipList, "ips", "127.0.0.1",
		"a comma separated list of IP addresses for the child certificate")
	flag.Parse()

	if caPath == "" && caKeyPath != "" || caPath != "" && caKeyPath == "" {
		flag.Usage()
		fmt.Fprintf(flag.CommandLine.Output(),
			"Both 'ca' and 'ca-key' must be specified, or neither should be provided.\nGot ca: %s, ca-key: %s\n",
			caPath, caKeyPath)

	}

	ips := strings.Split(ipList, ",")
	var netIPs []net.IP
	for _, ip := range ips {
		netIPs = append(netIPs, net.ParseIP(ip))
	}

	var ca certutil.CA
	var err error
	// if caPath == "" && caKeyPath == "" {
	ca, err = certutil.NewCA()
	if err != nil {
		panic(fmt.Errorf("could not create root CA certificate: %w", err))
	}

	savePair(dest, "ca", ca.Pair)
	// }

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic(fmt.Errorf("could not create private key: %w", err))
	}

	csr := x509.CertificateRequest{
		// RawSubjectPublicKeyInfo: pubKeyDERBytes,
		Subject: pkix.Name{
			CommonName:         "Temporal Proxy",
			Country:            []string{"Gallifrey"},
			Province:           []string{"Time Proxy"},
			Locality:           []string{"TARDIS"},
			Organization:       []string{"Time Lords"},
			OrganizationalUnit: []string{"Temporal Mechanics", "Proxy"},
		},
		DNSNames:       []string{name},
		EmailAddresses: []string{"temporal.proxy@time-lords.time"},
		IPAddresses:    netIPs,
	}
	certDERBytes, err := ca.GenerateFromCSR(csr, &privateKey.PublicKey)
	if err != nil {
		panic(fmt.Errorf("could not GenerateFromCSR: %w", err))
	}

	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		panic(fmt.Errorf("could not marshal private key: %w", err))
	}

	// PEM private key
	var privBytesOut []byte
	privateKeyBuff := bytes.NewBuffer(privBytesOut)
	err = pem.Encode(privateKeyBuff, &pem.Block{
		Type: "EC PRIVATE KEY", Bytes: privateKeyDER})
	if err != nil {
		panic(fmt.Errorf("could not pem.Encode private key: %w", err))
	}

	// PEM certificate
	var certBytesOut []byte
	certBuff := bytes.NewBuffer(certBytesOut)
	err = pem.Encode(certBuff, &pem.Block{
		Type: "CERTIFICATE", Bytes: certDERBytes})
	if err != nil {
		panic(fmt.Errorf("could not pem.Encode certificate: %w", err))
	}

	savePair(dest, name, certutil.Pair{
		Cert: certBuff.Bytes(),
		Key:  privateKeyBuff.Bytes(),
	})
}

func loadCA(caPath string, keyPath string) (crypto.PrivateKey, *x509.Certificate) {
	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		panic(fmt.Errorf("failed reading CA file: %w", err))
	}

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		panic(fmt.Errorf("failed reading CA key file: %w", err))
	}

	tlsCert, err := tls.X509KeyPair(caBytes, keyBytes)
	if err != nil {
		panic(fmt.Errorf("failed generating TLS key pair: %w", err))
	}

	rootCACert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		panic(fmt.Errorf("could not parse certificate: %w", err))
	}

	return tlsCert.PrivateKey, rootCACert
}

func savePair(dest string, name string, pair certutil.Pair) {
	err := os.WriteFile(filepath.Join(dest, name+".pem"), pair.Cert, 0o600)
	if err != nil {
		panic(fmt.Errorf("could not save %s certificate: %w", name, err))
	}

	err = os.WriteFile(filepath.Join(dest, name+"_key.pem"), pair.Key, 0o600)
	if err != nil {
		panic(fmt.Errorf("could not save %s certificate key: %w", name, err))
	}
}
