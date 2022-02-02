package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"time"

	"github.com/galenguyer/hancock/paths"
)

func GenerateCert(csrBytes []byte, lifetime int, rootKey rsa.PrivateKey, baseDir string) ([]byte, error) {
	rootCACert, err := GetRootCACert(baseDir)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}

	serial, err := getSerial()
	if err != nil {
		return nil, err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(lifetime) * 24 * time.Hour).Add(-1 * time.Second)

	template := &x509.Certificate{
		Subject:               csr.Subject,
		SerialNumber:          serial,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	return x509.CreateCertificate(rand.Reader, template, rootCACert, csr.PublicKey, &rootKey)
}

func SaveCert(certBytes []byte, name, baseDir string) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	path, err := paths.GetCertPath(name, baseDir)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, pemBytes, 0644)
}

func GetCert(name, baseDir string) (*x509.Certificate, error) {
	path, err := paths.GetCertPath(name, baseDir)
	if err != nil {
		return nil, err
	}
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)
	return x509.ParseCertificate(block.Bytes)
}
