package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"time"

	"github.com/galenguyer/hancock/paths"
)

func GenerateRootCACert(rootKey rsa.PrivateKey, lifetime int, commonName, country, state, locality, organization, organizationalUnit string) ([]byte, error) {
	serial, err := getSerial()
	if err != nil {
		return nil, err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(lifetime) * 24 * time.Hour).Add(-1 * time.Second)

	subject := pkix.Name{
		CommonName: commonName,
	}
	if country != "" {
		subject.Country = []string{country}
	}
	if locality != "" {
		subject.Locality = []string{locality}
	}
	if state != "" {
		subject.Province = []string{state}
	}
	if organization != "" {
		subject.Organization = []string{organization}
	}
	if organizationalUnit != "" {
		subject.OrganizationalUnit = []string{organizationalUnit}
	}

	parentTemplate := &x509.Certificate{}
	template := &x509.Certificate{
		Subject:               subject,
		SerialNumber:          serial,
		PublicKeyAlgorithm:    x509.RSA,
		PublicKey:             rootKey.PublicKey,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return x509.CreateCertificate(rand.Reader, template, parentTemplate, &rootKey.PublicKey, &rootKey)
}

func SaveRootCACert(certBytes []byte, baseDir string) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	return ioutil.WriteFile(paths.GetCACertPath(baseDir), pemBytes, 0644)
}

func GetRootCACert(baseDir string) (*x509.Certificate, error) {
	bytes, err := ioutil.ReadFile(paths.GetCACertPath(baseDir))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)
	return x509.ParseCertificate(block.Bytes)
}

func getSerial() (*big.Int, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	return serial, nil
}
