package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"

	"github.com/galenguyer/hancock/paths"
)

func GenerateCsr(name, baseDir string, key rsa.PrivateKey) ([]byte, error) {
	rootCACert, err := GetRootCACert(baseDir)
	if err != nil {
		return nil, err
	}

	subject := pkix.Name{
		CommonName:         name,
		Country:            rootCACert.Issuer.Country,
		Locality:           rootCACert.Issuer.Locality,
		Province:           rootCACert.Issuer.Province,
		Organization:       rootCACert.Issuer.Organization,
		OrganizationalUnit: rootCACert.Issuer.OrganizationalUnit,
	}
	template := x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	return x509.CreateCertificateRequest(rand.Reader, &template, &key)
}

func SaveCsr(name string, csrBytes []byte, baseDir string) error {
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}
	pemBytes := pem.EncodeToMemory(block)
	path, err := paths.GetCsrPath(name, baseDir)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, pemBytes, 0600)
}
