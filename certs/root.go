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

	"github.com/galenguyer/hancock/config"
	"github.com/galenguyer/hancock/paths"
)

func GenerateRootCACert(rootKey rsa.PrivateKey, conf config.Config) ([]byte, error) {
	serial, err := getSerial()
	if err != nil {
		return nil, err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(conf.Key.Lifetime) * 24 * time.Hour).Add(-1 * time.Second)
	subject := pkix.Name{
		CommonName:         conf.Key.CommonName,
		Country:            []string{conf.Key.Country},
		Locality:           []string{conf.Key.Locality},
		Province:           []string{conf.Key.Province},
		Organization:       []string{conf.Key.Organization},
		OrganizationalUnit: []string{conf.Key.OrganizationalUnit},
	}
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
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &rootKey.PublicKey, &rootKey)
	if err != nil {
		return nil, err
	}
	return certBytes, nil
}

func SaveRootCACert(certBytes []byte, conf config.Config) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	err := ioutil.WriteFile(paths.GetCACertPath(conf), pemBytes, 0644)
	if err != nil {
		return err
	}
	return nil
}

func getSerial() (*big.Int, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	return serial, nil
}
