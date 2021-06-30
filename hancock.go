package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strings"
	"time"
)

type Config struct {
	Key struct {
		Bits     int `yaml:"bits"`
		Lifetime int `yaml:"lifetime"`
	} `yaml:"key"`
	File struct {
		BaseDir string `yaml:"basedir"`
	} `yaml:"file"`
}

var (
	defaultConf = &Config{
		Key: struct {
			Bits     int "yaml:\"bits\""
			Lifetime int "yaml:\"lifetime\""
		}{
			Bits:     4096,
			Lifetime: 10 * 365,
		},
		File: struct {
			BaseDir string "yaml:\"basedir\""
		}{
			BaseDir: "./.ca",
		},
	}
)

func main() {
	conf := defaultConf

	err := createDirectories(*conf)
	if err != nil {
		log.Fatalln(err)
	}

	key, err := generateRootRsaKey(*conf)
	if err != nil {
		log.Fatalln(err)
	}
	err = saveRootRsaKey(*key, *conf)
	if err != nil {
		log.Fatalln(err)
	}

	caCertBytes, err := generateRootCACert(*key, *conf)
	if err != nil {
		log.Fatalln(err)
	}
	err = saveRootCACert(caCertBytes, *conf)
	if err != nil {
		log.Fatalln(err)
	}
}

func createDirectories(conf Config) error {
	err := os.MkdirAll(strings.TrimSuffix(conf.File.BaseDir, "/"), 0755)
	if err != nil {
		return err
	}
	return os.MkdirAll(strings.TrimSuffix(conf.File.BaseDir, "/")+"/certificates", 0755)
}

func getRootRsaKeyPath(conf Config) string {
	return strings.TrimSuffix(conf.File.BaseDir, "/") + "/ca.pem"
}

func getCACertPath(conf Config) string {
	return strings.TrimSuffix(conf.File.BaseDir, "/") + "/certificates/ca.crt"
}

// TODO: password encryption of root rsa key
func generateRootRsaKey(conf Config) (*rsa.PrivateKey, error) {
	log.Printf("generating %d bit root rsa key\n", conf.Key.Bits)
	rootRsaKey, err := rsa.GenerateKey(rand.Reader, conf.Key.Bits)
	if err != nil {
		return nil, err
	}
	log.Println("generated root rsa key")
	return rootRsaKey, nil
}

func saveRootRsaKey(key rsa.PrivateKey, conf Config) error {
	log.Println("saving root rsa key to " + getRootRsaKeyPath(conf))
	keyPem := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(&key)}
	bytes := pem.EncodeToMemory(keyPem)
	err := ioutil.WriteFile(getRootRsaKeyPath(conf), bytes, 0600)
	if err != nil {
		return err
	}
	log.Println("saved root rsa key to " + getRootRsaKeyPath(conf))
	return nil
}

func generateRootCACert(rootKey rsa.PrivateKey, conf Config) ([]byte, error) {
	serial, err := getSerial()
	if err != nil {
		return nil, err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(conf.Key.Lifetime) * 24 * time.Hour).Add(-1 * time.Second)
	subject := pkix.Name{
		CommonName:         "Root CA",
		Country:            []string{"US"},
		Locality:           []string{"Redmond"},
		Province:           []string{"Washington"},
		Organization:       []string{"Contoso"},
		OrganizationalUnit: []string{"Contoso"},
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

func saveRootCACert(certBytes []byte, conf Config) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	err := ioutil.WriteFile(getCACertPath(conf), pemBytes, 0644)
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
