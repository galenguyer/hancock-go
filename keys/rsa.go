package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"github.com/galenguyer/hancock/config"
	"github.com/galenguyer/hancock/paths"
)

// TODO: password encryption of root rsa key
func GenerateRootRsaKey(conf config.Config) (*rsa.PrivateKey, error) {
	rootRsaKey, err := rsa.GenerateKey(rand.Reader, conf.Key.Bits)
	if err != nil {
		return nil, err
	}
	return rootRsaKey, nil
}

func SaveRootRsaKey(key rsa.PrivateKey, conf config.Config) error {
	keyPem := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(&key)}
	bytes := pem.EncodeToMemory(keyPem)
	err := ioutil.WriteFile(paths.GetRootRsaKeyPath(conf), bytes, 0600)
	if err != nil {
		return err
	}
	return nil
}

func GetRootRsaKey(conf config.Config) (*rsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(paths.GetRootRsaKeyPath(conf))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}
