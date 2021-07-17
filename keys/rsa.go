package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"github.com/galenguyer/hancock/paths"
)

// TODO: password encryption of root rsa key
func GenerateRootRsaKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

func GenerateRsaKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

func SaveRootRsaKey(key rsa.PrivateKey, password string, baseDir string) error {
	keyPem := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(&key)}

	if password != "" {
		var err error
		keyPem, err = x509.EncryptPEMBlock(rand.Reader, keyPem.Type, keyPem.Bytes, []byte(password), x509.PEMCipherAES256)
		if err != nil {
			return err
		}
	}

	bytes := pem.EncodeToMemory(keyPem)
	err := ioutil.WriteFile(paths.GetRootRsaKeyPath(baseDir), bytes, 0600)
	if err != nil {
		return err
	}
	return nil
}

func SaveRsaKey(key rsa.PrivateKey, name string, baseDir string) error {
	keyPem := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(&key)}
	bytes := pem.EncodeToMemory(keyPem)
	path, err := paths.GetRsaKeyPath(name, baseDir)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path, bytes, 0600)
	if err != nil {
		return err
	}
	return nil
}

func GetRootRsaKey(baseDir string) (*rsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(paths.GetRootRsaKeyPath(baseDir))
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
