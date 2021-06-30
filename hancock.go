package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
)

type Config struct {
	Key struct {
		Bits int `yaml:"bits"`
	} `yaml:"key"`
}

var (
	defaultConf = &Config{
		Key: struct {
			Bits int "yaml:\"bits\""
		}{
			Bits: 4096,
		},
	}
)

func main() {
	generateRootRsaKey(*defaultConf)
}

func generateRootRsaKey(conf Config) error {
	rootRsaKey, err := rsa.GenerateKey(rand.Reader, conf.Key.Bits)
	if err != nil {
		return err
	}
	fmt.Print(saveRootRsaKey(*rootRsaKey))
	return nil
}

func saveRootRsaKey(key rsa.PrivateKey) string {
	keyPem := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(&key)}
	bytes := pem.EncodeToMemory(keyPem)
	return string(bytes)
}

func getSerial() (*big.Int, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return big.NewInt(0), err
	}
	return serial, nil
}
