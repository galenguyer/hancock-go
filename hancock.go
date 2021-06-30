package main

import (
	"log"

	"github.com/galenguyer/hancock/certs"
	"github.com/galenguyer/hancock/config"
	"github.com/galenguyer/hancock/keys"
	"github.com/galenguyer/hancock/paths"
)

var (
	defaultConf = &config.Config{
		Key: struct {
			Bits               int    "yaml:\"bits\""
			Lifetime           int    "yaml:\"lifetime\""
			CommonName         string "yaml:\"commonname\""
			Country            string "yaml:\"country\""
			Province           string "yaml:\"province\""
			Locality           string "yaml:\"locality\""
			Organization       string "yaml:\"organization\""
			OrganizationalUnit string "yaml:\"unit\""
		}{
			Bits:               4096,
			Lifetime:           3650,
			CommonName:         "Root CA",
			Country:            "US",
			Province:           "Washington",
			Locality:           "Redmond",
			Organization:       "Contoso",
			OrganizationalUnit: "Contoso",
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

	err := paths.CreateDirectories(*conf)
	if err != nil {
		log.Fatalln(err)
	}

	key, err := keys.GenerateRootRsaKey(*conf)
	if err != nil {
		log.Fatalln(err)
	}
	err = keys.SaveRootRsaKey(*key, *conf)
	if err != nil {
		log.Fatalln(err)
	}

	caCertBytes, err := certs.GenerateRootCACert(*key, *conf)
	if err != nil {
		log.Fatalln(err)
	}
	err = certs.SaveRootCACert(caCertBytes, *conf)
	if err != nil {
		log.Fatalln(err)
	}
}
