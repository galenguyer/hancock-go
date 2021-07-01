package main

import (
	"fmt"
	"log"
	"os"

	"github.com/galenguyer/hancock/certs"
	"github.com/galenguyer/hancock/keys"
	"github.com/galenguyer/hancock/paths"
	"github.com/urfave/cli/v2"
)

const (
	configPath = "./config.yaml"
)

func main() {
	app := &cli.App{
		Name: "hancock",
		Commands: []*cli.Command{
			{
				Name:  "init",
				Usage: "initialize the certificate authority",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:    "lifetime",
						Aliases: []string{"t"},
						Value:   10 * 365,
					},
					&cli.IntFlag{
						Name:    "bits",
						Aliases: []string{"b"},
						Value:   4096,
					},
					&cli.StringFlag{
						Name:    "commonname",
						Aliases: []string{"cn"},
						Value:   "Root CA",
					},
					&cli.StringFlag{
						Name:    "country",
						Aliases: []string{"c"},
						Value:   "US",
					},
					&cli.StringFlag{
						Name:    "state",
						Aliases: []string{"st"},
						Value:   "Washington",
					},
					&cli.StringFlag{
						Name:    "locality",
						Aliases: []string{"l"},
						Value:   "Redmond",
					},
					&cli.StringFlag{
						Name:    "organization",
						Aliases: []string{"o"},
						Value:   "Contoso",
					},
					&cli.StringFlag{
						Name:    "organizationalunit",
						Aliases: []string{"ou"},
						Value:   "Contoso",
					},
				},
				Action: func(c *cli.Context) error {
					return InitCA(
						c.Int("bits"),
						c.Int("lifetime"),
						c.String("commonname"),
						c.String("country"),
						c.String("province"),
						c.String("locality"),
						c.String("organization"),
						c.String("organizationalunit"),
						c.String("basedir"),
					)
				},
			},
			{
				Name:    "new",
				Aliases: []string{"create"},
				Usage:   "sign a new key for a host",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:    "lifetime",
						Aliases: []string{"t"},
						Value:   10 * 365,
					},
					&cli.IntFlag{
						Name:    "bits",
						Aliases: []string{"b"},
						Value:   4096,
					},
					&cli.StringFlag{
						Name:    "commonname",
						Aliases: []string{"cn"},
						Value:   "Root CA",
					},
					&cli.StringFlag{
						Name:    "country",
						Aliases: []string{"c"},
						Value:   "US",
					},
					&cli.StringFlag{
						Name:    "state",
						Aliases: []string{"st"},
						Value:   "Washington",
					},
					&cli.StringFlag{
						Name:    "locality",
						Aliases: []string{"l"},
						Value:   "Redmond",
					},
					&cli.StringFlag{
						Name:    "organization",
						Aliases: []string{"o"},
						Value:   "Contoso",
					},
					&cli.StringFlag{
						Name:    "organizationalunit",
						Aliases: []string{"ou"},
						Value:   "Contoso",
					},
				},
				Action: func(c *cli.Context) error {
					return NewCert(
						c.Int("bits"),
						c.Int("lifetime"),
						c.String("commonname"),
						c.String("country"),
						c.String("province"),
						c.String("locality"),
						c.String("organization"),
						c.String("organizationalunit"),
						c.String("basedir"),
					)
				},
			},
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "basedir",
				Value: "./.ca",
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func InitCA(bits, lifetime int, commonname, country, province, locality, organization, organizationalUnit, baseDir string) error {
	// create paths for generated files
	err := paths.CreateDirectories(baseDir)
	if err != nil {
		return err
	}

	// if root rsa key does not exist
	if _, err = os.Stat(paths.GetRootRsaKeyPath(baseDir)); os.IsNotExist(err) {
		// generate new root rsa key
		if err = newRootRsaKey(bits, baseDir); err != nil {
			return err
		}
	} else {
		fmt.Println("not overwriting root rsa key")
	}

	// if the root ca certificate does not exist
	if _, err = os.Stat(paths.GetCACertPath(baseDir)); os.IsNotExist(err) {
		// generate new root ca certificate
		return newRootCACert(lifetime, commonname, country, province, locality, organization, organizationalUnit, baseDir)
	} else {
		fmt.Println("not overwriting root ca certificate")
	}
	return nil
}

func newRootRsaKey(bits int, baseDir string) error {
	fmt.Println("generating new root rsa key")
	// generate the root rsa key
	key, err := keys.GenerateRootRsaKey(bits)
	if err != nil {
		return err
	}
	// save root rsa key to disk
	return keys.SaveRootRsaKey(*key, baseDir)
}

func newRootCACert(lifetime int, commonname, country, province, locality, organization, organizationalUnit, baseDir string) error {
	fmt.Println("generating new ca certificate")
	// load the root rsa key from disk
	key, err := keys.GetRootRsaKey(baseDir)
	if err != nil {
		return err
	}
	// generate a root certificate using the key and configuration
	caCertBytes, err := certs.GenerateRootCACert(*key, lifetime, commonname, country, province, locality, organization, organizationalUnit)
	if err != nil {
		return err
	}
	// write certificate to disk
	return certs.SaveRootCACert(caCertBytes, baseDir)
}

func NewCert(bits, lifetime int, name, country, province, locality, organization, organizationalUnit, baseDir string) error {
	// generate and write a new rsa key
	key, err := keys.GenerateRsaKey(bits)
	if err != nil {
		return err
	}
	err = keys.SaveRsaKey(*key, name, baseDir)
	if err != nil {
		return err
	}

	// generate and write a new csr
	csr, err := certs.GenerateCsr(name, *key, country, province, locality, organization, organizationalUnit)
	if err != nil {
		return err
	}
	err = certs.SaveCsr(name, csr, baseDir)
	if err != nil {
		return err
	}

	// sign and save the certificate
	rootKey, err := keys.GetRootRsaKey(baseDir)
	if err != nil {
		return err
	}
	cert, err := certs.GenerateCert(csr, *rootKey, baseDir)
	if err != nil {
		return err
	}
	err = certs.SaveCert(cert, name, baseDir)
	if err != nil {
		return err
	}

	return nil
}
