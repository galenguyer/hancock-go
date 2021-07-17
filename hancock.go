package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/galenguyer/hancock/certs"
	"github.com/galenguyer/hancock/keys"
	"github.com/galenguyer/hancock/paths"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
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
						Value:   "Contoso Root CA",
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
					&cli.StringFlag{
						Name:    "password",
						Aliases: []string{"p"},
						Value:   "",
					},
					&cli.BoolFlag{
						Name:  "no-password",
						Value: false,
					},
					&cli.StringFlag{
						Name:  "basedir",
						Value: "~/.ca",
					},
				},
				Action: func(c *cli.Context) error {
					return InitCA(
						c.Int("bits"),
						c.Int("lifetime"),
						c.String("commonname"),
						c.String("country"),
						c.String("state"),
						c.String("locality"),
						c.String("organization"),
						c.String("organizationalunit"),
						c.String("password"),
						c.Bool("no-password"),
						c.String("basedir"),
					)
				},
			},
			{
				// TODO: Support for multiple DNS names
				Name:    "new",
				Aliases: []string{"create"},
				Usage:   "sign a new key for a host",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:    "lifetime",
						Aliases: []string{"t"},
						Value:   90,
					},
					&cli.IntFlag{
						Name:    "bits",
						Aliases: []string{"b"},
						Value:   2048,
					},
					&cli.StringFlag{
						Name:    "name",
						Aliases: []string{"n"},
						Value:   "localhost",
					},
					&cli.StringFlag{
						Name:    "password",
						Aliases: []string{"p"},
						Value:   "",
					},
					&cli.StringFlag{
						Name:  "basedir",
						Value: "~/.ca",
					},
				},
				Action: func(c *cli.Context) error {
					return NewCert(
						c.Int("bits"),
						c.Int("lifetime"),
						c.String("name"),
						c.String("password"),
						c.String("basedir"),
					)
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func InitCA(bits, lifetime int, commonname, country, state, locality, organization, organizationalUnit, password string, noPassword bool, baseDir string) error {
	// create paths for generated files
	err := paths.CreateDirectories(baseDir)
	if err != nil {
		return err
	}

	// if root rsa key does not exist
	if _, err = os.Stat(paths.GetRootRsaKeyPath(baseDir)); os.IsNotExist(err) {
		// generate new root rsa key
		if err = newRootRsaKey(bits, password, noPassword, baseDir); err != nil {
			return err
		}
	} else {
		fmt.Println("not overwriting root rsa key")
	}

	// if the root ca certificate does not exist
	if _, err = os.Stat(paths.GetCACertPath(baseDir)); os.IsNotExist(err) {
		// generate new root ca certificate
		return newRootCACert(lifetime, commonname, country, state, locality, organization, organizationalUnit, password, baseDir)
	} else {
		fmt.Println("not overwriting root ca certificate")
	}
	return nil
}

func newRootRsaKey(bits int, password string, noPassword bool, baseDir string) error {
	fmt.Println("generating new root rsa key")
	// generate the root rsa key
	key, err := keys.GenerateRootRsaKey(bits)
	if err != nil {
		return err
	}

	var bytePassword, byteConfirmPassword []byte
	if !noPassword && password == "" {
		fmt.Print("enter password: ")
		bytePassword, err = term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return err
		}
		fmt.Print("\n")
		fmt.Print("confirm password: ")
		byteConfirmPassword, err = term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return err
		}
		fmt.Print("\n")

		if string(bytePassword) != string(byteConfirmPassword) {
			return errors.New("passwords do not match")
		}
	} else if password != "" {
		bytePassword = []byte(password)
	}

	// save root rsa key to disk
	return keys.SaveRootRsaKey(*key, string(bytePassword), baseDir)
}

func newRootCACert(lifetime int, commonname, country, province, locality, organization, organizationalUnit, password, baseDir string) error {
	fmt.Println("generating new ca certificate")
	// load the root rsa key from disk
	key, err := keys.GetRootRsaKey(password, baseDir)
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

func NewCert(bits, lifetime int, name, password, baseDir string) error {
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
	csr, err := certs.GenerateCsr(name, baseDir, *key)
	if err != nil {
		return err
	}
	err = certs.SaveCsr(name, csr, baseDir)
	if err != nil {
		return err
	}

	// sign and save the certificate
	rootKey, err := keys.GetRootRsaKey(password, baseDir)
	if err != nil {
		return err
	}
	cert, err := certs.GenerateCert(csr, lifetime, *rootKey, baseDir)
	if err != nil {
		return err
	}
	err = certs.SaveCert(cert, name, baseDir)
	if err != nil {
		return err
	}

	return nil
}
