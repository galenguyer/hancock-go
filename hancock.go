package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/galenguyer/hancock/certs"
	"github.com/galenguyer/hancock/config"
	"github.com/galenguyer/hancock/keys"
	"github.com/galenguyer/hancock/paths"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
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
				Usage: "initialize the app",
				Subcommands: []*cli.Command{
					{
						Name:  "config",
						Usage: "create a new configuration file with all defaults",
						Action: func(c *cli.Context) error {
							return InitConfig()
						},
					},
					{
						Name:  "ca",
						Usage: "initialize a new ca from the configuration file",
						Action: func(c *cli.Context) error {
							return InitCA()
						},
					},
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func InitConfig() error {
	// if the config path does not exist
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// create a new config
		return newConfig()
	} else {
		// else prompt for overwrite
		fmt.Printf("config file %s exists already - do you want to overwrite it? [yN]: ", configPath)
		var prompt string
		if _, err = fmt.Scanln(&prompt); err != nil {
			return err
		}
		// if we got y create a new config
		if strings.ToLower(prompt) == "y" {
			return newConfig()
		} else {
			// else state we won't overwrite and exit
			fmt.Println("not overwriting config")
		}
	}
	return nil
}

func newConfig() error {
	// stet up a default configuration object
	defaultConf := &config.Config{
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
	// marshall the object into yaml bytes
	yamlBytes, err := yaml.Marshal(defaultConf)
	if err != nil {
		return err
	}
	// write the config bytes to disk
	err = ioutil.WriteFile(configPath, yamlBytes, 0644)
	if err != nil {
		return err
	}
	fmt.Printf("created new config file at %s\n", configPath)
	return nil

}

func readConfig() (*config.Config, error) {
	// load bytes from disk
	yamlFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	// unmarshall bytes into struct
	var conf config.Config
	err = yaml.Unmarshal(yamlFile, &conf)
	if err != nil {
		return nil, err
	}
	// return config struct
	return &conf, nil
}

func InitCA() error {
	// load config from disk
	conf, err := readConfig()
	if err != nil {
		return err
	}
	// create paths for generated files
	err = paths.CreateDirectories(*conf)
	if err != nil {
		return err
	}

	// if root rsa key does not exist
	if _, err = os.Stat(paths.GetRootRsaKeyPath(*conf)); os.IsNotExist(err) {
		// generate new root rsa key
		return newRootRsaKey()
	} else {
		// else prompt for overwrite
		fmt.Printf("root rsa key %s exists already - do you want to overwrite it? [yN]: ", paths.GetRootRsaKeyPath(*conf))
		var prompt string
		if _, err = fmt.Scanln(&prompt); err != nil {
			return err
		}
		if strings.ToLower(prompt) == "y" {
			// if we got y create the new key
			return newRootRsaKey()
		} else {
			// else state we won't overwrite it and exit
			fmt.Println("not overwriting root rsa key")
		}
	}

	// if the root ca certificate does not exist
	if _, err = os.Stat(paths.GetCACertPath(*conf)); os.IsNotExist(err) {
		// generate new root ca certificate
		return newRootCACert()
	} else {
		// else prompt for overwrite
		fmt.Printf("root ca certificate %s exists already - do you want to overwrite it? [yN]: ", paths.GetCACertPath(*conf))
		var prompt string
		if _, err = fmt.Scanln(&prompt); err != nil {
			return err
		}
		if strings.ToLower(prompt) == "y" {
			// if we got y create the new certificate
			return newRootCACert()
		} else {
			// else state we won't overwrite it and continue
			fmt.Println("not overwriting root ca certificate")
		}
	}
	return nil
}

func newRootRsaKey() error {
	fmt.Println("generating new root rsa key")
	// load configuration from disk
	conf, err := readConfig()
	if err != nil {
		return err
	}
	// generate the root rsa key
	key, err := keys.GenerateRootRsaKey(*conf)
	if err != nil {
		return err
	}
	// save root rsa key to disk
	return keys.SaveRootRsaKey(*key, *conf)
}

func newRootCACert() error {
	fmt.Println("generating new ca certificate")
	// load the config from disk
	conf, err := readConfig()
	if err != nil {
		return err
	}
	// load the root rsa key from disk
	key, err := keys.GetRootRsaKey(*conf)
	if err != nil {
		return err
	}
	// generate a root certificate using the key and configuration
	caCertBytes, err := certs.GenerateRootCACert(*key, *conf)
	if err != nil {
		return err
	}
	// write certificate to disk
	return certs.SaveRootCACert(caCertBytes, *conf)
}
