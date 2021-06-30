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
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return newConfig()
	} else {
		fmt.Printf("Config file %s exists already - do you want to overwrite it? [yN]: ", configPath)
		var prompt string
		_, err = fmt.Scanln(&prompt)
		if err != nil {
			return err
		}
		if strings.ToLower(prompt) == "y" {
			newConfig()
		} else {
			fmt.Println("not overwriting config and exiting")
			os.Exit(0)
		}
	}
	return nil
}

func newConfig() error {
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
	yamlBytes, err := yaml.Marshal(defaultConf)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(configPath, yamlBytes, 0644)
	if err != nil {
		return err
	}
	fmt.Printf("created new config file at %s\n", configPath)
	return nil

}

func readConfig() (*config.Config, error) {
	yamlFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var conf config.Config
	err = yaml.Unmarshal(yamlFile, conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}

func InitCA() error {
	conf, err := readConfig()
	if err != nil {
		return err
	}
	err = paths.CreateDirectories(*conf)
	if err != nil {
		return err
	}

	key, err := keys.GenerateRootRsaKey(*conf)
	if err != nil {
		return err
	}
	err = keys.SaveRootRsaKey(*key, *conf)
	if err != nil {
		return err
	}

	caCertBytes, err := certs.GenerateRootCACert(*key, *conf)
	if err != nil {
		return err
	}
	err = certs.SaveRootCACert(caCertBytes, *conf)
	if err != nil {
		return err
	}
	return nil
}
