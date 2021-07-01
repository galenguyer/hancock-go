package paths

import (
	"os"
	"strings"

	"github.com/galenguyer/hancock/config"
)

func GetRootRsaKeyPath(conf config.Config) string {
	return strings.TrimSuffix(conf.File.BaseDir, "/") + "/private/ca.pem"
}
func GetRsaKeyPath(name string, conf config.Config) (string, error) {
	err := os.MkdirAll(strings.TrimSuffix(conf.File.BaseDir, "/")+"/certificates/"+name, 0755)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(conf.File.BaseDir, "/") + "/certificates/" + name + "/" + name + ".pem", nil
}

func GetCACertPath(conf config.Config) string {
	return strings.TrimSuffix(conf.File.BaseDir, "/") + "/certificates/ca.crt"
}
func GetCertPath(name string, conf config.Config) (string, error) {
	err := os.MkdirAll(strings.TrimSuffix(conf.File.BaseDir, "/")+"/certificates/"+name, 0755)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(conf.File.BaseDir, "/") + "/certificates/" + name + "/" + name + ".crt", nil
}

func GetCsrPath(name string, conf config.Config) (string, error) {
	err := os.MkdirAll(strings.TrimSuffix(conf.File.BaseDir, "/")+"/certificates/"+name, 0755)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(conf.File.BaseDir, "/") + "/certificates/" + name + "/" + name + ".csr", nil
}

func CreateDirectories(conf config.Config) error {
	err := os.MkdirAll(strings.TrimSuffix(conf.File.BaseDir, "/"), 0755)
	if err != nil {
		return err
	}
	err = os.MkdirAll(strings.TrimSuffix(conf.File.BaseDir, "/")+"/private", 0755)
	if err != nil {
		return err
	}
	return os.MkdirAll(strings.TrimSuffix(conf.File.BaseDir, "/")+"/certificates", 0755)
}
