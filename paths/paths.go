package paths

import (
	"os"
	"strings"

	"github.com/galenguyer/hancock/config"
)

func GetRootRsaKeyPath(conf config.Config) string {
	return strings.TrimSuffix(conf.File.BaseDir, "/") + "/private/ca.pem"
}

func GetCACertPath(conf config.Config) string {
	return strings.TrimSuffix(conf.File.BaseDir, "/") + "/certificates/ca.crt"
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
