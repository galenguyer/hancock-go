package paths

import (
	"log"
	"os"
	"strings"
)

var (
	homeDir string
)

func init() {
	dirname, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	homeDir = dirname
}

func GetRootRsaKeyPath(baseDir string) string {
	return strings.TrimSuffix(strings.ReplaceAll(baseDir, "~", homeDir), "/") + "/private/ca.pem"
}
func GetRsaKeyPath(name string, baseDir string) (string, error) {
	err := os.MkdirAll(strings.TrimSuffix(strings.ReplaceAll(baseDir, "~", homeDir), "/")+"/certificates/"+name, 0755)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.ReplaceAll(baseDir, "~", homeDir), "/") + "/certificates/" + name + "/" + name + ".pem", nil
}

func GetCACertPath(baseDir string) string {
	return strings.TrimSuffix(strings.ReplaceAll(baseDir, "~", homeDir), "/") + "/certificates/ca.crt"
}
func GetCertPath(name string, baseDir string) (string, error) {
	err := os.MkdirAll(strings.TrimSuffix(strings.ReplaceAll(baseDir, "~", homeDir), "/")+"/certificates/"+name, 0755)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.ReplaceAll(baseDir, "~", homeDir), "/") + "/certificates/" + name + "/" + name + ".crt", nil
}

func GetCsrPath(name string, baseDir string) (string, error) {
	err := os.MkdirAll(strings.TrimSuffix(strings.ReplaceAll(baseDir, "~", homeDir), "/")+"/certificates/"+name, 0755)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.ReplaceAll(baseDir, "~", homeDir), "/") + "/certificates/" + name + "/" + name + ".csr", nil
}

func CreateDirectories(baseDir string) error {
	err := os.MkdirAll(strings.TrimSuffix(strings.ReplaceAll(baseDir, "~", homeDir), "/"), 0755)
	if err != nil {
		return err
	}
	err = os.MkdirAll(strings.TrimSuffix(strings.ReplaceAll(baseDir, "~", homeDir), "/")+"/private", 0755)
	if err != nil {
		return err
	}
	return os.MkdirAll(strings.TrimSuffix(strings.ReplaceAll(baseDir, "~", homeDir), "/")+"/certificates", 0755)
}
