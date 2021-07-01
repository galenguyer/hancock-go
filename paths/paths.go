package paths

import (
	"os"
	"strings"
)

func GetRootRsaKeyPath(baseDir string) string {
	return strings.TrimSuffix(baseDir, "/") + "/private/ca.pem"
}
func GetRsaKeyPath(name string, baseDir string) (string, error) {
	err := os.MkdirAll(strings.TrimSuffix(baseDir, "/")+"/certificates/"+name, 0755)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(baseDir, "/") + "/certificates/" + name + "/" + name + ".pem", nil
}

func GetCACertPath(baseDir string) string {
	return strings.TrimSuffix(baseDir, "/") + "/certificates/ca.crt"
}
func GetCertPath(name string, baseDir string) (string, error) {
	err := os.MkdirAll(strings.TrimSuffix(baseDir, "/")+"/certificates/"+name, 0755)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(baseDir, "/") + "/certificates/" + name + "/" + name + ".crt", nil
}

func GetCsrPath(name string, baseDir string) (string, error) {
	err := os.MkdirAll(strings.TrimSuffix(baseDir, "/")+"/certificates/"+name, 0755)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(baseDir, "/") + "/certificates/" + name + "/" + name + ".csr", nil
}

func CreateDirectories(baseDir string) error {
	err := os.MkdirAll(strings.TrimSuffix(baseDir, "/"), 0755)
	if err != nil {
		return err
	}
	err = os.MkdirAll(strings.TrimSuffix(baseDir, "/")+"/private", 0755)
	if err != nil {
		return err
	}
	return os.MkdirAll(strings.TrimSuffix(baseDir, "/")+"/certificates", 0755)
}
