package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"net"
	"regexp"
	"strings"

	"github.com/galenguyer/hancock/paths"
)

const ipRegex = `((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))`

func GenerateCsr(name, san, baseDir string, key rsa.PrivateKey) ([]byte, error) {
	//rootCACert, err := GetRootCACert(baseDir)
	// if err != nil {
	// 	return nil, err
	// }

	subject := pkix.Name{
		CommonName: name,
		// Country:            rootCACert.Issuer.Country,
		// Locality:           rootCACert.Issuer.Locality,
		// Province:           rootCACert.Issuer.Province,
		// Organization:       rootCACert.Issuer.Organization,
		// OrganizationalUnit: rootCACert.Issuer.OrganizationalUnit,
	}
	var dnsNames []string
	var ipAddresses []net.IP
	if match, _ := regexp.Match(ipRegex, []byte(name)); match {
		ipAddresses = append(ipAddresses, net.ParseIP(name))
	} else {
		dnsNames = append(dnsNames, name)
	}
	for _, s := range strings.Split(san, " ") {
		if match, _ := regexp.Match(ipRegex, []byte(s)); match {
			ipAddresses = append(ipAddresses, net.ParseIP(s))
		} else {
			dnsNames = append(dnsNames, s)
		}
	}
	template := x509.CertificateRequest{
		Subject:            subject,
		DNSNames:           dnsNames,
		IPAddresses:        ipAddresses,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	return x509.CreateCertificateRequest(rand.Reader, &template, &key)
}

func SaveCsr(name string, csrBytes []byte, baseDir string) error {
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}
	pemBytes := pem.EncodeToMemory(block)
	path, err := paths.GetCsrPath(name, baseDir)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, pemBytes, 0600)
}
