package config

type Config struct {
	Key struct {
		Bits               int    `yaml:"bits"`
		Lifetime           int    `yaml:"lifetime"`
		CommonName         string `yaml:"commonname"`
		Country            string `yaml:"country"`
		Province           string `yaml:"province"`
		Locality           string `yaml:"locality"`
		Organization       string `yaml:"organization"`
		OrganizationalUnit string `yaml:"unit"`
	} `yaml:"key"`
	File struct {
		BaseDir string `yaml:"basedir"`
	} `yaml:"file"`
}
