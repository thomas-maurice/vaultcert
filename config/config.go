package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

// GetConfig returns an unmarshaled config
func GetConfig(filePath string) (*Config, error) {
	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = yaml.Unmarshal(b, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}
