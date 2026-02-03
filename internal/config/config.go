package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type ApiConfig struct {
	Port string
	Env  string
}

type Config struct {
	Authorize struct {
		MandatoryState bool `yaml:"mandatory_state"`
	} `yaml:"authorize"`
}

func Load() ApiConfig {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "development"
	}

	return ApiConfig{
		Port: port,
		Env:  env,
	}
}

func LoadConfig(filename string) (*Config, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var config Config
	decoder := yaml.NewDecoder(f)
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}
