package config

import (
	"os"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

type ApiConfig struct {
	Port   string
	Env    string
	Issuer string
}

type Config struct {
	Authorize struct {
		MandatoryState bool `yaml:"mandatory_state"`
	} `yaml:"authorize"`
}

func Load() ApiConfig {
	_ = godotenv.Load()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "development"
	}

	issuer := os.Getenv("ISSUER")
	if issuer == "" {
		issuer = "http://localhost:" + port
	}

	return ApiConfig{
		Port:   port,
		Env:    env,
		Issuer: issuer,
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
