package main

import (
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/goccy/go-yaml"
)

type Config struct {

	LogLevel   string           `yaml:"log_level"`

	Interfaces []InterfaceConfig `yaml:"interfaces" validate:"dive"`

	Rules      []Rule           `yaml:"rules" validate:"dive"`

}

type InterfaceConfig struct {
	Name  string `yaml:"name" validate:"required"`
	Group string `yaml:"group" validate:"required"`
}

type Rule struct {
	From   string   `yaml:"from" validate:"required"`
	To     []string `yaml:"to" validate:"required"`
	Filter Filter   `yaml:"filter"`
	Types  []string `yaml:"types"`
}

type Filter struct {
	AllowedIPs []string `yaml:"allowed_ips" validate:"dive,ip"`
	AllowedServices []string `yaml:"allowed_services"`
}

func LoadConfig(path string) (*Config, error) {

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	// Validate the config
	validate := validator.New()
	if err := validate.Struct(&config); err != nil {
		return nil, err
	}

	return &config, nil

}
