package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	LogLevel   string            `yaml:"log_level"`
	Interfaces []InterfaceConfig `yaml:"interfaces"`
	Rules      []Rule            `yaml:"rules"`
}

type InterfaceConfig struct {
	Name  string `yaml:"name"`
	Group string `yaml:"group"`
}

type Rule struct {
	From   string   `yaml:"from"`
	To     []string `yaml:"to"`
	Filter Filter   `yaml:"filter"`
	Types  []string `yaml:"types"` // "query" or "response"
}

type Filter struct {
	AllowedIPs      []string `yaml:"allowed_ips"`
	AllowedServices []string `yaml:"allowed_services"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Debug: print first 500 chars of config
	// log.Printf("Raw Config Content:\n%s", string(data))

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
