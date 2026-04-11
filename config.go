package main

import (
	"fmt"
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/goccy/go-yaml"
)

type Config struct {
	Interfaces []InterfaceConfig `yaml:"interfaces" validate:"dive"`
	Rules      []Rule            `yaml:"rules" validate:"dive"`
}

type InterfaceConfig struct {
	Name  string `yaml:"name" validate:"required"`
	Group string `yaml:"group" validate:"required"`
}

type Rule struct {
	From           string   `yaml:"from" validate:"required"`
	To             []string `yaml:"to" validate:"required"`
	Filter         Filter   `yaml:"filter"`
	Types          []string `yaml:"types"`
	Stateful       bool     `yaml:"stateful"`
	StatefulWindow int      `yaml:"stateful_window"` // seconds; defaults to 60 if omitted
}

type Filter struct {
	AllowedIPs      []string `yaml:"allowed_ips" validate:"dive,ip"`
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

	// Apply defaults
	for i := range config.Rules {
		if config.Rules[i].Stateful && config.Rules[i].StatefulWindow <= 0 {
			config.Rules[i].StatefulWindow = 60
		}
	}

	// Validate that rule groups reference defined interfaces
	groups := make(map[string]bool)
	for _, iface := range config.Interfaces {
		groups[iface.Group] = true
	}
	for i, rule := range config.Rules {
		if !groups[rule.From] {
			return nil, fmt.Errorf("rule %d: 'from' group %q is not defined in interfaces", i, rule.From)
		}
		for _, to := range rule.To {
			if !groups[to] {
				return nil, fmt.Errorf("rule %d: 'to' group %q is not defined in interfaces", i, to)
			}
		}
	}

	return &config, nil

}
