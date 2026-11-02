package main

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/goccy/go-yaml"
)

const defaultStatefulWindow = 60 // seconds

type Config struct {
	LogLevel   string            `yaml:"log_level" validate:"omitempty,oneof=debug info warn error"`
	Interfaces []InterfaceConfig `yaml:"interfaces" validate:"required,min=1,dive"`
	Rules      []Rule            `yaml:"rules" validate:"required,min=1,dive"`
}

type InterfaceConfig struct {
	Name  string `yaml:"name" validate:"required"`
	Group string `yaml:"group" validate:"required"`
}

type Rule struct {
	From  string   `yaml:"from" validate:"required"`
	To    []string `yaml:"to" validate:"required,min=1,dive,required"`
	Types []string `yaml:"types" validate:"required,min=1,dive,oneof=query response"`
	// Stateful defaults to true: a response is reflected to an interface only
	// if that interface forwarded a query for a name the response answers
	// within StatefulWindow seconds. Set it to false to reflect every response.
	Stateful       *bool  `yaml:"stateful"`
	StatefulWindow int    `yaml:"stateful_window" validate:"gte=0"` // seconds; 0 means 60
	Filter         Filter `yaml:"filter"`
}

type Filter struct {
	AllowedIPs      []string `yaml:"allowed_ips" validate:"dive,ipv4"`
	AllowedServices []string `yaml:"allowed_services" validate:"dive,required,excludesall=\\"`
}

func (r *Rule) isStateful() bool { return r.Stateful == nil || *r.Stateful }

func (r *Rule) window() int {
	if r.StatefulWindow <= 0 {
		return defaultStatefulWindow
	}
	return r.StatefulWindow
}

func (r *Rule) hasType(t string) bool { return slices.Contains(r.Types, t) }

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseConfig(data)
}

func parseConfig(data []byte) (*Config, error) {
	var config Config
	if err := yaml.NewDecoder(bytes.NewReader(data), yaml.DisallowUnknownField()).Decode(&config); err != nil {
		return nil, err
	}

	if err := validator.New().Struct(&config); err != nil {
		return nil, err
	}

	groups := make(map[string]bool)
	names := make(map[string]bool)
	for _, iface := range config.Interfaces {
		if names[iface.Name] {
			return nil, fmt.Errorf("interface %q is listed more than once", iface.Name)
		}
		names[iface.Name] = true
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
			// Reflecting a group into itself bounces every packet between its
			// interfaces.
			if to == rule.From {
				return nil, fmt.Errorf("rule %d: group %q is both 'from' and 'to'", i, to)
			}
		}
		for _, s := range rule.Filter.AllowedServices {
			if strings.Trim(s, ".") == "" {
				return nil, fmt.Errorf("rule %d: empty allowed_services entry %q", i, s)
			}
		}
	}

	return &config, nil
}
