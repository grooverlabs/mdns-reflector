package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validConfig = `
log_level: info
interfaces:
  - { name: "vlan.10", group: "users" }
  - { name: "vlan.19", group: "gl_iot" }
rules:
  - from: users
    to: [gl_iot]
    types: [query]
    filter:
      allowed_services: ["_ipp._tcp", "_airplay._tcp"]
  - from: gl_iot
    to: [users]
    types: [response]
    filter:
      allowed_ips: ["192.168.19.10"]
`

func TestParseConfigValid(t *testing.T) {
	cfg, err := parseConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Rules[1].isStateful() || cfg.Rules[1].window() != 60 {
		t.Errorf("stateful default: %v %d, want true 60", cfg.Rules[1].isStateful(), cfg.Rules[1].window())
	}
	if _, err := NewReflector(cfg); err != nil {
		t.Fatal(err)
	}

	optOut, err := parseConfig([]byte(strings.Replace(validConfig, "types: [response]", "types: [response]\n    stateful: false", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if optOut.Rules[1].isStateful() {
		t.Error("stateful: false ignored")
	}
}

// Review finding 10 (and 2: from in to; types required).
func TestParseConfigRejects(t *testing.T) {
	const ifaces = "interfaces:\n  - {name: a, group: g}\n  - {name: b, group: h}\n"
	cases := map[string]string{
		"empty to":            ifaces + "rules:\n  - from: g\n    to: []\n    types: [query]\n",
		"missing to":          ifaces + "rules:\n  - from: g\n    types: [query]\n",
		"bad type":            ifaces + "rules:\n  - from: g\n    to: [h]\n    types: [Query]\n",
		"missing types":       ifaces + "rules:\n  - from: g\n    to: [h]\n",
		"from in to":          ifaces + "rules:\n  - from: g\n    to: [h, g]\n    types: [query]\n",
		"duplicate interface": "interfaces:\n  - {name: a, group: g}\n  - {name: a, group: h}\nrules:\n  - from: g\n    to: [h]\n    types: [query]\n",
		"ipv6 allowed_ip":     ifaces + "rules:\n  - from: g\n    to: [h]\n    types: [response]\n    filter: {allowed_ips: ['fe80::1']}\n",
		"bad allowed_ip":      ifaces + "rules:\n  - from: g\n    to: [h]\n    types: [response]\n    filter: {allowed_ips: ['printer']}\n",
		"unknown rule key":    ifaces + "rules:\n  - from: g\n    to: [h]\n    types: [query]\n    statefull: true\n",
		"unknown top key":     ifaces + "rule:\n  - from: g\n    to: [h]\n    types: [query]\n",
		"unknown filter key":  ifaces + "rules:\n  - from: g\n    to: [h]\n    types: [query]\n    filter: {allowed_service: [_ipp._tcp]}\n",
		"undefined to group":  ifaces + "rules:\n  - from: g\n    to: [x]\n    types: [query]\n",
		"undefined from":      ifaces + "rules:\n  - from: x\n    to: [h]\n    types: [query]\n",
		"no interfaces":       "rules:\n  - from: g\n    to: [h]\n    types: [query]\n",
		"no rules":            ifaces,
		"bad log level":       "log_level: loud\n" + ifaces + "rules:\n  - from: g\n    to: [h]\n    types: [query]\n",
		"negative window":     ifaces + "rules:\n  - from: g\n    to: [h]\n    types: [response]\n    stateful_window: -1\n",
		"empty service":       ifaces + "rules:\n  - from: g\n    to: [h]\n    types: [query]\n    filter: {allowed_services: ['.']}\n",
	}
	for name, y := range cases {
		_, err := parseConfig([]byte(y))
		t.Logf("%-20s %v", name, err)
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadConfigFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err != nil {
		t.Fatal(err)
	}
}
