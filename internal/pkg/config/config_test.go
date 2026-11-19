package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

type nested struct {
	Level string `yaml:"level" env:"LOG_LEVEL"`
}

type testConfig struct {
	Listen   string        `yaml:"listen" env:"LISTEN"`
	Interval time.Duration `yaml:"interval" env:"INTERVAL"`
	Debug    bool          `yaml:"debug" env:"DEBUG"`
	Workers  int           `yaml:"workers" env:"WORKERS"`
	Names    []string      `yaml:"names" env:"NAMES"`
	NoEnv    string        `yaml:"no_env"`
	Log      nested        `yaml:"log"`
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDefaultsFileAndEnv(t *testing.T) {
	cfg := testConfig{Listen: ":1", Interval: time.Second, Workers: 1}
	path := writeFile(t, "listen: \":2\"\ninterval: 5s\nnames: [a, b]\nlog:\n  level: warn\n")
	env := map[string]string{"SM_WORKERS": "8", "SM_DEBUG": "true", "SM_LOG_LEVEL": "debug", "SM_NAMES": "x, y,,z"}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	if err := load(path, "SM_", &cfg, lookup); err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":2" || cfg.Interval != 5*time.Second {
		t.Errorf("file values not applied: %+v", cfg)
	}
	if cfg.Workers != 8 || !cfg.Debug || cfg.Log.Level != "debug" {
		t.Errorf("env values not applied: %+v", cfg)
	}
	if got := cfg.Names; len(got) != 3 || got[0] != "x" || got[2] != "z" {
		t.Errorf("names = %v", got)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	var cfg testConfig
	if err := load(writeFile(t, "lisen: typo\n"), "SM_", &cfg, func(string) (string, bool) { return "", false }); err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestLoadEmptyFile(t *testing.T) {
	cfg := testConfig{Listen: ":1"}
	if err := load(writeFile(t, ""), "SM_", &cfg, func(string) (string, bool) { return "", false }); err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":1" {
		t.Errorf("default overwritten: %q", cfg.Listen)
	}
}

func TestLoadBadEnvValue(t *testing.T) {
	var cfg testConfig
	lookup := func(k string) (string, bool) { return "notaduration", k == "SM_INTERVAL" }
	if err := load("", "SM_", &cfg, lookup); err == nil {
		t.Fatal("expected error for bad duration")
	}
}
