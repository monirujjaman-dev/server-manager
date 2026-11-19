// Package config loads YAML configuration files with environment-variable overrides.
//
// Fields are mapped from YAML with `yaml` tags. A field with an `env:"NAME"` tag can be
// overridden by the environment variable prefix+NAME. Unknown YAML keys are rejected so
// that typos in security-relevant settings do not go unnoticed.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Load fills dst (a pointer to a struct that already holds defaults) from the YAML file
// at path, if path is not empty, and then from environment variables starting with prefix.
func Load(path, prefix string, dst any) error {
	return load(path, prefix, dst, os.LookupEnv)
}

func load(path, prefix string, dst any, lookup func(string) (string, bool)) error {
	rv := reflect.ValueOf(dst)
	if rv.Kind() != reflect.Pointer || rv.Elem().Kind() != reflect.Struct {
		return errors.New("config: destination must be a pointer to a struct")
	}
	if path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // path is an operator-supplied config file
		if err != nil {
			return fmt.Errorf("config: read %s: %w", path, err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		// An empty file decodes to io.EOF; treat it as "no settings".
		if err := dec.Decode(dst); err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("config: parse %s: %w", path, err)
		}
	}
	return applyEnv(rv.Elem(), prefix, lookup)
}

var durationType = reflect.TypeFor[time.Duration]()

func applyEnv(v reflect.Value, prefix string, lookup func(string) (string, bool)) error {
	t := v.Type()
	for i := range t.NumField() {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		fv := v.Field(i)
		if field.Type.Kind() == reflect.Struct && field.Type != durationType {
			if err := applyEnv(fv, prefix, lookup); err != nil {
				return err
			}
			continue
		}
		name, ok := field.Tag.Lookup("env")
		if !ok || name == "" {
			continue
		}
		name = prefix + name
		raw, ok := lookup(name)
		if !ok {
			continue
		}
		if err := setValue(fv, raw); err != nil {
			return fmt.Errorf("config: env %s: %w", name, err)
		}
	}
	return nil
}

func setValue(fv reflect.Value, raw string) error {
	if fv.Type() == durationType {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return err
		}
		fv.SetInt(int64(d))
		return nil
	}
	switch fv.Kind() {
	case reflect.String:
		fv.SetString(raw)
	case reflect.Bool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return err
		}
		fv.SetBool(b)
	case reflect.Int, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(raw, 10, fv.Type().Bits())
		if err != nil {
			return err
		}
		fv.SetInt(n)
	case reflect.Uint, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(raw, 10, fv.Type().Bits())
		if err != nil {
			return err
		}
		fv.SetUint(n)
	case reflect.Slice:
		if fv.Type().Elem().Kind() != reflect.String {
			return fmt.Errorf("unsupported slice type %s", fv.Type())
		}
		var parts []string
		for p := range strings.SplitSeq(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				parts = append(parts, p)
			}
		}
		fv.Set(reflect.ValueOf(parts))
	default:
		return fmt.Errorf("unsupported field type %s", fv.Type())
	}
	return nil
}
