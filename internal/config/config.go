// Package config parses dne's command-line flags into a typed Config
// that the manager wires into controller-runtime.
//
// Splitting parsing from main keeps validation testable without
// having to spin up a manager.
package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/labels"
)

// Config holds the validated runtime configuration. A zero Config is
// not valid — always go through ParseFlags or NewFromArgs.
type Config struct {
	Namespaces         []string
	LabelSelector      labels.Selector
	MetricsBindAddress string
	HealthBindAddress  string
	LeaderElection     bool
	LeaderElectionID   string
	LogLevel           string
}

// Defaults returns a Config populated with conservative defaults that
// match the Helm chart's default values.yaml.
func Defaults() Config {
	return Config{
		Namespaces:         nil,
		LabelSelector:      labels.Everything(),
		MetricsBindAddress: ":8080",
		HealthBindAddress:  ":8081",
		LeaderElection:     false,
		LeaderElectionID:   "dne.dgamo.github.io",
		LogLevel:           "info",
	}
}

// Register binds Config flags onto fs. The receiver captures the raw
// string forms; call Validate after fs.Parse to populate the typed
// fields.
func (c *Config) Register(fs *pflag.FlagSet) {
	fs.StringSliceVar(&c.Namespaces, "namespaces", c.Namespaces, "Comma-separated list of namespaces to watch. Empty (default) means cluster-wide.")
	fs.Var(newSelectorFlag(&c.LabelSelector), "label-selector", "Standard Kubernetes label selector applied to Secrets at the watch layer (e.g. 'dne.k8s.io/watch=true'). Empty (default) means no filter.")
	fs.StringVar(&c.MetricsBindAddress, "metrics-bind-address", c.MetricsBindAddress, "Address the metrics endpoint binds to.")
	fs.StringVar(&c.HealthBindAddress, "health-probe-bind-address", c.HealthBindAddress, "Address the healthz/readyz endpoints bind to.")
	fs.BoolVar(&c.LeaderElection, "leader-elect", c.LeaderElection, "Enable leader election. Only useful when running multiple replicas.")
	fs.StringVar(&c.LeaderElectionID, "leader-election-id", c.LeaderElectionID, "Lease object name used for leader election.")
	fs.StringVar(&c.LogLevel, "log-level", c.LogLevel, "Log level (debug, info, warn, error).")
}

// Validate normalises and checks the parsed config. Call it after
// fs.Parse.
func (c *Config) Validate() error {
	if c.LabelSelector == nil {
		c.LabelSelector = labels.Everything()
	}
	c.Namespaces = normaliseNamespaces(c.Namespaces)
	if c.MetricsBindAddress == "" {
		return errors.New("--metrics-bind-address must not be empty (use ':0' to disable)")
	}
	if c.HealthBindAddress == "" {
		return errors.New("--health-probe-bind-address must not be empty")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("--log-level: %q is not one of debug|info|warn|error", c.LogLevel)
	}
	return nil
}

// NewFromArgs parses args into a Config. Exposed for tests; production
// uses Register + a shared pflag.FlagSet.
func NewFromArgs(args []string) (Config, error) {
	cfg := Defaults()
	fs := pflag.NewFlagSet("dne", pflag.ContinueOnError)
	cfg.Register(fs)
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func normaliseNamespaces(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		ns := strings.TrimSpace(raw)
		if ns == "" {
			continue
		}
		if _, dup := seen[ns]; dup {
			continue
		}
		seen[ns] = struct{}{}
		out = append(out, ns)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// selectorFlag implements pflag.Value for labels.Selector so invalid
// selectors fail at flag-parse time rather than at watch setup.
type selectorFlag struct {
	target *labels.Selector
	raw    string
}

func newSelectorFlag(target *labels.Selector) *selectorFlag {
	return &selectorFlag{target: target}
}

func (s *selectorFlag) String() string {
	if s == nil || s.raw == "" {
		return ""
	}
	return s.raw
}

func (s *selectorFlag) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		*s.target = labels.Everything()
		s.raw = ""
		return nil
	}
	sel, err := labels.Parse(v)
	if err != nil {
		return fmt.Errorf("parse label selector %q: %w", v, err)
	}
	*s.target = sel
	s.raw = v
	return nil
}

func (s *selectorFlag) Type() string { return "labelSelector" }

// HasNamespaceFilter reports whether the config restricts to specific namespaces.
func (c Config) HasNamespaceFilter() bool {
	return len(c.Namespaces) > 0
}

// HasLabelFilter reports whether the config has a non-empty label selector.
func (c Config) HasLabelFilter() bool {
	return c.LabelSelector != nil && !c.LabelSelector.Empty()
}
