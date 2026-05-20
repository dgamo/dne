package config_test

import (
	"reflect"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/labels"

	"github.com/dgamo/dne/internal/config"
)

func TestDefaults(t *testing.T) {
	cfg, err := config.NewFromArgs(nil)
	if err != nil {
		t.Fatalf("parse defaults: %v", err)
	}
	if cfg.HasNamespaceFilter() {
		t.Errorf("default should be cluster-wide, got namespaces=%v", cfg.Namespaces)
	}
	if cfg.HasLabelFilter() {
		t.Errorf("default should have no label filter, got %v", cfg.LabelSelector)
	}
	if cfg.MetricsBindAddress != ":8080" || cfg.HealthBindAddress != ":8081" {
		t.Errorf("default bind addresses wrong: %q / %q", cfg.MetricsBindAddress, cfg.HealthBindAddress)
	}
	if cfg.LeaderElection {
		t.Error("default leader election should be off")
	}
}

func TestNamespacesParsing(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{name: "single", args: []string{"--namespaces=kube-system"}, want: []string{"kube-system"}},
		{name: "comma list", args: []string{"--namespaces=a,b,c"}, want: []string{"a", "b", "c"}},
		{name: "whitespace trimmed", args: []string{"--namespaces= a , b "}, want: []string{"a", "b"}},
		{name: "duplicates dropped", args: []string{"--namespaces=a,a,b,a"}, want: []string{"a", "b"}},
		{name: "empty entries dropped", args: []string{"--namespaces=,a,,b,"}, want: []string{"a", "b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.NewFromArgs(tc.args)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !reflect.DeepEqual(cfg.Namespaces, tc.want) {
				t.Errorf("got %v, want %v", cfg.Namespaces, tc.want)
			}
		})
	}
}

func TestLabelSelectorParsing(t *testing.T) {
	cases := []struct {
		name      string
		args      []string
		wantMatch map[string]string
		wantSkip  map[string]string
		wantErr   bool
	}{
		{
			name:      "equality",
			args:      []string{"--label-selector=dne.k8s.io/watch=true"},
			wantMatch: map[string]string{"dne.k8s.io/watch": "true"},
			wantSkip:  map[string]string{"dne.k8s.io/watch": "false"},
		},
		{
			name:      "set-based in",
			args:      []string{"--label-selector=env in (prod,staging)"},
			wantMatch: map[string]string{"env": "prod"},
			wantSkip:  map[string]string{"env": "dev"},
		},
		{
			name:      "set-based exists",
			args:      []string{"--label-selector=watch"},
			wantMatch: map[string]string{"watch": "yes"},
			wantSkip:  map[string]string{"other": "yes"},
		},
		{
			name:      "set-based negation",
			args:      []string{"--label-selector=!disabled"},
			wantMatch: map[string]string{"foo": "bar"},
			wantSkip:  map[string]string{"disabled": "any"},
		},
		{name: "invalid", args: []string{"--label-selector=not!a!selector"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.NewFromArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !cfg.HasLabelFilter() {
				t.Fatalf("expected a label filter, selector=%v", cfg.LabelSelector)
			}
			if !cfg.LabelSelector.Matches(labels.Set(tc.wantMatch)) {
				t.Errorf("expected selector to match %v, got %v", tc.wantMatch, cfg.LabelSelector)
			}
			if cfg.LabelSelector.Matches(labels.Set(tc.wantSkip)) {
				t.Errorf("expected selector NOT to match %v, got %v", tc.wantSkip, cfg.LabelSelector)
			}
		})
	}
}

func TestEmptyLabelSelectorClearsFilter(t *testing.T) {
	cfg, err := config.NewFromArgs([]string{"--label-selector="})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.HasLabelFilter() {
		t.Errorf("explicit empty selector should disable filter, got %v", cfg.LabelSelector)
	}
}

func TestInvalidBindAddress(t *testing.T) {
	_, err := config.NewFromArgs([]string{"--metrics-bind-address="})
	if err == nil {
		t.Fatal("expected error on empty metrics-bind-address")
	}
}

func TestInvalidLogLevel(t *testing.T) {
	_, err := config.NewFromArgs([]string{"--log-level=quiet"})
	if err == nil {
		t.Fatal("expected error on bad log-level")
	}
}

func TestLeaderElectionFlag(t *testing.T) {
	cfg, err := config.NewFromArgs([]string{"--leader-elect=true"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cfg.LeaderElection {
		t.Error("--leader-elect=true should enable leader election")
	}
}

func TestHelpDoesntPanic(t *testing.T) {
	// pflag.ContinueOnError returns ErrHelp without panicking; ensure
	// NewFromArgs surfaces it as a normal error.
	_, err := config.NewFromArgs([]string{"--help"})
	if err == nil {
		t.Fatal("expected an error from --help")
	}
	if !strings.Contains(err.Error(), "help") && !strings.Contains(err.Error(), "pflag: help") {
		// Not a strict check; pflag's help error message varies.
		t.Logf("got error: %v", err)
	}
}
