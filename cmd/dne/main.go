// Command dne runs the Do-Not-Expire controller: it watches Secrets,
// parses certificates from them, and exposes Prometheus metrics for
// the certificate validity windows.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"
	"go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/dgamo/dne/internal/config"
	"github.com/dgamo/dne/internal/controller"
	"github.com/dgamo/dne/internal/metrics"
)

// Version is overridden at build time via -ldflags="-X main.Version=...".
var Version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "dne: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg := config.Defaults()
	fs := pflag.NewFlagSet("dne", pflag.ContinueOnError)
	cfg.Register(fs)
	showVersion := fs.Bool("version", false, "Print version and exit.")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println(Version)
		return nil
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	logger := zap.New(zap.UseDevMode(false), zap.Level(zapLevel(cfg.LogLevel)))
	ctrl.SetLogger(logger)
	setupLog := ctrl.Log.WithName("setup")

	setupLog.Info("starting dne",
		"version", Version,
		"namespaces", cfg.Namespaces,
		"labelSelector", cfg.LabelSelector.String(),
		"leaderElection", cfg.LeaderElection,
	)

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return fmt.Errorf("register client-go scheme: %w", err)
	}

	cacheOpts := cache.Options{}
	if cfg.HasNamespaceFilter() {
		cacheOpts.DefaultNamespaces = make(map[string]cache.Config, len(cfg.Namespaces))
		for _, ns := range cfg.Namespaces {
			cacheOpts.DefaultNamespaces[ns] = cache.Config{}
		}
	}
	if cfg.HasLabelFilter() {
		cacheOpts.ByObject = map[client.Object]cache.ByObject{
			&corev1.Secret{}: {Label: cfg.LabelSelector},
		}
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: cfg.MetricsBindAddress},
		HealthProbeBindAddress:  cfg.HealthBindAddress,
		LeaderElection:          cfg.LeaderElection,
		LeaderElectionID:        cfg.LeaderElectionID,
		LeaderElectionNamespace: leaderElectionNamespace(),
		Cache:                   cacheOpts,
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	rec := metrics.New(ctrlmetrics.Registry)
	tracker := metrics.NewTracker(rec)

	r := &controller.SecretReconciler{
		Client:          mgr.GetClient(),
		Tracker:         tracker,
		Metrics:         rec,
		SkipCertManager: cfg.SkipCertManager,
	}
	if err := r.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup reconciler: %w", err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add healthz: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("add readyz: %w", err)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("manager exited with error: %w", err)
	}
	return nil
}

// leaderElectionNamespace lets the operator override the Lease's
// namespace via the downward API. An empty return value tells
// controller-runtime to autodetect (it reads the namespace file
// projected into every Pod).
func leaderElectionNamespace() string {
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}
	return ""
}

func zapLevel(level string) zapcore.LevelEnabler {
	switch level {
	case "debug":
		return zapcore.DebugLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}
