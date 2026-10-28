// Command senselb-controller is the entrypoint for the senselb load-balancer
// controller.
//
// It loads the controller configuration and the provider credentials once at
// startup, builds the OPNsense provider, and starts the controller-runtime
// manager with leader election, the Service reconciler, the debounced apply
// queue, health probes and the metrics server.
//
// This is the only place that imports a concrete provider package: the rest of
// the controller depends on the provider.Provider interface.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/yasn77/senselb/pkg/config"
	"github.com/yasn77/senselb/pkg/controller"
	"github.com/yasn77/senselb/pkg/provider/opnsense"
)

// version is stamped at build time via:
//
//	-ldflags "-X main.version=<version>"
//
// It defaults to "dev" for local builds.
var version = "dev"

// Startup defaults.
const (
	// defaultNamespace is where the controller expects its own ConfigMap,
	// Secret and lease.
	defaultNamespace = "senselb-system"
	// defaultConfigName is the ConfigMap carrying the controller
	// configuration.
	defaultConfigName = "senselb-config"
	// configKey is the ConfigMap data key holding the YAML document.
	configKey = "config.yaml"
	// caCertKey is the Secret data key holding the optional PEM CA bundle.
	caCertKey = "ca.crt"
	// leaderElectionID names the Lease. It is created in the controller
	// namespace, so it is scoped to that namespace.
	leaderElectionID = "senselb-controller"
)

func main() {
	if err := run(); err != nil {
		slog.Error("senselb-controller stopped", "error", err)
		os.Exit(1)
	}
}

// run parses the flags, wires every component and starts the manager.
func run() error {
	var (
		metricsAddr     string
		probeAddr       string
		leaderElect     bool
		configNamespace string
		configName      string
		applyDebounce   time.Duration
		logLevel        string
		showVersion     bool
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080",
		"Address the metrics endpoint binds to; 0 disables it.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081",
		"Address the health probe endpoint binds to; 0 disables it.")
	flag.BoolVar(&leaderElect, "leader-elect", true,
		"Hold a Lease so only one replica programs the provider.")
	flag.StringVar(&configNamespace, "config-namespace", defaultNamespace,
		"Namespace holding the controller ConfigMap, Secret and leader-election Lease.")
	flag.StringVar(&configName, "config-name", defaultConfigName,
		"Name of the ConfigMap holding the controller configuration.")
	flag.DurationVar(&applyDebounce, "apply-debounce", controller.DefaultDebounce,
		"Quiet window that collapses a burst of Service changes into one apply.")
	flag.StringVar(&logLevel, "log-level", "info", "Log level: debug, info, warn or error.")
	flag.BoolVar(&showVersion, "version", false, "Print the version and exit.")
	flag.Parse()

	if showVersion {
		fmt.Println("senselb-controller", version)
		return nil
	}

	logger, err := newLogger(logLevel)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)
	slog.Info("senselb-controller starting", "version", version)

	ctx := ctrl.SetupSignalHandler()
	restConfig := ctrl.GetConfigOrDie()

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return fmt.Errorf("register core Kubernetes types: %w", err)
	}
	if err := discoveryv1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("register discovery types: %w", err)
	}

	// The configuration and credentials are read through a direct client
	// before the manager starts: the manager's cache cannot serve an object
	// before its informer has synced, and startup needs the configuration to
	// construct the provider at all. The trade-off is that the ConfigMap is
	// read once per process; a change requires a rollout, which the
	// deployment performs.
	directClient, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("build Kubernetes client: %w", err)
	}

	cfg, err := loadConfig(ctx, directClient, configNamespace, configName)
	if err != nil {
		return err
	}

	providerClient, err := providerConfig(ctx, directClient, configNamespace, cfg)
	if err != nil {
		return err
	}
	// The queue derives its ingress fallback from this field, so it must carry
	// the effective URL, not only the configuration's own.
	cfg.Provider.URL = providerClient.URL

	lbProvider, err := opnsense.New(providerClient)
	if err != nil {
		return fmt.Errorf("build OPNsense provider: %w", err)
	}
	// ClientConfig renders its own credentials redacted, including any
	// user information in the URL.
	slog.Info("provider configured", "client", providerClient.String())

	manager, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 server.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          leaderElect,
		LeaderElectionID:        leaderElectionID,
		LeaderElectionNamespace: configNamespace,
	})
	if err != nil {
		return fmt.Errorf("build manager: %w", err)
	}

	store := &controller.Store{
		Client:    directClient,
		Namespace: configNamespace,
		Name:      cfg.StoreName,
	}
	recorder := manager.GetEventRecorderFor("senselb") //nolint:staticcheck // the reconciler takes the classic client-go recorder; see ServiceReconciler.SetupWithManager

	reconciler := &controller.ServiceReconciler{
		Client:   manager.GetClient(),
		Scheme:   scheme,
		Provider: lbProvider,
		Config:   cfg,
		Store:    store,
		Recorder: recorder,
	}
	reconciler.Queue = &controller.ApplyQueue{
		Provider:          lbProvider,
		Client:            manager.GetClient(),
		Store:             store,
		Recorder:          recorder,
		Config:            cfg,
		BuildContribution: reconciler.BuildForService,
		Debounce:          applyDebounce,
	}

	if err := reconciler.SetupWithManager(manager); err != nil {
		return fmt.Errorf("register Service reconciler: %w", err)
	}

	// The queue reports NeedLeaderElection, so the manager starts it only on
	// the elected replica, alongside the controllers.
	if err := manager.Add(reconciler.Queue); err != nil {
		return fmt.Errorf("register apply queue: %w", err)
	}

	if err := manager.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("register liveness check: %w", err)
	}
	if err := manager.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("register readiness check: %w", err)
	}

	slog.Info("starting manager",
		"metrics", metricsAddr,
		"probes", probeAddr,
		"leaderElection", leaderElect,
		"debounce", applyDebounce.String(),
	)
	if err := manager.Start(ctx); err != nil {
		return fmt.Errorf("run manager: %w", err)
	}

	slog.Info("senselb-controller stopped cleanly")
	return nil
}

// newLogger builds the JSON logger the process installs as the slog default.
func newLogger(level string) (*slog.Logger, error) {
	var parsed slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		parsed = slog.LevelDebug
	case "", "info":
		parsed = slog.LevelInfo
	case "warn", "warning":
		parsed = slog.LevelWarn
	case "error":
		parsed = slog.LevelError
	default:
		return nil, fmt.Errorf("log level %q is not one of debug, info, warn, error", level)
	}

	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parsed})), nil
}

// loadConfig reads and validates the controller ConfigMap.
func loadConfig(ctx context.Context, c client.Client, namespace, name string) (*config.Config, error) {
	var configMap corev1.ConfigMap
	key := types.NamespacedName{Namespace: namespace, Name: name}
	if err := c.Get(ctx, key, &configMap); err != nil {
		return nil, fmt.Errorf("read ConfigMap %s: %w", key, err)
	}

	document, ok := configMap.Data[configKey]
	if !ok {
		return nil, fmt.Errorf("ConfigMap %s has no %q key", key, configKey)
	}

	cfg, err := config.Load([]byte(document))
	if err != nil {
		return nil, fmt.Errorf("load configuration from ConfigMap %s: %w", key, err)
	}
	return cfg, nil
}

// providerConfig resolves the provider credentials and URL.
//
// The Secret supplies the key and secret, and may override the URL: a non-empty
// "url" field wins over the configuration's own URL (ADR 0005). The optional CA
// bundle comes from a second Secret.
func providerConfig(ctx context.Context, c client.Client, namespace string, cfg *config.Config) (opnsense.ClientConfig, error) {
	providerCfg := opnsense.ClientConfig{
		URL:                cfg.Provider.URL,
		InsecureSkipVerify: cfg.Provider.InsecureSkipVerify,
	}

	if cfg.Provider.SecretName != "" {
		var secret corev1.Secret
		key := types.NamespacedName{Namespace: namespace, Name: cfg.Provider.SecretName}
		if err := c.Get(ctx, key, &secret); err != nil {
			return opnsense.ClientConfig{}, fmt.Errorf("read provider Secret %s: %w", key, err)
		}

		providerCfg.Key = string(secret.Data["key"])
		providerCfg.Secret = string(secret.Data["secret"])
		if url := strings.TrimSpace(string(secret.Data["url"])); url != "" {
			providerCfg.URL = url
		}
		if providerCfg.Key == "" || providerCfg.Secret == "" {
			return opnsense.ClientConfig{}, fmt.Errorf("provider Secret %s must set both \"key\" and \"secret\"", key)
		}
	}

	if providerCfg.URL == "" {
		return opnsense.ClientConfig{}, errors.New("provider URL is empty: set provider.url or the Secret's url field")
	}

	if cfg.Provider.CACertSecretName != "" {
		var secret corev1.Secret
		key := types.NamespacedName{Namespace: namespace, Name: cfg.Provider.CACertSecretName}
		if err := c.Get(ctx, key, &secret); err != nil {
			return opnsense.ClientConfig{}, fmt.Errorf("read CA Secret %s: %w", key, err)
		}
		ca := secret.Data[caCertKey]
		if len(ca) == 0 {
			return opnsense.ClientConfig{}, fmt.Errorf("CA Secret %s has no %q entry", key, caCertKey)
		}
		providerCfg.CA = ca
	}

	return providerCfg, nil
}
