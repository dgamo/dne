// Package metrics owns the Prometheus collectors exposed by dne.
//
// All collectors are registered against a configurable Registerer so
// that tests can use an isolated registry — production code wires this
// into controller-runtime's metrics registry, which already serves
// /metrics on the manager's metrics bind address.
package metrics

import "github.com/prometheus/client_golang/prometheus"

// Recorder bundles the metric collectors. A single Recorder is shared
// by the reconciler and the tracker so they emit consistent series.
type Recorder struct {
	NotAfter      *prometheus.GaugeVec
	NotBefore     *prometheus.GaugeVec
	Info          *prometheus.GaugeVec
	ParseErrors   *prometheus.CounterVec
	Reconciles    *prometheus.CounterVec
	LockedSecrets *prometheus.CounterVec
}

// Reconcile result labels.
const (
	ReconcileSuccess  = "success"
	ReconcileError    = "error"
	ReconcileNotFound = "notfound"
	ReconcileSkipped  = "skipped"
)

// SeriesLabels are the slim labels shared by NotAfter / NotBefore.
var SeriesLabels = []string{"namespace", "secret", "key", "cert_index"}

// InfoLabels are the slim labels plus the identifying companion labels.
var InfoLabels = []string{
	"namespace", "secret", "key", "cert_index",
	"subject", "issuer", "serial", "dns_names",
}

// New builds a Recorder and registers all collectors with reg. The
// caller owns reg's lifetime: production passes controller-runtime's
// metrics.Registry, tests pass a fresh prometheus.NewRegistry().
func New(reg prometheus.Registerer) *Recorder {
	r := &Recorder{
		NotAfter: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "dne_certificate_not_after_seconds",
			Help: "Unix timestamp of the certificate NotAfter (expiry). Compute remaining lifetime with `value - time()`.",
		}, SeriesLabels),
		NotBefore: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "dne_certificate_not_before_seconds",
			Help: "Unix timestamp of the certificate NotBefore (start of validity).",
		}, SeriesLabels),
		Info: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "dne_certificate_info",
			Help: "Static identifying labels for a certificate. Value is always 1; join with dne_certificate_not_after_seconds on (namespace, secret, key, cert_index).",
		}, InfoLabels),
		ParseErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dne_secret_parse_errors_total",
			Help: "Count of Secret values that contained PEM CERTIFICATE blocks that failed to parse as X.509.",
		}, []string{"namespace", "secret", "key"}),
		Reconciles: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dne_reconcile_total",
			Help: "Total Secret reconciles, partitioned by outcome.",
		}, []string{"result"}),
		LockedSecrets: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dne_secret_locked_total",
			Help: "Secret values that contain a cert-shaped blob (typically PKCS#12 / PFX) that dne could not decode. The reason label distinguishes a missing password, a wrong password, and other decode errors.",
		}, []string{"namespace", "secret", "key", "reason"}),
	}
	reg.MustRegister(r.NotAfter, r.NotBefore, r.Info, r.ParseErrors, r.Reconciles, r.LockedSecrets)
	return r
}
