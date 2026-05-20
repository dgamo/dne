// Package controller wires Secret reconciliation to the dne metrics
// pipeline. The Reconciler is intentionally minimal: it fetches the
// Secret, parses every value for X.509 certs, and asks the metrics
// tracker to synchronise the emitted series.
package controller

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/dgamo/dne/internal/cert"
	"github.com/dgamo/dne/internal/metrics"
)

// SecretReconciler reconciles a Secret object: it never mutates the
// Secret, only mirrors its certificate contents into Prometheus
// metrics via Tracker.
type SecretReconciler struct {
	Client  client.Client
	Tracker *metrics.Tracker
	Metrics *metrics.Recorder
}

// Reconcile implements reconcile.Reconciler.
func (r *SecretReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	logger := log.FromContext(ctx).WithValues("namespace", req.Namespace, "secret", req.Name)

	var sec corev1.Secret
	if err := r.Client.Get(ctx, req.NamespacedName, &sec); err != nil {
		if apierrors.IsNotFound(err) {
			r.Tracker.DropSecret(req.NamespacedName)
			r.Metrics.Reconciles.WithLabelValues(metrics.ReconcileNotFound).Inc()
			logger.V(1).Info("secret removed; cleared metrics")
			return reconcile.Result{}, nil
		}
		r.Metrics.Reconciles.WithLabelValues(metrics.ReconcileError).Inc()
		return reconcile.Result{}, err
	}

	parsed, errs := cert.ParseAll(sec.Data)
	for _, e := range errs {
		r.Metrics.ParseErrors.WithLabelValues(req.Namespace, req.Name, e.Key).Inc()
		logger.V(1).Info("certificate parse error", "key", e.Key, "err", e.Err)
	}
	r.Tracker.Sync(req.NamespacedName, parsed)
	r.Metrics.Reconciles.WithLabelValues(metrics.ReconcileSuccess).Inc()
	return reconcile.Result{}, nil
}

// SetupWithManager registers the Reconciler with the given manager.
func (r *SecretReconciler) SetupWithManager(mgr manager.Manager) error {
	return builder.ControllerManagedBy(mgr).
		Named("dne-secret").
		For(&corev1.Secret{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}
