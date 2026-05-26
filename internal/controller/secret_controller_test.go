package controller_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/dgamo/dne/internal/controller"
	dnemetrics "github.com/dgamo/dne/internal/metrics"
	"github.com/dgamo/dne/internal/testutil"
)

type envtestFixture struct {
	env       *envtest.Environment
	cfg       *runtime.Scheme
	client    client.Client
	reg       *prometheus.Registry
	cancel    context.CancelFunc
	stopErr   chan error
	namespace string
}

type fixtureOpts struct {
	LabelSelector   labels.Selector
	SkipCertManager bool
}

func setupEnvtest(t *testing.T, opts fixtureOpts) *envtestFixture {
	t.Helper()
	logf.SetLogger(zap.New(zap.WriteTo(os.Stderr), zap.UseDevMode(true)))

	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set; run `make envtest` first or `setup-envtest use` to install kube-apiserver/etcd binaries")
	}

	env := &envtest.Environment{
		ErrorIfCRDPathMissing: false,
	}
	restCfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("add scheme: %v", err)
	}

	cacheOpts := cache.Options{}
	if opts.LabelSelector != nil && !opts.LabelSelector.Empty() {
		cacheOpts.ByObject = map[client.Object]cache.ByObject{
			&corev1.Secret{}: {Label: opts.LabelSelector},
		}
	}

	skipValidation := true
	mgr, err := manager.New(restCfg, manager.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		LeaderElection:         false,
		Cache:                  cacheOpts,
		Controller: ctrlconfig.Controller{
			SkipNameValidation: &skipValidation,
		},
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	reg := prometheus.NewRegistry()
	rec := dnemetrics.New(reg)
	tracker := dnemetrics.NewTracker(rec)

	r := &controller.SecretReconciler{
		Client:          mgr.GetClient(),
		Tracker:         tracker,
		Metrics:         rec,
		SkipCertManager: opts.SkipCertManager,
	}
	if err := r.SetupWithManager(mgr); err != nil {
		t.Fatalf("setup reconciler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	stopErr := make(chan error, 1)
	go func() { stopErr <- mgr.Start(ctx) }()

	// Wait for the cache to sync so the test doesn't race with the
	// informer's initial list.
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		cancel()
		t.Fatal("cache sync failed")
	}

	ns := "dne-test"
	if err := mgr.GetClient().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		cancel()
		t.Fatalf("create namespace: %v", err)
	}

	t.Cleanup(func() {
		cancel()
		<-stopErr
		_ = env.Stop()
	})

	return &envtestFixture{
		env:       env,
		cfg:       scheme,
		client:    mgr.GetClient(),
		reg:       reg,
		cancel:    cancel,
		stopErr:   stopErr,
		namespace: ns,
	}
}

func (f *envtestFixture) gather(t *testing.T) []*dto.MetricFamily {
	t.Helper()
	mf, err := f.reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	return mf
}

const eventuallyTimeout = 5 * time.Second

func eventually(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(eventuallyTimeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("condition did not become true within %s", eventuallyTimeout)
}

func metricExists(mf []*dto.MetricFamily, name, ns, secret string) bool {
	for _, f := range mf {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			gotNS, gotSec := "", ""
			for _, l := range m.GetLabel() {
				if l.GetName() == "namespace" {
					gotNS = l.GetValue()
				}
				if l.GetName() == "secret" {
					gotSec = l.GetValue()
				}
			}
			if gotNS == ns && gotSec == secret {
				return true
			}
		}
	}
	return false
}

func metricCount(mf []*dto.MetricFamily, name, ns, secret string) int {
	count := 0
	for _, f := range mf {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			gotNS, gotSec := "", ""
			for _, l := range m.GetLabel() {
				if l.GetName() == "namespace" {
					gotNS = l.GetValue()
				}
				if l.GetName() == "secret" {
					gotSec = l.GetValue()
				}
			}
			if gotNS == ns && gotSec == secret {
				count++
			}
		}
	}
	return count
}

func TestMain(m *testing.M) {
	// Hint to anyone running the suite without envtest binaries: the
	// individual tests will Skip rather than fail.
	if path := os.Getenv("KUBEBUILDER_ASSETS"); path != "" {
		_, _ = os.Stat(filepath.Clean(path))
	}
	os.Exit(m.Run())
}

func TestReconcile_CreateUpdateDelete(t *testing.T) {
	f := setupEnvtest(t, fixtureOpts{})
	ctx := context.Background()

	leaf := testutil.NewCert(t, testutil.CertOptions{DNSNames: []string{"e2e.test"}})

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: f.namespace, Name: "demo"},
		Data: map[string][]byte{
			"tls.crt": leaf.PEM,
			"tls.key": testutil.PrivateKeyPEM(t, leaf.Key),
		},
	}
	if err := f.client.Create(ctx, sec); err != nil {
		t.Fatalf("create secret: %v", err)
	}

	eventually(t, func() bool {
		return metricExists(f.gather(t), "dne_certificate_not_after_seconds", f.namespace, "demo")
	})

	// Update the cert with a new subject and confirm the old series is
	// gone (rotation correctness).
	rotated := testutil.NewCert(t, testutil.CertOptions{CommonName: "rotated.test", DNSNames: []string{"rotated.test"}})
	current := &corev1.Secret{}
	if err := f.client.Get(ctx, types.NamespacedName{Namespace: f.namespace, Name: "demo"}, current); err != nil {
		t.Fatalf("get for update: %v", err)
	}
	current.Data["tls.crt"] = rotated.PEM
	if err := f.client.Update(ctx, current); err != nil {
		t.Fatalf("update secret: %v", err)
	}

	eventually(t, func() bool {
		mf := f.gather(t)
		for _, fam := range mf {
			if fam.GetName() != "dne_certificate_info" {
				continue
			}
			for _, m := range fam.GetMetric() {
				subj := ""
				for _, l := range m.GetLabel() {
					if l.GetName() == "subject" {
						subj = l.GetValue()
					}
				}
				if strings.Contains(subj, "rotated.test") {
					return true
				}
			}
		}
		return false
	})

	if got := metricCount(f.gather(t), "dne_certificate_info", f.namespace, "demo"); got != 1 {
		t.Errorf("expected exactly 1 info series after rotation, got %d", got)
	}

	if err := f.client.Delete(ctx, current); err != nil {
		t.Fatalf("delete secret: %v", err)
	}
	eventually(t, func() bool {
		return !metricExists(f.gather(t), "dne_certificate_not_after_seconds", f.namespace, "demo")
	})
}

func TestReconcile_Bundle(t *testing.T) {
	f := setupEnvtest(t, fixtureOpts{})
	ctx := context.Background()

	leaf := testutil.NewCert(t, testutil.CertOptions{CommonName: "leaf.test"})
	intermediate := testutil.NewCert(t, testutil.CertOptions{CommonName: "intermediate.test", IsCA: true})
	bundle := testutil.Bundle(leaf, intermediate)

	if err := f.client.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: f.namespace, Name: "bundle-secret"},
		Data:       map[string][]byte{"chain.pem": bundle},
	}); err != nil {
		t.Fatalf("create secret: %v", err)
	}

	eventually(t, func() bool {
		return metricCount(f.gather(t), "dne_certificate_info", f.namespace, "bundle-secret") == 2
	})
}

func TestReconcile_GarbageDataIncrementsParseErrors(t *testing.T) {
	f := setupEnvtest(t, fixtureOpts{})
	ctx := context.Background()

	if err := f.client.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: f.namespace, Name: "bad"},
		Data:       map[string][]byte{"crt": testutil.CorruptedPEM()},
	}); err != nil {
		t.Fatalf("create secret: %v", err)
	}

	eventually(t, func() bool {
		return metricExists(f.gather(t), "dne_secret_parse_errors_total", f.namespace, "bad")
	})
	if metricExists(f.gather(t), "dne_certificate_not_after_seconds", f.namespace, "bad") {
		t.Errorf("garbage secret should not produce cert series")
	}
}

func TestReconcile_LabelSelector(t *testing.T) {
	sel, err := labels.Parse("dne.k8s.io/watch=true")
	if err != nil {
		t.Fatalf("parse selector: %v", err)
	}
	f := setupEnvtest(t, fixtureOpts{LabelSelector: sel})
	ctx := context.Background()

	leaf := testutil.NewCert(t, testutil.CertOptions{DNSNames: []string{"lsel.test"}})

	// Without the label, the secret never reaches the cache.
	noLabel := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: f.namespace, Name: "unlabeled"},
		Data:       map[string][]byte{"tls.crt": leaf.PEM},
	}
	if err := f.client.Create(ctx, noLabel); err != nil {
		t.Fatalf("create: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	if metricExists(f.gather(t), "dne_certificate_not_after_seconds", f.namespace, "unlabeled") {
		t.Fatal("unlabeled secret should not produce metrics under the label selector")
	}

	// Labeling the secret should make it appear.
	labeled := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: f.namespace, Name: "labeled",
			Labels: map[string]string{"dne.k8s.io/watch": "true"},
		},
		Data: map[string][]byte{"tls.crt": leaf.PEM},
	}
	if err := f.client.Create(ctx, labeled); err != nil {
		t.Fatalf("create labeled: %v", err)
	}
	eventually(t, func() bool {
		return metricExists(f.gather(t), "dne_certificate_not_after_seconds", f.namespace, "labeled")
	})

	// Removing the label triggers a synthetic delete; metrics must be cleared.
	current := &corev1.Secret{}
	if err := f.client.Get(ctx, types.NamespacedName{Namespace: f.namespace, Name: "labeled"}, current); err != nil {
		t.Fatalf("get: %v", err)
	}
	current.Labels = map[string]string{}
	if err := f.client.Update(ctx, current); err != nil {
		t.Fatalf("update: %v", err)
	}
	eventually(t, func() bool {
		return !metricExists(f.gather(t), "dne_certificate_not_after_seconds", f.namespace, "labeled")
	})
}

// ---- PKCS#12 reconcile flow ----------------------------------------------

func TestReconcile_PKCS12_NoAnnotation_Locked(t *testing.T) {
	f := setupEnvtest(t, fixtureOpts{})
	ctx := context.Background()

	pfx := testutil.NewPKCS12(t, testutil.CertOptions{CommonName: "pfx-locked.test"}, "hunter2")

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: f.namespace, Name: "pfx-no-anno"},
		Data:       map[string][]byte{"cert.p12": pfx},
	}
	if err := f.client.Create(ctx, sec); err != nil {
		t.Fatalf("create secret: %v", err)
	}

	eventually(t, func() bool {
		return metricExists(f.gather(t), "dne_secret_locked_total", f.namespace, "pfx-no-anno")
	})
	if metricExists(f.gather(t), "dne_certificate_not_after_seconds", f.namespace, "pfx-no-anno") {
		t.Errorf("locked PFX without password should not produce cert series")
	}
}

func TestReconcile_PKCS12_AnnotationFlow(t *testing.T) {
	f := setupEnvtest(t, fixtureOpts{})
	ctx := context.Background()

	pfx := testutil.NewPKCS12(t, testutil.CertOptions{CommonName: "pfx-flow.test", DNSNames: []string{"pfx-flow.test"}}, "hunter2")

	// Create without annotation → locked.
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: f.namespace, Name: "pfx-flow"},
		Data: map[string][]byte{
			"cert.p12":      pfx,
			"cert-password": []byte("hunter2"),
		},
	}
	if err := f.client.Create(ctx, sec); err != nil {
		t.Fatalf("create: %v", err)
	}
	eventually(t, func() bool {
		return metricExists(f.gather(t), "dne_secret_locked_total", f.namespace, "pfx-flow")
	})

	// Add the annotation → cert appears.
	current := &corev1.Secret{}
	if err := f.client.Get(ctx, types.NamespacedName{Namespace: f.namespace, Name: "pfx-flow"}, current); err != nil {
		t.Fatalf("get: %v", err)
	}
	if current.Annotations == nil {
		current.Annotations = map[string]string{}
	}
	current.Annotations["dne.k8s.io/pkcs12-passwords"] = "cert.p12=cert-password"
	if err := f.client.Update(ctx, current); err != nil {
		t.Fatalf("update with annotation: %v", err)
	}
	eventually(t, func() bool {
		return metricExists(f.gather(t), "dne_certificate_not_after_seconds", f.namespace, "pfx-flow")
	})

	// Sanity: the info series carries the correct subject.
	mf := f.gather(t)
	series := []*dto.Metric{}
	for _, fam := range mf {
		if fam.GetName() != "dne_certificate_info" {
			continue
		}
		for _, m := range fam.GetMetric() {
			ns, sec := "", ""
			for _, l := range m.GetLabel() {
				if l.GetName() == "namespace" {
					ns = l.GetValue()
				}
				if l.GetName() == "secret" {
					sec = l.GetValue()
				}
			}
			if ns == f.namespace && sec == "pfx-flow" {
				series = append(series, m)
			}
		}
	}
	if len(series) != 1 {
		t.Fatalf("expected 1 info series, got %d", len(series))
	}
	subj := ""
	for _, l := range series[0].GetLabel() {
		if l.GetName() == "subject" {
			subj = l.GetValue()
		}
	}
	if subj != "CN=pfx-flow.test" {
		t.Errorf("subject = %q, want CN=pfx-flow.test", subj)
	}

	// Remove the annotation → cert series disappears.
	if err := f.client.Get(ctx, types.NamespacedName{Namespace: f.namespace, Name: "pfx-flow"}, current); err != nil {
		t.Fatalf("get after add: %v", err)
	}
	delete(current.Annotations, "dne.k8s.io/pkcs12-passwords")
	if err := f.client.Update(ctx, current); err != nil {
		t.Fatalf("update remove anno: %v", err)
	}
	eventually(t, func() bool {
		return !metricExists(f.gather(t), "dne_certificate_not_after_seconds", f.namespace, "pfx-flow")
	})
}

func TestReconcile_MixedFormatsSecret(t *testing.T) {
	f := setupEnvtest(t, fixtureOpts{})
	ctx := context.Background()

	pemLeaf := testutil.NewCert(t, testutil.CertOptions{CommonName: "pem-side.test"})
	pfxA := testutil.NewPKCS12(t, testutil.CertOptions{CommonName: "pfx-a.test"}, "pwA")
	pfxB := testutil.NewPKCS12(t, testutil.CertOptions{CommonName: "pfx-b.test"}, "pwB")

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: f.namespace, Name: "mixed",
			Annotations: map[string]string{
				"dne.k8s.io/pkcs12-passwords": "a.p12=pwA-key,b.p12=pwB-key",
			},
		},
		Data: map[string][]byte{
			"tls.crt": pemLeaf.PEM,
			"a.p12":   pfxA,
			"b.p12":   pfxB,
			"pwA-key": []byte("pwA"),
			"pwB-key": []byte("pwB"),
		},
	}
	if err := f.client.Create(ctx, sec); err != nil {
		t.Fatalf("create: %v", err)
	}
	eventually(t, func() bool {
		return metricCount(f.gather(t), "dne_certificate_info", f.namespace, "mixed") == 3
	})
}

// ---- cert-manager skip flow ---------------------------------------------

func TestReconcile_SkipCertManager_Off(t *testing.T) {
	f := setupEnvtest(t, fixtureOpts{}) // skip off
	ctx := context.Background()

	leaf := testutil.NewCert(t, testutil.CertOptions{DNSNames: []string{"cm.test"}})
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: f.namespace, Name: "cm-secret",
			Annotations: map[string]string{
				"cert-manager.io/certificate-name": "demo",
			},
		},
		Data: map[string][]byte{"tls.crt": leaf.PEM},
	}
	if err := f.client.Create(ctx, sec); err != nil {
		t.Fatalf("create: %v", err)
	}
	eventually(t, func() bool {
		return metricExists(f.gather(t), "dne_certificate_not_after_seconds", f.namespace, "cm-secret")
	})
}

func TestReconcile_SkipCertManager_On(t *testing.T) {
	f := setupEnvtest(t, fixtureOpts{SkipCertManager: true})
	ctx := context.Background()

	leaf := testutil.NewCert(t, testutil.CertOptions{DNSNames: []string{"cm.test"}})
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: f.namespace, Name: "cm-secret",
			Annotations: map[string]string{
				"cert-manager.io/certificate-name": "demo",
			},
		},
		Data: map[string][]byte{"tls.crt": leaf.PEM},
	}
	if err := f.client.Create(ctx, sec); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Give the reconciler a chance to run, then assert no certs and a skipped tick.
	eventually(t, func() bool {
		return reconcileResultCount(f.gather(t), "skipped") >= 1
	})
	if metricExists(f.gather(t), "dne_certificate_not_after_seconds", f.namespace, "cm-secret") {
		t.Errorf("cert-manager-owned secret should not produce cert metrics when --skip-cert-manager is on")
	}
}

func TestReconcile_SkipCertManager_CleanupOnAnnotate(t *testing.T) {
	f := setupEnvtest(t, fixtureOpts{SkipCertManager: true})
	ctx := context.Background()

	leaf := testutil.NewCert(t, testutil.CertOptions{DNSNames: []string{"cm.test"}})
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: f.namespace, Name: "later-cm"},
		Data:       map[string][]byte{"tls.crt": leaf.PEM},
	}
	if err := f.client.Create(ctx, sec); err != nil {
		t.Fatalf("create: %v", err)
	}
	eventually(t, func() bool {
		return metricExists(f.gather(t), "dne_certificate_not_after_seconds", f.namespace, "later-cm")
	})

	// Operator later marks it as cert-manager-managed (e.g. they migrated
	// the cert under cert-manager's control). Next reconcile should clear
	// the previously-emitted series via DropSecret.
	current := &corev1.Secret{}
	if err := f.client.Get(ctx, types.NamespacedName{Namespace: f.namespace, Name: "later-cm"}, current); err != nil {
		t.Fatalf("get: %v", err)
	}
	if current.Annotations == nil {
		current.Annotations = map[string]string{}
	}
	current.Annotations["cert-manager.io/certificate-name"] = "demo"
	if err := f.client.Update(ctx, current); err != nil {
		t.Fatalf("update with annotation: %v", err)
	}
	eventually(t, func() bool {
		return !metricExists(f.gather(t), "dne_certificate_not_after_seconds", f.namespace, "later-cm")
	})
}

// reconcileResultCount sums the value of dne_reconcile_total for the
// given result label.
func reconcileResultCount(mf []*dto.MetricFamily, result string) int {
	for _, f := range mf {
		if f.GetName() != "dne_reconcile_total" {
			continue
		}
		total := 0
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "result" && l.GetValue() == result {
					total += int(m.GetCounter().GetValue())
				}
			}
		}
		return total
	}
	return 0
}
