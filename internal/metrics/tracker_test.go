package metrics_test

import (
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/dgamo/dne/internal/cert"
	"github.com/dgamo/dne/internal/metrics"
	"github.com/dgamo/dne/internal/testutil"
)

func newTracker(t *testing.T) (*prometheus.Registry, *metrics.Tracker) {
	t.Helper()
	reg := prometheus.NewRegistry()
	rec := metrics.New(reg)
	return reg, metrics.NewTracker(rec)
}

func gather(t *testing.T, reg *prometheus.Registry) []*dto.MetricFamily {
	t.Helper()
	mf, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	return mf
}

func countSeries(mf []*dto.MetricFamily, name string) int {
	for _, f := range mf {
		if f.GetName() == name {
			return len(f.GetMetric())
		}
	}
	return 0
}

func seriesForSecret(mf []*dto.MetricFamily, name, namespace, secret string) []*dto.Metric {
	var out []*dto.Metric
	for _, f := range mf {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			ns, sec := "", ""
			for _, l := range m.GetLabel() {
				if l.GetName() == "namespace" {
					ns = l.GetValue()
				}
				if l.GetName() == "secret" {
					sec = l.GetValue()
				}
			}
			if ns == namespace && sec == secret {
				out = append(out, m)
			}
		}
	}
	return out
}

func labelValue(m *dto.Metric, name string) string {
	for _, l := range m.GetLabel() {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}

func TestTracker_EmitSingleCert(t *testing.T) {
	reg, tr := newTracker(t)

	leaf := testutil.NewCert(t, testutil.CertOptions{DNSNames: []string{"emit.test"}})
	parsed, _ := cert.ParseAll(map[string][]byte{"tls.crt": leaf.PEM})

	key := client.ObjectKey{Namespace: "default", Name: "emit"}
	tr.Sync(key, parsed)

	mf := gather(t, reg)
	if got := countSeries(mf, "dne_certificate_not_after_seconds"); got != 1 {
		t.Errorf("expected 1 NotAfter series, got %d", got)
	}
	if got := countSeries(mf, "dne_certificate_info"); got != 1 {
		t.Errorf("expected 1 Info series, got %d", got)
	}
	if tr.Tracked() != 1 {
		t.Errorf("Tracked() = %d, want 1", tr.Tracked())
	}
}

func TestTracker_Idempotent(t *testing.T) {
	reg, tr := newTracker(t)

	leaf := testutil.NewCert(t, testutil.CertOptions{DNSNames: []string{"idem.test"}})
	parsed, _ := cert.ParseAll(map[string][]byte{"tls.crt": leaf.PEM})
	key := client.ObjectKey{Namespace: "default", Name: "idem"}

	tr.Sync(key, parsed)
	tr.Sync(key, parsed)
	tr.Sync(key, parsed)

	mf := gather(t, reg)
	if got := countSeries(mf, "dne_certificate_not_after_seconds"); got != 1 {
		t.Errorf("expected 1 series after repeated syncs, got %d", got)
	}
}

func TestTracker_Rotation(t *testing.T) {
	reg, tr := newTracker(t)
	key := client.ObjectKey{Namespace: "default", Name: "rotate"}

	old := testutil.NewCert(t, testutil.CertOptions{CommonName: "old.test", DNSNames: []string{"old.test"}})
	parsedOld, _ := cert.ParseAll(map[string][]byte{"tls.crt": old.PEM})
	tr.Sync(key, parsedOld)

	newCert := testutil.NewCert(t, testutil.CertOptions{CommonName: "new.test", DNSNames: []string{"new.test"}})
	parsedNew, _ := cert.ParseAll(map[string][]byte{"tls.crt": newCert.PEM})
	tr.Sync(key, parsedNew)

	mf := gather(t, reg)
	series := seriesForSecret(mf, "dne_certificate_info", "default", "rotate")
	if len(series) != 1 {
		t.Fatalf("expected 1 Info series after rotation, got %d", len(series))
	}
	if subject := labelValue(series[0], "subject"); !strings.Contains(subject, "new.test") {
		t.Errorf("expected new subject, got %q", subject)
	}
}

func TestTracker_PartialRotation(t *testing.T) {
	reg, tr := newTracker(t)
	key := client.ObjectKey{Namespace: "default", Name: "bundle"}

	leaf := testutil.NewCert(t, testutil.CertOptions{CommonName: "leaf.test"})
	intermediate := testutil.NewCert(t, testutil.CertOptions{CommonName: "intermediate.test", IsCA: true})
	parsedFull, _ := cert.ParseAll(map[string][]byte{"bundle.pem": testutil.Bundle(leaf, intermediate)})
	tr.Sync(key, parsedFull)

	// Now the Secret loses the intermediate.
	parsedLeafOnly, _ := cert.ParseAll(map[string][]byte{"bundle.pem": leaf.PEM})
	tr.Sync(key, parsedLeafOnly)

	mf := gather(t, reg)
	series := seriesForSecret(mf, "dne_certificate_not_after_seconds", "default", "bundle")
	if len(series) != 1 {
		t.Fatalf("expected 1 series after partial removal, got %d", len(series))
	}
	if idx := labelValue(series[0], "cert_index"); idx != "0" {
		t.Errorf("expected the remaining series to be cert_index=0, got %q", idx)
	}
}

func TestTracker_DropSecret(t *testing.T) {
	reg, tr := newTracker(t)
	key := client.ObjectKey{Namespace: "default", Name: "drop"}

	leaf := testutil.NewCert(t, testutil.CertOptions{DNSNames: []string{"drop.test"}})
	parsed, _ := cert.ParseAll(map[string][]byte{"tls.crt": leaf.PEM})
	tr.Sync(key, parsed)

	tr.DropSecret(key)

	mf := gather(t, reg)
	if got := countSeries(mf, "dne_certificate_not_after_seconds"); got != 0 {
		t.Errorf("expected 0 series after drop, got %d", got)
	}
	if got := countSeries(mf, "dne_certificate_info"); got != 0 {
		t.Errorf("expected 0 info series after drop, got %d", got)
	}
	if tr.Tracked() != 0 {
		t.Errorf("Tracked() = %d, want 0", tr.Tracked())
	}
}

func TestTracker_DropUntrackedIsSafe(t *testing.T) {
	_, tr := newTracker(t)
	tr.DropSecret(client.ObjectKey{Namespace: "default", Name: "never-existed"})
	if tr.Tracked() != 0 {
		t.Errorf("Tracked() = %d, want 0", tr.Tracked())
	}
}

func TestTracker_SyncEmptyDropsTracking(t *testing.T) {
	reg, tr := newTracker(t)
	key := client.ObjectKey{Namespace: "default", Name: "now-empty"}

	leaf := testutil.NewCert(t, testutil.CertOptions{DNSNames: []string{"e.test"}})
	parsed, _ := cert.ParseAll(map[string][]byte{"tls.crt": leaf.PEM})
	tr.Sync(key, parsed)

	// Secret rewritten with no certs (e.g. user blanked tls.crt).
	tr.Sync(key, nil)

	if tr.Tracked() != 0 {
		t.Errorf("Tracked() = %d, want 0 after empty sync", tr.Tracked())
	}
	mf := gather(t, reg)
	if got := countSeries(mf, "dne_certificate_not_after_seconds"); got != 0 {
		t.Errorf("expected 0 series after empty sync, got %d", got)
	}
}

func TestTracker_Concurrent(t *testing.T) {
	_, tr := newTracker(t)

	leaf := testutil.NewCert(t, testutil.CertOptions{DNSNames: []string{"conc.test"}})
	parsed, _ := cert.ParseAll(map[string][]byte{"tls.crt": leaf.PEM})

	const n = 100
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(2)
		key := client.ObjectKey{Namespace: "default", Name: "c-" + strconv.Itoa(i)}
		go func(k client.ObjectKey) { defer wg.Done(); tr.Sync(k, parsed) }(key)
		go func(k client.ObjectKey) { defer wg.Done(); tr.DropSecret(k) }(key)
	}
	wg.Wait()
	// We only assert no race / no panic; the final state is order-dependent.
}
