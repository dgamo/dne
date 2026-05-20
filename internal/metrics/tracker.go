package metrics

import (
	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/dgamo/dne/internal/cert"
)

// seriesKey uniquely identifies one emitted time series. The slim
// fields (Namespace…CertIndex) are the only labels carried by the
// NotAfter/NotBefore gauges; the rest live on the companion Info
// gauge but we track all of them together so cleanup is one operation.
type seriesKey struct {
	Namespace string
	Secret    string
	Key       string
	CertIndex string
	Subject   string
	Issuer    string
	Serial    string
	DNSNames  string
}

func (k seriesKey) slimLabels() prometheus.Labels {
	return prometheus.Labels{
		"namespace":  k.Namespace,
		"secret":     k.Secret,
		"key":        k.Key,
		"cert_index": k.CertIndex,
	}
}

func (k seriesKey) infoLabels() prometheus.Labels {
	l := k.slimLabels()
	l["subject"] = k.Subject
	l["issuer"] = k.Issuer
	l["serial"] = k.Serial
	l["dns_names"] = k.DNSNames
	return l
}

// Tracker keeps the per-Secret set of emitted series so that cert
// rotation and Secret deletion correctly remove the previous label
// values from the registry. Without this, rotated certs would
// accumulate stale series forever (high-cardinality labels like serial
// and dns_names make that especially bad).
type Tracker struct {
	rec *Recorder

	mu      sync.Mutex
	emitted map[client.ObjectKey]map[seriesKey]struct{}
}

// NewTracker wires a Tracker to the given Recorder. The recorder owns
// the collectors; the tracker just calls Set/Delete on them.
func NewTracker(rec *Recorder) *Tracker {
	return &Tracker{
		rec:     rec,
		emitted: make(map[client.ObjectKey]map[seriesKey]struct{}),
	}
}

// Sync reconciles the metric series for one Secret. It deletes any
// previously-emitted series that no longer appear in certs, sets fresh
// values for the rest, and updates the internal bookkeeping.
//
// Sync is safe to call concurrently for different Secrets; the
// reconciler itself is single-threaded per object.
func (t *Tracker) Sync(secret client.ObjectKey, certs map[string][]cert.ParsedCert) {
	desired := buildSeriesSet(secret, certs)

	t.mu.Lock()
	defer t.mu.Unlock()

	prev := t.emitted[secret]
	for k := range prev {
		if _, keep := desired[k]; !keep {
			t.deleteSeries(k)
		}
	}
	for k := range desired {
		t.setSeries(k, certs)
	}
	if len(desired) == 0 {
		delete(t.emitted, secret)
	} else {
		t.emitted[secret] = desired
	}
}

// DropSecret removes every series associated with secret. It is
// idempotent: calling it on a Secret we never tracked is a no-op.
func (t *Tracker) DropSecret(secret client.ObjectKey) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, ok := t.emitted[secret]; !ok {
		// Even if we never tracked the Secret, do a partial-match delete
		// as a defensive sweep — handles the case where the controller
		// restarted between an emit and the corresponding NotFound.
		t.partialDelete(secret)
		return
	}
	t.partialDelete(secret)
	delete(t.emitted, secret)
}

// Tracked returns the number of Secrets currently tracked. Used by
// tests; cheap enough to leave exported.
func (t *Tracker) Tracked() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.emitted)
}

func (t *Tracker) partialDelete(secret client.ObjectKey) {
	match := prometheus.Labels{"namespace": secret.Namespace, "secret": secret.Name}
	t.rec.NotAfter.DeletePartialMatch(match)
	t.rec.NotBefore.DeletePartialMatch(match)
	t.rec.Info.DeletePartialMatch(match)
}

func (t *Tracker) setSeries(k seriesKey, certs map[string][]cert.ParsedCert) {
	// Look up the parsed cert by (Key, CertIndex) to retrieve the
	// timestamps. We rebuild the lookup here rather than carry the
	// times on seriesKey because seriesKey is a comparable map key and
	// time.Time isn't a great fit.
	idx, err := strconv.Atoi(k.CertIndex)
	if err != nil {
		return
	}
	bucket := certs[k.Key]
	if idx < 0 || idx >= len(bucket) {
		return
	}
	c := bucket[idx]
	t.rec.NotAfter.With(k.slimLabels()).Set(float64(c.NotAfter.Unix()))
	t.rec.NotBefore.With(k.slimLabels()).Set(float64(c.NotBefore.Unix()))
	t.rec.Info.With(k.infoLabels()).Set(1)
}

func (t *Tracker) deleteSeries(k seriesKey) {
	t.rec.NotAfter.Delete(k.slimLabels())
	t.rec.NotBefore.Delete(k.slimLabels())
	t.rec.Info.Delete(k.infoLabels())
}

func buildSeriesSet(secret client.ObjectKey, certs map[string][]cert.ParsedCert) map[seriesKey]struct{} {
	out := make(map[seriesKey]struct{})
	for key, bucket := range certs {
		for _, c := range bucket {
			out[seriesKey{
				Namespace: secret.Namespace,
				Secret:    secret.Name,
				Key:       key,
				CertIndex: strconv.Itoa(c.Index),
				Subject:   c.Subject,
				Issuer:    c.Issuer,
				Serial:    c.Serial,
				DNSNames:  c.JoinDNSNames(),
			}] = struct{}{}
		}
	}
	return out
}
