// Package testutil holds helpers used only by tests. Keep it free of
// production-code imports so tests can wire it in without dragging
// extra weight into the controller binary.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"
)

// CertOptions tunes a generated self-signed certificate. Zero values pick
// safe defaults: a fresh ECDSA P-256 key, 24h validity, CN derived from
// the first DNS SAN.
type CertOptions struct {
	CommonName string
	DNSNames   []string
	NotBefore  time.Time
	NotAfter   time.Time
	Serial     *big.Int
	IsCA       bool
	Parent     *x509.Certificate
	ParentKey  *ecdsa.PrivateKey
}

// GeneratedCert is everything callers need: the parsed cert (for
// reading SAN/Subject/etc), its private key (for chaining), and the
// PEM blob suitable for putting straight into a Secret's data map.
type GeneratedCert struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	PEM  []byte
}

// NewCert generates a single self-signed certificate (or a child of
// opts.Parent if set). It fails the test on any error — callers don't
// need to handle returned errors.
func NewCert(t testing.TB, opts CertOptions) GeneratedCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	cn := opts.CommonName
	if cn == "" && len(opts.DNSNames) > 0 {
		cn = opts.DNSNames[0]
	}
	if cn == "" {
		cn = "dne-test"
	}

	notBefore := opts.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-time.Hour).UTC()
	}
	notAfter := opts.NotAfter
	if notAfter.IsZero() {
		notAfter = notBefore.Add(24 * time.Hour)
	}
	serial := opts.Serial
	if serial == nil {
		s, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			t.Fatalf("generate serial: %v", err)
		}
		serial = s
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              opts.DNSNames,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  opts.IsCA,
		BasicConstraintsValid: true,
	}

	parent := tmpl
	parentKey := key
	if opts.Parent != nil {
		parent = opts.Parent
		parentKey = opts.ParentKey
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("re-parse certificate: %v", err)
	}
	pemBlob := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return GeneratedCert{Cert: cert, Key: key, PEM: pemBlob}
}

// Bundle concatenates the PEM bytes of every input, producing a chain
// (leaf first, then intermediates). Use it to seed Secrets that hold
// multi-cert bundles under a single key.
func Bundle(certs ...GeneratedCert) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, c.PEM...)
	}
	return out
}

// CorruptedPEM returns a CERTIFICATE-framed blob whose DER body is
// garbage, useful for asserting that parse errors are surfaced without
// bringing down the whole reconcile.
func CorruptedPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-actually-der-bytes")})
}

// PrivateKeyPEM marshals key as a PKCS#8 PEM block. Useful for building
// Secrets that mix a key and a certificate under separate keys.
func PrivateKeyPEM(t testing.TB, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// MustParseTime parses an RFC3339 timestamp or fails the test.
func MustParseTime(t testing.TB, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse time %q: %v", s, err)
	}
	return tm
}

// FormatNotAfter returns NotAfter as a Unix-seconds string, matching
// what would land in a Prometheus gauge.
func FormatNotAfter(c *x509.Certificate) string {
	return fmt.Sprintf("%d", c.NotAfter.Unix())
}
