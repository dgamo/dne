// Package testutil holds helpers used only by tests. Keep it free of
// production-code imports so tests can wire it in without dragging
// extra weight into the controller binary.
package testutil

import (
	"bytes"
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

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
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

// NewDER returns a fresh self-signed cert's raw DER bytes, with no PEM
// envelope. Used to test the raw-DER detection path.
func NewDER(t testing.TB, opts CertOptions) []byte {
	t.Helper()
	g := NewCert(t, opts)
	return g.Cert.Raw
}

// NewPKCS12 builds a PKCS#12 bundle containing one cert and its private
// key. Pass password="" to produce an unencrypted bundle.
func NewPKCS12(t testing.TB, opts CertOptions, password string) []byte {
	t.Helper()
	g := NewCert(t, opts)
	return encodePKCS12(t, g.Key, g.Cert, nil, password)
}

// NewPKCS12Chain builds a PKCS#12 bundle containing a leaf cert (with
// its private key) and zero or more CA certs in the chain. The private
// key belongs to the leaf only — the CAs are added as ca-bag entries.
func NewPKCS12Chain(t testing.TB, leaf GeneratedCert, cas []GeneratedCert, password string) []byte {
	t.Helper()
	caCerts := make([]*x509.Certificate, 0, len(cas))
	for _, c := range cas {
		caCerts = append(caCerts, c.Cert)
	}
	return encodePKCS12(t, leaf.Key, leaf.Cert, caCerts, password)
}

func encodePKCS12(t testing.TB, key *ecdsa.PrivateKey, cert *x509.Certificate, cas []*x509.Certificate, password string) []byte {
	t.Helper()
	encoder := pkcs12.Modern
	out, err := encoder.Encode(key, cert, cas, password)
	if err != nil {
		t.Fatalf("encode pkcs12: %v", err)
	}
	return out
}

// NewJKS builds a Java KeyStore containing one private-key entry (the
// leaf cert + key). password "" produces a keystore whose integrity
// MAC is computed with an empty password (still valid JKS, just not
// useful).
func NewJKS(t testing.TB, opts CertOptions, password string) []byte {
	t.Helper()
	g := NewCert(t, opts)
	return encodeJKS(t, []jksEntry{{alias: "demo", privateKey: g.Key, chain: []*x509.Certificate{g.Cert}}}, password)
}

// NewJKSChain builds a keystore where one private-key entry carries
// leaf + intermediates as its certificate chain.
func NewJKSChain(t testing.TB, leaf GeneratedCert, chain []GeneratedCert, password string) []byte {
	t.Helper()
	certs := make([]*x509.Certificate, 0, 1+len(chain))
	certs = append(certs, leaf.Cert)
	for _, c := range chain {
		certs = append(certs, c.Cert)
	}
	return encodeJKS(t, []jksEntry{{alias: "demo", privateKey: leaf.Key, chain: certs}}, password)
}

// NewJKSTruststore builds a keystore of trusted-cert entries, one per
// input. Alias names are deterministic (`ca-0`, `ca-1`, …) so tests can
// assert on cert_index ordering after the in-package sort.
func NewJKSTruststore(t testing.TB, certs []GeneratedCert, password string) []byte {
	t.Helper()
	entries := make([]jksEntry, len(certs))
	for i, c := range certs {
		entries[i] = jksEntry{alias: fmt.Sprintf("ca-%d", i), trusted: c.Cert}
	}
	return encodeJKS(t, entries, password)
}

type jksEntry struct {
	alias      string
	privateKey *ecdsa.PrivateKey   // nil → trusted-cert entry
	chain      []*x509.Certificate // leaf first
	trusted    *x509.Certificate
}

func encodeJKS(t testing.TB, entries []jksEntry, password string) []byte {
	t.Helper()
	ks := keystore.New()
	now := time.Now()
	for _, e := range entries {
		switch {
		case e.privateKey != nil:
			der, err := x509.MarshalPKCS8PrivateKey(e.privateKey)
			if err != nil {
				t.Fatalf("marshal key: %v", err)
			}
			ksChain := make([]keystore.Certificate, len(e.chain))
			for i, c := range e.chain {
				ksChain[i] = keystore.Certificate{Type: "X.509", Content: c.Raw}
			}
			if err := ks.SetPrivateKeyEntry(e.alias, keystore.PrivateKeyEntry{
				CreationTime:     now,
				PrivateKey:       der,
				CertificateChain: ksChain,
			}, []byte(password)); err != nil {
				t.Fatalf("set private key entry: %v", err)
			}
		case e.trusted != nil:
			if err := ks.SetTrustedCertificateEntry(e.alias, keystore.TrustedCertificateEntry{
				CreationTime: now,
				Certificate:  keystore.Certificate{Type: "X.509", Content: e.trusted.Raw},
			}); err != nil {
				t.Fatalf("set trusted cert entry: %v", err)
			}
		}
	}
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatalf("store keystore: %v", err)
	}
	return buf.Bytes()
}
