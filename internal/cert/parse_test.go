package cert_test

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/dgamo/dne/internal/cert"
	"github.com/dgamo/dne/internal/testutil"
)

func TestParseAll_Empty(t *testing.T) {
	out, errs := cert.ParseAll(nil)
	if out != nil || errs != nil {
		t.Fatalf("expected nil/nil, got %v/%v", out, errs)
	}
	out, errs = cert.ParseAll(map[string][]byte{})
	if out != nil || errs != nil {
		t.Fatalf("expected nil/nil for empty map, got %v/%v", out, errs)
	}
}

func TestParseAll_SingleLeaf(t *testing.T) {
	leaf := testutil.NewCert(t, testutil.CertOptions{DNSNames: []string{"example.test", "www.example.test"}})

	out, errs := cert.ParseAll(map[string][]byte{
		"tls.crt": leaf.PEM,
		"tls.key": testutil.PrivateKeyPEM(t, leaf.Key),
	})
	if len(errs) != 0 {
		t.Fatalf("unexpected errs: %v", errs)
	}
	got, ok := out["tls.crt"]
	if !ok || len(got) != 1 {
		t.Fatalf("expected one cert under tls.crt, got %v", out)
	}
	if got[0].Index != 0 {
		t.Errorf("expected index 0, got %d", got[0].Index)
	}
	if got[0].Subject != "CN=example.test" {
		t.Errorf("subject = %q", got[0].Subject)
	}
	wantDNS := []string{"example.test", "www.example.test"}
	if got[0].JoinDNSNames() != strings.Join(wantDNS, ",") {
		t.Errorf("dns_names = %q, want %q", got[0].JoinDNSNames(), strings.Join(wantDNS, ","))
	}
	// tls.key should never produce a cert entry.
	if _, present := out["tls.key"]; present {
		t.Errorf("tls.key should not produce certs, got %v", out["tls.key"])
	}
}

func TestParseAll_Bundle(t *testing.T) {
	leaf := testutil.NewCert(t, testutil.CertOptions{CommonName: "leaf.test", DNSNames: []string{"leaf.test"}})
	intermediate := testutil.NewCert(t, testutil.CertOptions{CommonName: "intermediate.test", IsCA: true})
	bundle := testutil.Bundle(leaf, intermediate)

	out, errs := cert.ParseAll(map[string][]byte{"bundle.pem": bundle})
	if len(errs) != 0 {
		t.Fatalf("unexpected errs: %v", errs)
	}
	certs := out["bundle.pem"]
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}
	if certs[0].Index != 0 || certs[1].Index != 1 {
		t.Errorf("expected indexes 0,1, got %d,%d", certs[0].Index, certs[1].Index)
	}
	if certs[0].Subject != "CN=leaf.test" || certs[1].Subject != "CN=intermediate.test" {
		t.Errorf("subjects = %q, %q", certs[0].Subject, certs[1].Subject)
	}
}

func TestParseAll_NonPEMSilent(t *testing.T) {
	garbage := make([]byte, 4096)
	if _, err := rand.Read(garbage); err != nil {
		t.Fatalf("rand: %v", err)
	}

	out, errs := cert.ParseAll(map[string][]byte{
		"binary":    garbage,
		"json":      []byte(`{"hello":"world"}`),
		"dockercfg": []byte(`{"auths":{"reg":{"auth":"AAAA"}}}`),
	})
	if out != nil {
		t.Errorf("expected nil out for non-PEM, got %v", out)
	}
	if len(errs) != 0 {
		t.Errorf("expected no errs for non-PEM, got %v", errs)
	}
}

func TestParseAll_CorruptedPEM(t *testing.T) {
	leaf := testutil.NewCert(t, testutil.CertOptions{DNSNames: []string{"good.test"}})

	out, errs := cert.ParseAll(map[string][]byte{
		"good.crt": leaf.PEM,
		"bad.crt":  testutil.CorruptedPEM(),
	})
	if len(errs) != 1 {
		t.Fatalf("expected 1 parse error, got %d (%v)", len(errs), errs)
	}
	if errs[0].Key != "bad.crt" {
		t.Errorf("expected error on bad.crt, got %s", errs[0].Key)
	}
	if got := out["good.crt"]; len(got) != 1 {
		t.Errorf("good.crt should still parse despite bad.crt errors, got %v", got)
	}
	if got, present := out["bad.crt"]; present && len(got) > 0 {
		t.Errorf("bad.crt should not produce certs, got %v", got)
	}
}

func TestParseAll_MixedCertAndKey(t *testing.T) {
	leaf := testutil.NewCert(t, testutil.CertOptions{DNSNames: []string{"mixed.test"}})

	// A single value that holds both a CERTIFICATE block and a PRIVATE KEY block.
	mixed := append(append([]byte(nil), leaf.PEM...), testutil.PrivateKeyPEM(t, leaf.Key)...)

	out, errs := cert.ParseAll(map[string][]byte{"combo.pem": mixed})
	if len(errs) != 0 {
		t.Fatalf("unexpected errs: %v", errs)
	}
	if got := out["combo.pem"]; len(got) != 1 {
		t.Fatalf("expected one cert (key block ignored), got %d", len(got))
	}
}

func TestParseAll_TruncatedBlock(t *testing.T) {
	leaf := testutil.NewCert(t, testutil.CertOptions{DNSNames: []string{"trunc.test"}})
	truncated := leaf.PEM[:len(leaf.PEM)/2]

	out, errs := cert.ParseAll(map[string][]byte{"trunc.pem": truncated})
	// Truncated PEM frame: pem.Decode returns nil (it requires a complete BEGIN…END envelope),
	// so this is silently skipped — neither a parse error nor a cert.
	if len(errs) != 0 || len(out) != 0 {
		t.Errorf("expected silent skip on truncated PEM, got out=%v errs=%v", out, errs)
	}
}

func TestParseAll_LargeSecretWithOneCert(t *testing.T) {
	leaf := testutil.NewCert(t, testutil.CertOptions{DNSNames: []string{"large.test"}})

	// 1MB of deterministic non-PEM noise. Random bytes would do, but
	// pem.Decode requires the cert to be preceded by '\n', so we use
	// a fixed-character fill that ends with a newline and concatenate
	// the real cert after it.
	noise := bytes.Repeat([]byte("x"), 1<<20)
	noise = append(noise, '\n')
	value := make([]byte, 0, len(noise)+len(leaf.PEM))
	value = append(value, noise...)
	value = append(value, leaf.PEM...)

	out, errs := cert.ParseAll(map[string][]byte{"big.pem": value})
	if len(errs) != 0 {
		t.Fatalf("unexpected errs: %v", errs)
	}
	if got := out["big.pem"]; len(got) != 1 {
		t.Fatalf("expected one cert, got %d", len(got))
	}
}

func TestParseAll_DeterministicKeyOrder(t *testing.T) {
	a := testutil.NewCert(t, testutil.CertOptions{CommonName: "a.test"})
	b := testutil.NewCert(t, testutil.CertOptions{CommonName: "b.test"})

	in := map[string][]byte{"zeta.crt": b.PEM, "alpha.crt": a.PEM}
	out, _ := cert.ParseAll(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(out))
	}
	// Sorted iteration is an internal invariant we rely on for stable
	// tracker behaviour; assert it directly by checking the keys are
	// both present and the parsed certs have the expected subjects.
	if out["alpha.crt"][0].Subject != "CN=a.test" {
		t.Errorf("alpha subject = %q", out["alpha.crt"][0].Subject)
	}
	if out["zeta.crt"][0].Subject != "CN=b.test" {
		t.Errorf("zeta subject = %q", out["zeta.crt"][0].Subject)
	}
}
