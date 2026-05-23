package cert_test

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/dgamo/dne/internal/cert"
	"github.com/dgamo/dne/internal/testutil"
)

// noOpts is shorthand for the common case where the caller doesn't
// supply any PKCS#12 passwords.
var noOpts = cert.ParseOptions{}

func TestParseAll_Empty(t *testing.T) {
	out, errs, locked := cert.ParseAll(nil, noOpts)
	if out != nil || errs != nil || locked != nil {
		t.Fatalf("expected nil/nil/nil, got %v/%v/%v", out, errs, locked)
	}
	out, errs, locked = cert.ParseAll(map[string][]byte{}, noOpts)
	if out != nil || errs != nil || locked != nil {
		t.Fatalf("expected nil/nil/nil for empty map, got %v/%v/%v", out, errs, locked)
	}
}

func TestParseAll_SingleLeaf(t *testing.T) {
	leaf := testutil.NewCert(t, testutil.CertOptions{DNSNames: []string{"example.test", "www.example.test"}})

	out, errs, locked := cert.ParseAll(map[string][]byte{
		"tls.crt": leaf.PEM,
		"tls.key": testutil.PrivateKeyPEM(t, leaf.Key),
	}, noOpts)
	if len(errs) != 0 {
		t.Fatalf("unexpected errs: %v", errs)
	}
	if len(locked) != 0 {
		t.Fatalf("unexpected locked: %v", locked)
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
	if _, present := out["tls.key"]; present {
		t.Errorf("tls.key should not produce certs, got %v", out["tls.key"])
	}
}

func TestParseAll_Bundle(t *testing.T) {
	leaf := testutil.NewCert(t, testutil.CertOptions{CommonName: "leaf.test", DNSNames: []string{"leaf.test"}})
	intermediate := testutil.NewCert(t, testutil.CertOptions{CommonName: "intermediate.test", IsCA: true})
	bundle := testutil.Bundle(leaf, intermediate)

	out, errs, _ := cert.ParseAll(map[string][]byte{"bundle.pem": bundle}, noOpts)
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

	out, errs, locked := cert.ParseAll(map[string][]byte{
		"binary":    garbage,
		"json":      []byte(`{"hello":"world"}`),
		"dockercfg": []byte(`{"auths":{"reg":{"auth":"AAAA"}}}`),
	}, noOpts)
	if out != nil {
		t.Errorf("expected nil out for non-PEM, got %v", out)
	}
	if len(errs) != 0 {
		t.Errorf("expected no errs for non-PEM, got %v", errs)
	}
	if len(locked) != 0 {
		t.Errorf("expected no locked blobs for non-PEM, got %v", locked)
	}
}

func TestParseAll_CorruptedPEM(t *testing.T) {
	leaf := testutil.NewCert(t, testutil.CertOptions{DNSNames: []string{"good.test"}})

	out, errs, _ := cert.ParseAll(map[string][]byte{
		"good.crt": leaf.PEM,
		"bad.crt":  testutil.CorruptedPEM(),
	}, noOpts)
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

	mixed := append(append([]byte(nil), leaf.PEM...), testutil.PrivateKeyPEM(t, leaf.Key)...)

	out, errs, _ := cert.ParseAll(map[string][]byte{"combo.pem": mixed}, noOpts)
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

	out, errs, _ := cert.ParseAll(map[string][]byte{"trunc.pem": truncated}, noOpts)
	if len(errs) != 0 || len(out) != 0 {
		t.Errorf("expected silent skip on truncated PEM, got out=%v errs=%v", out, errs)
	}
}

func TestParseAll_LargeSecretWithOneCert(t *testing.T) {
	leaf := testutil.NewCert(t, testutil.CertOptions{DNSNames: []string{"large.test"}})

	noise := bytes.Repeat([]byte("x"), 1<<20)
	noise = append(noise, '\n')
	value := make([]byte, 0, len(noise)+len(leaf.PEM))
	value = append(value, noise...)
	value = append(value, leaf.PEM...)

	out, errs, _ := cert.ParseAll(map[string][]byte{"big.pem": value}, noOpts)
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
	out, _, _ := cert.ParseAll(in, noOpts)
	if len(out) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(out))
	}
	if out["alpha.crt"][0].Subject != "CN=a.test" {
		t.Errorf("alpha subject = %q", out["alpha.crt"][0].Subject)
	}
	if out["zeta.crt"][0].Subject != "CN=b.test" {
		t.Errorf("zeta subject = %q", out["zeta.crt"][0].Subject)
	}
}

// ---- DER detection ------------------------------------------------------

func TestParseAll_RawDER(t *testing.T) {
	der := testutil.NewDER(t, testutil.CertOptions{CommonName: "der.test", DNSNames: []string{"der.test"}})

	out, errs, locked := cert.ParseAll(map[string][]byte{"cert.der": der}, noOpts)
	if len(errs) != 0 || len(locked) != 0 {
		t.Fatalf("expected clean parse, got errs=%v locked=%v", errs, locked)
	}
	got := out["cert.der"]
	if len(got) != 1 {
		t.Fatalf("expected 1 cert from DER, got %d", len(got))
	}
	if got[0].Subject != "CN=der.test" {
		t.Errorf("subject = %q", got[0].Subject)
	}
	if got[0].Index != 0 {
		t.Errorf("expected cert_index 0, got %d", got[0].Index)
	}
}

// ---- PKCS#12 detection --------------------------------------------------

func TestParseAll_UnencryptedPKCS12(t *testing.T) {
	pfx := testutil.NewPKCS12(t, testutil.CertOptions{CommonName: "pfx.test", DNSNames: []string{"pfx.test"}}, "")

	out, errs, locked := cert.ParseAll(map[string][]byte{"cert.p12": pfx}, noOpts)
	if len(errs) != 0 || len(locked) != 0 {
		t.Fatalf("expected clean parse, got errs=%v locked=%v", errs, locked)
	}
	if got := out["cert.p12"]; len(got) != 1 {
		t.Fatalf("expected 1 cert from unencrypted PFX, got %d", len(got))
	}
}

func TestParseAll_EncryptedPKCS12_CorrectPassword(t *testing.T) {
	pfx := testutil.NewPKCS12(t, testutil.CertOptions{CommonName: "enc.test"}, "hunter2")

	opts := cert.ParseOptions{PKCS12Passwords: map[string]string{"locked.p12": "hunter2"}}
	out, errs, locked := cert.ParseAll(map[string][]byte{"locked.p12": pfx}, opts)
	if len(errs) != 0 || len(locked) != 0 {
		t.Fatalf("expected clean parse, got errs=%v locked=%v", errs, locked)
	}
	if got := out["locked.p12"]; len(got) != 1 {
		t.Fatalf("expected 1 cert from encrypted PFX, got %d", len(got))
	}
}

func TestParseAll_EncryptedPKCS12_WrongPassword(t *testing.T) {
	pfx := testutil.NewPKCS12(t, testutil.CertOptions{CommonName: "enc.test"}, "real-password")

	opts := cert.ParseOptions{PKCS12Passwords: map[string]string{"locked.p12": "wrong"}}
	out, errs, locked := cert.ParseAll(map[string][]byte{"locked.p12": pfx}, opts)
	if out != nil {
		t.Errorf("expected no certs, got %v", out)
	}
	if len(errs) != 0 {
		t.Errorf("expected no parse errors, got %v", errs)
	}
	if len(locked) != 1 {
		t.Fatalf("expected 1 locked blob, got %d (%v)", len(locked), locked)
	}
	if locked[0].Key != "locked.p12" || locked[0].Reason != cert.LockedWrongPassword {
		t.Errorf("got %+v, want key=locked.p12 reason=%s", locked[0], cert.LockedWrongPassword)
	}
}

func TestParseAll_EncryptedPKCS12_NoPassword(t *testing.T) {
	pfx := testutil.NewPKCS12(t, testutil.CertOptions{CommonName: "enc.test"}, "secret")

	out, errs, locked := cert.ParseAll(map[string][]byte{"locked.p12": pfx}, noOpts)
	if out != nil {
		t.Errorf("expected no certs, got %v", out)
	}
	if len(errs) != 0 {
		t.Errorf("expected no parse errors, got %v", errs)
	}
	if len(locked) != 1 {
		t.Fatalf("expected 1 locked blob, got %d", len(locked))
	}
	if locked[0].Reason != cert.LockedNoPassword {
		t.Errorf("expected reason=%s, got %s", cert.LockedNoPassword, locked[0].Reason)
	}
}

func TestParseAll_PKCS12Chain(t *testing.T) {
	leaf := testutil.NewCert(t, testutil.CertOptions{CommonName: "leaf.test", DNSNames: []string{"leaf.test"}})
	ca := testutil.NewCert(t, testutil.CertOptions{CommonName: "ca.test", IsCA: true})
	pfx := testutil.NewPKCS12Chain(t, leaf, []testutil.GeneratedCert{ca}, "")

	out, errs, locked := cert.ParseAll(map[string][]byte{"chain.p12": pfx}, noOpts)
	if len(errs) != 0 || len(locked) != 0 {
		t.Fatalf("expected clean parse, got errs=%v locked=%v", errs, locked)
	}
	got := out["chain.p12"]
	if len(got) != 2 {
		t.Fatalf("expected 2 certs from chain PFX, got %d", len(got))
	}
	if got[0].Index != 0 || got[1].Index != 1 {
		t.Errorf("expected indexes 0,1; got %d,%d", got[0].Index, got[1].Index)
	}
	if got[0].Subject != "CN=leaf.test" {
		t.Errorf("expected leaf at index 0, got %q", got[0].Subject)
	}
	if got[1].Subject != "CN=ca.test" {
		t.Errorf("expected CA at index 1, got %q", got[1].Subject)
	}
}

func TestParseAll_MixedFormats(t *testing.T) {
	pemLeaf := testutil.NewCert(t, testutil.CertOptions{CommonName: "pem.test"})
	derCert := testutil.NewDER(t, testutil.CertOptions{CommonName: "der.test"})
	pfx := testutil.NewPKCS12(t, testutil.CertOptions{CommonName: "pfx.test"}, "p")

	opts := cert.ParseOptions{PKCS12Passwords: map[string]string{"a.p12": "p"}}
	out, errs, locked := cert.ParseAll(map[string][]byte{
		"tls.crt":  pemLeaf.PEM,
		"cert.der": derCert,
		"a.p12":    pfx,
	}, opts)
	if len(errs) != 0 || len(locked) != 0 {
		t.Fatalf("expected clean parse, got errs=%v locked=%v", errs, locked)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 keys parsed, got %d (%v)", len(out), out)
	}
	for _, key := range []string{"tls.crt", "cert.der", "a.p12"} {
		if got := out[key]; len(got) != 1 {
			t.Errorf("key %s: expected 1 cert, got %d", key, len(got))
		}
	}
}

func TestParseAll_FalsePositiveASN1Prefix(t *testing.T) {
	// A blob that starts with 0x30 0x82 (ASN.1 SEQUENCE long-form) but
	// is not a valid DER cert nor a PKCS#12 bundle. Pre-filter should
	// route it to PKCS#12 (since DER parse fails), and DecodeChain
	// should return a non-password error → LockedDecodeError. This
	// surfaces a true positive on the operator dashboard rather than
	// silently dropping bytes that look like they could be certs.
	value := []byte{0x30, 0x82, 0x00, 0x10, 0x00, 0x00}
	out, _, locked := cert.ParseAll(map[string][]byte{"weird": value}, noOpts)
	if out != nil {
		t.Errorf("expected no certs, got %v", out)
	}
	if len(locked) != 1 || locked[0].Reason != cert.LockedDecodeError {
		t.Errorf("expected single LockedDecodeError, got %v", locked)
	}
}
