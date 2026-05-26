// Package cert extracts X.509 certificates from arbitrary byte slices.
//
// ParseAll walks the data of every key in a Secret and tries four
// detection strategies per value, in order:
//
//  1. PEM CERTIFICATE blocks (the canonical format used by
//     kubernetes.io/tls Secrets, cert-manager, and most cloud-native
//     tooling).
//  2. Raw X.509 DER bytes (rare, but cheap to support).
//  3. PKCS#12 / PFX bundles, optionally encrypted with a password
//     supplied via ParseOptions.PKCS12Passwords (typical for Java,
//     .NET, and payment-integration workloads).
//  4. Java KeyStore (JKS / JCEKS) bundles, using the same password
//     map as PKCS#12 (the format-agnostic name "PKCS12Passwords" is
//     historical; the cascade dispatches on magic bytes).
//
// The cascade stops on the first format that produces certs for a
// given value. Values that match none are silently skipped so that
// non-cert data (credentials, JSON configs, certificate authority
// metadata, etc.) does not generate noise.
package cert

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const certificateBlockType = "CERTIFICATE"

// ParsedCert is the minimal projection of an x509.Certificate that the
// metrics layer needs. The full certificate is intentionally not
// retained — it pins large byte slices in memory across reconciles.
type ParsedCert struct {
	Key       string
	Index     int
	NotBefore time.Time
	NotAfter  time.Time
	Subject   string
	Issuer    string
	Serial    string
	DNSNames  []string
}

// ParseError describes one failed PEM CERTIFICATE block. The parser
// continues past errors so that a single bad block doesn't mask other
// valid certs in the same Secret.
type ParseError struct {
	Key string
	Err error
}

func (e ParseError) Error() string { return fmt.Sprintf("%s: %v", e.Key, e.Err) }
func (e ParseError) Unwrap() error { return e.Err }

// LockedReason categorises why a PKCS#12 / PFX-shaped value could not
// be opened. It becomes the value of the `reason` label on the
// dne_secret_locked_total counter.
type LockedReason string

const (
	// LockedNoPassword is the reason when the value looks like a PKCS#12
	// bundle but no password mapping is configured for this data key and
	// the empty-password attempt failed.
	LockedNoPassword LockedReason = "pkcs12_no_password" // #nosec G101 -- metric label, not a credential.
	// LockedWrongPassword is the reason when the supplied password
	// didn't decrypt the bundle.
	LockedWrongPassword LockedReason = "pkcs12_wrong_password" // #nosec G101 -- metric label, not a credential.
	// LockedDecodeError is the reason when the PKCS#12 library returns
	// a non-password error (corrupt bundle, unsupported algorithm).
	LockedDecodeError LockedReason = "pkcs12_decode_error"
)

// LockedBlob describes one Secret value that we identified as a
// cert-shaped opaque blob but could not open. The caller increments
// dne_secret_locked_total{...} with these.
type LockedBlob struct {
	Key    string
	Reason LockedReason
}

// ParseOptions tunes ParseAll. The cert package never touches a Secret
// directly — the caller resolves any password it wants tried (looking
// up the password data key, decoding bytes to string, trimming
// trailing whitespace) before invoking ParseAll.
type ParseOptions struct {
	// PKCS12Passwords maps a Secret data key to the plain-text password
	// used to decrypt its PKCS#12 contents. Keys not present here fall
	// back to the empty password.
	PKCS12Passwords map[string]string
}

// ParseAll walks every value in data and returns the certs found
// (grouped by originating data key), parse errors from PEM CERTIFICATE
// blocks that failed to parse, and "locked" entries for values that
// look like PKCS#12 but couldn't be opened.
//
// The map's iteration order is sorted by key so downstream metric
// emission is deterministic — important for stable tracker behaviour
// and test assertions.
func ParseAll(data map[string][]byte, opts ParseOptions) (
	map[string][]ParsedCert,
	[]ParseError,
	[]LockedBlob,
) {
	if len(data) == 0 {
		return nil, nil, nil
	}

	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make(map[string][]ParsedCert, len(keys))
	var (
		errs   []ParseError
		locked []LockedBlob
	)

	for _, key := range keys {
		certs, keyErrs, keyLocked := parseValue(key, data[key], opts)
		if len(certs) > 0 {
			out[key] = certs
		}
		errs = append(errs, keyErrs...)
		locked = append(locked, keyLocked...)
	}

	if len(out) == 0 {
		out = nil
	}
	return out, errs, locked
}

// parseValue runs the detection cascade for one Secret data key. The
// first successful format short-circuits the rest.
func parseValue(key string, value []byte, opts ParseOptions) ([]ParsedCert, []ParseError, []LockedBlob) {
	if len(value) == 0 {
		return nil, nil, nil
	}

	if certs, errs := parseValuePEM(key, value); len(certs) > 0 || len(errs) > 0 {
		return certs, errs, nil
	}

	if c, ok := parseValueDER(key, value); ok {
		return []ParsedCert{c}, nil, nil
	}

	if looksLikeASN1Sequence(value) {
		return parseValuePKCS12(key, value, opts)
	}

	if looksLikeJKS(value) {
		return parseValueJKS(key, value, opts)
	}

	return nil, nil, nil
}

// parseValuePEM is the original v0.1.0 PEM scanner. It returns certs
// for all CERTIFICATE blocks found, and ParseErrors for any
// CERTIFICATE-framed block whose DER body fails to parse.
func parseValuePEM(key string, value []byte) ([]ParsedCert, []ParseError) {
	var (
		certs []ParsedCert
		errs  []ParseError
		idx   int
		rest  = value
	)

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return certs, errs
		}
		if block.Type != certificateBlockType {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			errs = append(errs, ParseError{Key: key, Err: fmt.Errorf("parse certificate block %d: %w", idx, err)})
			idx++
			continue
		}
		certs = append(certs, summarise(key, idx, c))
		idx++
	}
}

// parseValueDER tries to interpret value as a raw X.509 DER
// certificate. Returns (cert, true) on success, zero/false otherwise.
// No error path — failure just means "this isn't a DER cert, try the
// next format."
func parseValueDER(key string, value []byte) (ParsedCert, bool) {
	if !looksLikeASN1Sequence(value) {
		return ParsedCert{}, false
	}
	c, err := x509.ParseCertificate(value)
	if err != nil {
		return ParsedCert{}, false
	}
	return summarise(key, 0, c), true
}

// parseValuePKCS12 attempts to decode value as a PKCS#12 bundle using
// the password mapped to this data key (or the empty password if none
// is configured). On success it emits the leaf cert at cert_index=0
// followed by the CAs in order. On password-related failure it returns
// a LockedBlob describing what was wrong.
func parseValuePKCS12(key string, value []byte, opts ParseOptions) ([]ParsedCert, []ParseError, []LockedBlob) {
	password, havePassword := opts.PKCS12Passwords[key]

	leafKey, leafCert, caCerts, err := pkcs12.DecodeChain(value, password)
	_ = leafKey // we don't store private keys
	if err == nil {
		certs := make([]ParsedCert, 0, 1+len(caCerts))
		certs = append(certs, summarise(key, 0, leafCert))
		for i, ca := range caCerts {
			certs = append(certs, summarise(key, i+1, ca))
		}
		return certs, nil, nil
	}
	if errors.Is(err, pkcs12.ErrIncorrectPassword) {
		reason := LockedWrongPassword
		if !havePassword {
			reason = LockedNoPassword
		}
		return nil, nil, []LockedBlob{{Key: key, Reason: reason}}
	}
	// Some other decode error — corrupt bundle, unsupported algorithm,
	// or a value that started with 0x30 0x82 but isn't actually
	// PKCS#12. Either way: not a cert as far as the caller is
	// concerned, but it's worth surfacing so the operator can
	// investigate.
	return nil, nil, []LockedBlob{{Key: key, Reason: LockedDecodeError}}
}

// looksLikeASN1Sequence is a cheap pre-filter for DER and PKCS#12
// detection. Real ASN.1 SEQUENCEs of non-trivial length start with the
// tag 0x30 followed by a long-form length byte 0x82 (2-byte length).
// Random binary blobs almost never match these four bytes by chance,
// so this lets us skip the PKCS#12 path for ConfigMap-style JSON,
// MongoDB URIs, Docker credentials, etc.
func looksLikeASN1Sequence(value []byte) bool {
	return len(value) >= 4 && value[0] == 0x30 && value[1] == 0x82
}

func summarise(key string, idx int, c *x509.Certificate) ParsedCert {
	dns := append([]string(nil), c.DNSNames...)
	sort.Strings(dns)
	return ParsedCert{
		Key:       key,
		Index:     idx,
		NotBefore: c.NotBefore,
		NotAfter:  c.NotAfter,
		Subject:   c.Subject.String(),
		Issuer:    c.Issuer.String(),
		Serial:    serialString(c),
		DNSNames:  dns,
	}
}

func serialString(c *x509.Certificate) string {
	if c.SerialNumber == nil {
		return ""
	}
	return c.SerialNumber.String()
}

// JoinDNSNames returns a comma-joined SAN list suitable for a metric label.
func (p ParsedCert) JoinDNSNames() string {
	return strings.Join(p.DNSNames, ",")
}
