// Package cert extracts X.509 certificates from arbitrary byte slices.
//
// ParseAll walks the data of every key in a Secret, locating any
// PEM-encoded CERTIFICATE blocks and decoding them into ParsedCert
// summaries that are cheap to label as Prometheus series.
package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"
)

const certificateBlockType = "CERTIFICATE"

// ParsedCert is the minimal projection of an x509.Certificate that the
// metrics layer needs. The full certificate is intentionally not retained:
// it pins large byte slices in memory across reconciles.
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

// ParseError describes one failed decoding attempt. ParseAll continues
// past errors so that one bad block does not mask other valid certs in
// the same Secret.
type ParseError struct {
	Key string
	Err error
}

func (e ParseError) Error() string { return fmt.Sprintf("%s: %v", e.Key, e.Err) }
func (e ParseError) Unwrap() error { return e.Err }

// ParseAll walks every value in data, looks for PEM CERTIFICATE blocks,
// and returns the parsed certs grouped by the originating key. Values
// that contain no PEM at all are silently skipped (the typical case for
// non-cert keys like tls.key, dockerconfigjson, etc.).
//
// The returned map's outer iteration order is sorted by key so the
// caller's downstream behaviour (metric label emission) is
// deterministic — this matters for test assertions and for keeping the
// tracker's diff stable.
func ParseAll(data map[string][]byte) (map[string][]ParsedCert, []ParseError) {
	if len(data) == 0 {
		return nil, nil
	}

	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make(map[string][]ParsedCert, len(keys))
	var errs []ParseError

	for _, key := range keys {
		certs, keyErrs := parseValue(key, data[key])
		if len(certs) > 0 {
			out[key] = certs
		}
		errs = append(errs, keyErrs...)
	}

	if len(out) == 0 {
		out = nil
	}
	return out, errs
}

func parseValue(key string, value []byte) ([]ParsedCert, []ParseError) {
	if len(value) == 0 {
		return nil, nil
	}

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
