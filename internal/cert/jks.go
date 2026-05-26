package cert

import (
	"bytes"
	"crypto/x509"
	"sort"
	"strings"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
)

// JKS magic-byte prefixes. They're disjoint from PKCS#12's ASN.1
// SEQUENCE prefix (0x30 0x82), so the cascade can dispatch unambiguously.
var (
	jksMagic   = []byte{0xFE, 0xED, 0xFE, 0xED}
	jceksMagic = []byte{0xCE, 0xCE, 0xCE, 0xCE}
)

func looksLikeJKS(value []byte) bool {
	if len(value) < 4 {
		return false
	}
	return bytes.HasPrefix(value, jksMagic) || bytes.HasPrefix(value, jceksMagic)
}

func isJKSPasswordError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "invalid digest")
}

// parseValueJKS decodes a Java KeyStore (JKS or JCEKS) and emits one
// ParsedCert per certificate found, indexing 0..N sequentially across
// alphabetically-ordered aliases. Private keys are discarded.
//
// Locking semantics mirror parseValuePKCS12: wrong/missing password →
// LockedBlob with the same LockedReason values; other decode errors →
// LockedDecodeError. The metric label "reason" doesn't distinguish
// PKCS#12 from JKS — documented as covering any keystore format.
func parseValueJKS(key string, value []byte, opts ParseOptions) ([]ParsedCert, []ParseError, []LockedBlob) {
	password, havePassword := opts.PKCS12Passwords[key]

	ks := keystore.New()
	err := ks.Load(bytes.NewReader(value), []byte(password))
	if err != nil {
		// keystore-go doesn't export a sentinel for wrong-password —
		// the only signal is the "got invalid digest" error from the
		// HMAC integrity check. We match on the message text; anything
		// else is treated as a format/decode error.
		if isJKSPasswordError(err) {
			reason := LockedWrongPassword
			if !havePassword {
				reason = LockedNoPassword
			}
			return nil, nil, []LockedBlob{{Key: key, Reason: reason}}
		}
		return nil, nil, []LockedBlob{{Key: key, Reason: LockedDecodeError}}
	}

	aliases := ks.Aliases()
	sort.Strings(aliases)

	var (
		out  []ParsedCert
		idx  int
		errs []ParseError
	)
	for _, alias := range aliases {
		switch {
		case ks.IsPrivateKeyEntry(alias):
			entry, err := ks.GetPrivateKeyEntry(alias, []byte(password))
			if err != nil {
				errs = append(errs, ParseError{Key: key, Err: err})
				continue
			}
			for _, ksCert := range entry.CertificateChain {
				c, parseErr := x509.ParseCertificate(ksCert.Content)
				if parseErr != nil {
					errs = append(errs, ParseError{Key: key, Err: parseErr})
					continue
				}
				out = append(out, summarise(key, idx, c))
				idx++
			}
		case ks.IsTrustedCertificateEntry(alias):
			entry, err := ks.GetTrustedCertificateEntry(alias)
			if err != nil {
				errs = append(errs, ParseError{Key: key, Err: err})
				continue
			}
			c, parseErr := x509.ParseCertificate(entry.Certificate.Content)
			if parseErr != nil {
				errs = append(errs, ParseError{Key: key, Err: parseErr})
				continue
			}
			out = append(out, summarise(key, idx, c))
			idx++
		}
	}
	return out, errs, nil
}
