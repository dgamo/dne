package cert

import "strings"

// PasswordsAnnotation is the Secret annotation that maps PKCS#12 data
// keys to the data keys holding their passwords. Value format:
//
//	<datakey>=<passwordkey>[,<datakey>=<passwordkey>...]
//
// Whitespace and newlines around entries are tolerated. Malformed
// entries (no '=' or empty data key) are skipped silently. Duplicate
// data keys: last wins.
const PasswordsAnnotation = "dne.k8s.io/pkcs12-passwords" // #nosec G101 -- annotation name, not a credential.

// ParsePasswordsAnnotation parses the annotation value into a map of
// data-key → password-data-key. Returns nil for empty input — never
// errors so a bad annotation can't prevent the reconciler from running;
// the worst case is that affected PFX values fall back to the empty
// password and end up in dne_secret_locked_total.
func ParsePasswordsAnnotation(value string) map[string]string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	out := map[string]string{}
	for _, raw := range strings.Split(value, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		eq := strings.IndexByte(entry, '=')
		if eq <= 0 {
			// "no '=' at all" or "leading '=' with empty data key" — skip.
			continue
		}
		dataKey := strings.TrimSpace(entry[:eq])
		passwordKey := strings.TrimSpace(entry[eq+1:])
		if dataKey == "" || passwordKey == "" {
			continue
		}
		out[dataKey] = passwordKey
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
