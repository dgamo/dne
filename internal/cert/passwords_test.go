package cert_test

import (
	"reflect"
	"testing"

	"github.com/dgamo/dne/internal/cert"
)

func TestParsePasswordsAnnotation(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want map[string]string
	}{
		{name: "empty", in: "", want: nil},
		{name: "whitespace only", in: "   \n\t", want: nil},
		{name: "single entry", in: "a=A", want: map[string]string{"a": "A"}},
		{
			name: "two entries",
			in:   "a=A,b=B",
			want: map[string]string{"a": "A", "b": "B"},
		},
		{
			name: "entries with whitespace and newlines",
			in:   "  a = A , \n  b = B  ",
			want: map[string]string{"a": "A", "b": "B"},
		},
		{
			name: "eftpos motivating case",
			in:   "eftpos-live-certificate=EFTPOS_LIVE_SSL_CERTIFICATE_PASSWORD,eftpos-test-certificate=EFTPOS_TEST_SSL_CERTIFICATE_PASSWORD",
			want: map[string]string{
				"eftpos-live-certificate": "EFTPOS_LIVE_SSL_CERTIFICATE_PASSWORD",
				"eftpos-test-certificate": "EFTPOS_TEST_SSL_CERTIFICATE_PASSWORD",
			},
		},
		{name: "missing equals", in: "a", want: nil},
		{name: "empty data key", in: "=A", want: nil},
		{name: "empty password key", in: "a=", want: nil},
		{
			name: "valid entry followed by malformed one",
			in:   "a=A,broken,b=B",
			want: map[string]string{"a": "A", "b": "B"},
		},
		{
			name: "duplicate keys, last wins",
			in:   "a=first,a=second",
			want: map[string]string{"a": "second"},
		},
		{name: "trailing comma", in: "a=A,", want: map[string]string{"a": "A"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cert.ParsePasswordsAnnotation(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ParsePasswordsAnnotation(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestPasswordsAnnotationConst(t *testing.T) {
	// Stability check: the annotation name is part of the user-facing
	// contract documented in docs/configuration.md.
	if cert.PasswordsAnnotation != "dne.k8s.io/pkcs12-passwords" {
		t.Errorf("PasswordsAnnotation = %q, want %q", cert.PasswordsAnnotation, "dne.k8s.io/pkcs12-passwords")
	}
}
