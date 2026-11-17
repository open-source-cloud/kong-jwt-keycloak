package plugin

import (
	"strings"
	"testing"

	"github.com/open-source-cloud/kong-jwt-keycloak/pkg/keycloak"
)

func TestIsAllowedIssuer_ExactMatch(t *testing.T) {
	allowed := []string{"https://auth.example.com/realms/main"}

	if !isAllowedIssuer("https://auth.example.com/realms/main", allowed) {
		t.Fatal("exact match should be allowed")
	}
	if isAllowedIssuer("https://auth.example.com/realms/other", allowed) {
		t.Fatal("non-matching exact issuer should be rejected")
	}
}

func TestIsAllowedIssuer_PrefixWildcard(t *testing.T) {
	allowed := []string{
		"https://auth.example.com/realms/main",
		"https://auth.example.com/realms/tenant-*",
	}

	cases := []struct {
		issuer string
		want   bool
		desc   string
	}{
		{"https://auth.example.com/realms/main", true, "exact match still works alongside wildcard"},
		{"https://auth.example.com/realms/tenant-cnh", true, "tenant realm via wildcard"},
		{"https://auth.example.com/realms/tenant-acme", true, "any tenant slug accepted"},
		{"https://auth.example.com/realms/tenant-", false, "wildcard requires non-empty suffix"},
		{"https://auth.example.com/realms/other", false, "unrelated realm rejected"},
		{"https://other.host/realms/tenant-x", false, "different host rejected even with matching path"},
	}

	for _, c := range cases {
		got := isAllowedIssuer(c.issuer, allowed)
		if got != c.want {
			t.Errorf("%s: isAllowedIssuer(%q) = %v, want %v", c.desc, c.issuer, got, c.want)
		}
	}
}

func TestIsAllowedIssuer_EmptyAllowList(t *testing.T) {
	if isAllowedIssuer("any", nil) {
		t.Fatal("empty allow list should reject everything")
	}
}

func TestEscapeControl(t *testing.T) {
	cases := map[string]string{
		"plain reason":                     "plain reason",
		"tenant-x\nfake line":              `tenant-x\nfake line`,
		"a\r\nb":                           `a\r\nb`,
		"esc\x1b[31m":                      `esc\x1b[31m`,
		"tab\tand del\x7f":                 `tab\tand del\x7f`,
		"unicode stays: tenant-ñ, realm ü": "unicode stays: tenant-ñ, realm ü",
	}
	for in, want := range cases {
		if got := escapeControl(in); got != want {
			t.Errorf("escapeControl(%q) = %q, want %q", in, got, want)
		}
	}
}

// The discovery error wraps the issuer with %s, so under a wildcard
// allowed_iss a newline in the token's iss reaches the rejection reason.
func TestEscapeControl_IssuerFromToken(t *testing.T) {
	p := keycloak.NewJWKSProvider("%s/.well-known/openid-configuration", 3600)
	_, err := p.GetKey("https://auth.example.com/realms/tenant-x\nfake line", "kid")
	if err == nil {
		t.Fatal("expected an error for an issuer with a newline")
	}
	if got := escapeControl(err.Error()); strings.ContainsAny(got, "\r\n") {
		t.Fatalf("escaped reason still contains a line break: %q", got)
	}
}
