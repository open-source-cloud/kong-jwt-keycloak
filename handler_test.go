package main

import "testing"

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
