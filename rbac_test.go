package main

import (
	"testing"
)

func TestCheckAccess_NoRestrictions(t *testing.T) {
	claims := &KeycloakClaims{}
	conf := &Config{}

	if err := CheckAccess(claims, conf); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestCheckAccess_RealmRoles_Pass(t *testing.T) {
	claims := &KeycloakClaims{
		RealmAccess: RoleSet{Roles: []string{"admin", "viewer"}},
	}
	conf := &Config{RealmRoles: []string{"admin"}}

	if err := CheckAccess(claims, conf); err != nil {
		t.Fatalf("expected pass, got: %v", err)
	}
}

func TestCheckAccess_RealmRoles_Fail(t *testing.T) {
	claims := &KeycloakClaims{
		RealmAccess: RoleSet{Roles: []string{"viewer"}},
	}
	conf := &Config{RealmRoles: []string{"admin"}}

	if err := CheckAccess(claims, conf); err == nil {
		t.Fatal("expected error for missing realm role")
	}
}

func TestCheckAccess_RealmRoles_ORLogic(t *testing.T) {
	claims := &KeycloakClaims{
		RealmAccess: RoleSet{Roles: []string{"viewer"}},
	}
	conf := &Config{RealmRoles: []string{"admin", "viewer"}}

	if err := CheckAccess(claims, conf); err != nil {
		t.Fatalf("expected pass with OR logic, got: %v", err)
	}
}

func TestCheckAccess_ClientRoles_Pass(t *testing.T) {
	claims := &KeycloakClaims{
		Azp: "my-api",
		ResourceAccess: map[string]RoleSet{
			"my-api": {Roles: []string{"write", "read"}},
		},
	}
	conf := &Config{ClientRoles: []string{"write"}}

	if err := CheckAccess(claims, conf); err != nil {
		t.Fatalf("expected pass, got: %v", err)
	}
}

func TestCheckAccess_ClientRoles_Fail_NoResourceAccess(t *testing.T) {
	claims := &KeycloakClaims{Azp: "my-api"}
	conf := &Config{ClientRoles: []string{"write"}}

	if err := CheckAccess(claims, conf); err == nil {
		t.Fatal("expected error for missing resource_access")
	}
}

func TestCheckAccess_Scope_Pass(t *testing.T) {
	claims := &KeycloakClaims{Scope: "openid profile email"}
	conf := &Config{Scope: []string{"profile"}}

	if err := CheckAccess(claims, conf); err != nil {
		t.Fatalf("expected pass, got: %v", err)
	}
}

func TestCheckAccess_Scope_Fail(t *testing.T) {
	claims := &KeycloakClaims{Scope: "openid"}
	conf := &Config{Scope: []string{"admin-scope"}}

	if err := CheckAccess(claims, conf); err == nil {
		t.Fatal("expected error for missing scope")
	}
}

func TestCheckAccess_Combined_AllPass(t *testing.T) {
	claims := &KeycloakClaims{
		RealmAccess: RoleSet{Roles: []string{"admin"}},
		Azp:         "myapp",
		ResourceAccess: map[string]RoleSet{
			"myapp": {Roles: []string{"write"}},
		},
		Scope: "openid profile",
	}
	conf := &Config{
		RealmRoles:  []string{"admin"},
		ClientRoles: []string{"write"},
		Scope:       []string{"profile"},
	}

	if err := CheckAccess(claims, conf); err != nil {
		t.Fatalf("expected pass, got: %v", err)
	}
}

func TestCheckAccess_Combined_RealmFails(t *testing.T) {
	claims := &KeycloakClaims{
		RealmAccess: RoleSet{Roles: []string{"viewer"}},
		Azp:         "myapp",
		ResourceAccess: map[string]RoleSet{
			"myapp": {Roles: []string{"write"}},
		},
		Scope: "openid profile",
	}
	conf := &Config{
		RealmRoles:  []string{"admin"},
		ClientRoles: []string{"write"},
		Scope:       []string{"profile"},
	}

	if err := CheckAccess(claims, conf); err == nil {
		t.Fatal("expected error: realm role should fail")
	}
}

func TestHasAny(t *testing.T) {
	tests := []struct {
		actual   []string
		required []string
		expected bool
	}{
		{[]string{"a", "b"}, []string{"b"}, true},
		{[]string{"a", "b"}, []string{"c"}, false},
		{[]string{}, []string{"a"}, false},
		{[]string{"a"}, []string{}, false},
		{nil, []string{"a"}, false},
		{[]string{"admin", "viewer"}, []string{"superadmin", "admin"}, true},
	}

	for _, tt := range tests {
		got := hasAny(tt.actual, tt.required)
		if got != tt.expected {
			t.Errorf("hasAny(%v, %v) = %v, want %v", tt.actual, tt.required, got, tt.expected)
		}
	}
}
