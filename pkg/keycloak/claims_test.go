package keycloak

import (
	"testing"
)

func TestKeycloakClaims_RealmRoles(t *testing.T) {
	claims := &Claims{
		RealmAccess: RoleSet{Roles: []string{"admin", "viewer"}},
	}

	roles := claims.RealmRoles()
	if len(roles) != 2 || roles[0] != "admin" || roles[1] != "viewer" {
		t.Fatalf("unexpected realm roles: %v", roles)
	}
}

func TestKeycloakClaims_RealmRoles_Empty(t *testing.T) {
	claims := &Claims{}
	if roles := claims.RealmRoles(); len(roles) != 0 {
		t.Fatalf("expected empty roles, got: %v", roles)
	}
}

func TestKeycloakClaims_ClientRoles(t *testing.T) {
	claims := &Claims{
		Azp: "my-api",
		ResourceAccess: map[string]RoleSet{
			"my-api":       {Roles: []string{"read", "write"}},
			"other-client": {Roles: []string{"admin"}},
		},
	}

	roles := claims.ClientRoles()
	if len(roles) != 2 || roles[0] != "read" || roles[1] != "write" {
		t.Fatalf("unexpected client roles: %v", roles)
	}
}

func TestKeycloakClaims_ClientRoles_NoResourceAccess(t *testing.T) {
	claims := &Claims{Azp: "myapp"}
	if roles := claims.ClientRoles(); roles != nil {
		t.Fatalf("expected nil, got: %v", roles)
	}
}

func TestKeycloakClaims_ClientRoles_WrongClient(t *testing.T) {
	claims := &Claims{
		Azp: "myapp",
		ResourceAccess: map[string]RoleSet{
			"other-app": {Roles: []string{"admin"}},
		},
	}
	if roles := claims.ClientRoles(); roles != nil {
		t.Fatalf("expected nil for wrong client, got: %v", roles)
	}
}

func TestKeycloakClaims_Scopes(t *testing.T) {
	claims := &Claims{Scope: "openid profile email"}
	scopes := claims.Scopes()
	if len(scopes) != 3 {
		t.Fatalf("expected 3 scopes, got: %v", scopes)
	}
	if scopes[0] != "openid" || scopes[1] != "profile" || scopes[2] != "email" {
		t.Fatalf("unexpected scopes: %v", scopes)
	}
}

func TestKeycloakClaims_Scopes_Empty(t *testing.T) {
	claims := &Claims{}
	if scopes := claims.Scopes(); scopes != nil {
		t.Fatalf("expected nil for empty scope, got: %v", scopes)
	}
}

func TestKeycloakClaims_TenantID(t *testing.T) {
	claims := &Claims{TenantID: "cnh"}
	if claims.TenantID != "cnh" {
		t.Fatalf("expected tenant_id=cnh, got %q", claims.TenantID)
	}
}

func TestKeycloakClaims_AudienceString_Single(t *testing.T) {
	c := &Claims{}
	c.Audience = []string{"my-public"}
	if got := c.AudienceString(); got != "my-public" {
		t.Fatalf("unexpected audience: %q", got)
	}
}

func TestKeycloakClaims_AudienceString_Multiple(t *testing.T) {
	c := &Claims{}
	c.Audience = []string{"my-public", "account"}
	if got := c.AudienceString(); got != "my-public,account" {
		t.Fatalf("unexpected audience: %q", got)
	}
}

func TestKeycloakClaims_AudienceString_Empty(t *testing.T) {
	c := &Claims{}
	if got := c.AudienceString(); got != "" {
		t.Fatalf("expected empty audience, got %q", got)
	}
}
