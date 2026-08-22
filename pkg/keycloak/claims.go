package keycloak

import (
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// RoleSet holds a list of roles for a client or realm.
type RoleSet struct {
	Roles []string `json:"roles"`
}

// Claims represents the JWT claims structure issued by Keycloak.
type Claims struct {
	jwt.RegisteredClaims
	Email             string             `json:"email"`
	PreferredUsername string             `json:"preferred_username"`
	RealmAccess       RoleSet            `json:"realm_access"`
	ResourceAccess    map[string]RoleSet `json:"resource_access"`
	Scope             string             `json:"scope"`
	Azp               string             `json:"azp"`

	// TenantID is a hardcoded claim injected by per-tenant Keycloak realms
	// (tenant-<slug>). Empty for tokens issued by the shared 'main'
	// realm (admin-side requests are not tenant-scoped).
	TenantID string `json:"tenant_id"`
}

// AudienceString returns the JWT audience as a single comma-separated string,
// suitable for an X-Token-Audience HTTP header. Empty if no audience is set.
func (c *Claims) AudienceString() string {
	if len(c.Audience) == 0 {
		return ""
	}
	return strings.Join(c.Audience, ",")
}

// RealmRoles returns the list of realm-level roles from the token.
func (c *Claims) RealmRoles() []string {
	return c.RealmAccess.Roles
}

// ClientRoles returns the roles for the authorized party (azp) client.
func (c *Claims) ClientRoles() []string {
	if c.ResourceAccess == nil {
		return nil
	}
	rs, ok := c.ResourceAccess[c.Azp]
	if !ok {
		return nil
	}
	return rs.Roles
}

// Scopes returns the token scopes as a slice (space-separated in JWT).
func (c *Claims) Scopes() []string {
	if c.Scope == "" {
		return nil
	}
	return strings.Split(c.Scope, " ")
}
