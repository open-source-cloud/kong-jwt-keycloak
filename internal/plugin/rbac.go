package plugin

import (
	"fmt"
	"strings"

	"github.com/open-source-cloud/kong-jwt-keycloak/pkg/keycloak"
)

// CheckAccess verifies that the token claims satisfy the plugin's authorization config.
// Returns nil if access is granted, or an error describing the failure.
// If no roles/scope are configured, any valid token is accepted.
func CheckAccess(claims *keycloak.Claims, conf *Config) error {
	if len(conf.RealmRoles) > 0 {
		if !hasAny(claims.RealmRoles(), conf.RealmRoles) {
			return fmt.Errorf("required realm roles: [%s]", strings.Join(conf.RealmRoles, ", "))
		}
	}

	if len(conf.ClientRoles) > 0 {
		if !hasAny(claims.ClientRoles(), conf.ClientRoles) {
			return fmt.Errorf("required client roles: [%s]", strings.Join(conf.ClientRoles, ", "))
		}
	}

	if len(conf.Scope) > 0 {
		if !hasAny(claims.Scopes(), conf.Scope) {
			return fmt.Errorf("required scopes: [%s]", strings.Join(conf.Scope, ", "))
		}
	}

	return nil
}

// hasAny returns true if any element in required is present in actual.
func hasAny(actual, required []string) bool {
	set := make(map[string]struct{}, len(actual))
	for _, v := range actual {
		set[v] = struct{}{}
	}
	for _, v := range required {
		if _, ok := set[v]; ok {
			return true
		}
	}
	return false
}
