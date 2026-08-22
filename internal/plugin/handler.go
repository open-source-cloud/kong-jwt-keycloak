package plugin

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Kong/go-pdk"
	"github.com/golang-jwt/jwt/v5"

	"github.com/open-source-cloud/kong-jwt-keycloak/pkg/keycloak"
)

var jwksProvider *keycloak.JWKSProvider

func (conf *Config) Access(kong *pdk.PDK) {
	conf.applyDefaults()

	// Lazy-init the global JWKS provider
	if jwksProvider == nil {
		jwksProvider = keycloak.NewJWKSProvider(conf.WellKnownTemplate, conf.JWKSCacheTTL)
	}

	// 1. Skip preflight if configured
	if !conf.RunOnPreflight {
		method, err := kong.Request.GetMethod()
		if err == nil && method == "OPTIONS" {
			return
		}
	}

	// 2. Skip public paths
	if len(conf.PublicPaths) > 0 {
		path, err := kong.Request.GetPath()
		if err == nil && isPublicPath(path, conf.PublicPaths) {
			return
		}
	}

	// 3. Extract token
	tokenStr, err := extractToken(kong, conf)
	if err != nil || tokenStr == "" {
		exitUnauthorized(kong, "missing or invalid authorization token")
		return
	}

	// 3. Parse token without verification to read header
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	unverified, _, err := parser.ParseUnverified(tokenStr, &keycloak.Claims{})
	if err != nil {
		exitUnauthorized(kong, "malformed token")
		return
	}

	// 4. Validate algorithm
	alg, _ := unverified.Header["alg"].(string)
	if alg != conf.Algorithm {
		exitUnauthorized(kong, fmt.Sprintf("unexpected algorithm: %s", alg))
		return
	}

	kid, _ := unverified.Header["kid"].(string)
	if kid == "" {
		exitUnauthorized(kong, "missing kid in token header")
		return
	}

	// 5. Validate issuer
	unverifiedClaims := unverified.Claims.(*keycloak.Claims)
	issuer, _ := unverifiedClaims.GetIssuer()
	if !isAllowedIssuer(issuer, conf.AllowedIss) {
		exitUnauthorized(kong, fmt.Sprintf("invalid issuer: %s", issuer))
		return
	}

	// 6. Fetch public key and verify signature
	claims, err := verifyToken(tokenStr, issuer, kid, conf)
	if err != nil {
		exitUnauthorized(kong, err.Error())
		return
	}

	// 7. Validate maximum expiration
	if conf.MaximumExpiration > 0 {
		exp, _ := claims.GetExpirationTime()
		iat, _ := claims.GetIssuedAt()
		if exp != nil && iat != nil {
			if exp.Sub(iat.Time) > time.Duration(conf.MaximumExpiration)*time.Second {
				exitUnauthorized(kong, "token exceeds maximum expiration")
				return
			}
		}
	}

	// 8. Check RBAC
	if err := CheckAccess(claims, conf); err != nil {
		exitForbidden(kong, err.Error())
		return
	}

	// 9. Set upstream headers consumed by the upstream service.
	if conf.SetUpstreamHeaders {
		sub, _ := claims.GetSubject()
		kong.ServiceRequest.SetHeader("X-User-Sub", sub)
		kong.ServiceRequest.SetHeader("X-User-Email", claims.Email)
		kong.ServiceRequest.SetHeader("X-User-Name", claims.PreferredUsername)
		kong.ServiceRequest.SetHeader("X-Realm-Roles", strings.Join(claims.RealmRoles(), ","))
		if aud := claims.AudienceString(); aud != "" {
			kong.ServiceRequest.SetHeader("X-Token-Audience", aud)
		}
		if claims.TenantID != "" {
			kong.ServiceRequest.SetHeader("X-Tenant-Slug", claims.TenantID)
		}
	}

	// 10. Optionally strip Authorization header
	if conf.StripAuthHeader {
		kong.ServiceRequest.ClearHeader("Authorization")
	}
}

// verifyToken parses and verifies the JWT signature using JWKS.
// On signature failure, it retries once if the cache is stale (key rotation).
func verifyToken(tokenStr, issuer, kid string, conf *Config) (*keycloak.Claims, error) {
	pubKey, err := jwksProvider.GetKey(issuer, kid)
	if err != nil {
		return nil, fmt.Errorf("unable to get public key: %w", err)
	}

	claims := &keycloak.Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		return pubKey, nil
	}, jwt.WithIssuer(issuer), jwt.WithExpirationRequired())

	if err != nil {
		// Retry once if keys might have rotated
		gracePeriod := time.Duration(conf.KeyGracePeriod) * time.Second
		if jwksProvider.RefreshIfStale(issuer, gracePeriod) {
			pubKey, err2 := jwksProvider.GetKey(issuer, kid)
			if err2 != nil {
				return nil, fmt.Errorf("token verification failed: %w", err)
			}
			token, err = jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
				return pubKey, nil
			}, jwt.WithIssuer(issuer), jwt.WithExpirationRequired())
			if err != nil {
				return nil, fmt.Errorf("token verification failed after key refresh: %w", err)
			}
		} else {
			return nil, fmt.Errorf("token verification failed: %w", err)
		}
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// extractToken retrieves the Bearer token from configured locations.
func extractToken(kong *pdk.PDK, conf *Config) (string, error) {
	// Try headers first
	for _, name := range conf.HeaderNames {
		header, err := kong.Request.GetHeader(name)
		if err != nil || header == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(header), "bearer ") {
			return header[7:], nil
		}
		return header, nil
	}

	// Try query params
	for _, name := range conf.URIParamNames {
		args, err := kong.Request.GetQuery(-1)
		if err != nil {
			continue
		}
		if vals, ok := args[name]; ok && len(vals) > 0 {
			return vals[0], nil
		}
	}

	return "", fmt.Errorf("no token found")
}

// isPublicPath checks if the request path matches any configured public path prefix.
func isPublicPath(path string, publicPaths []string) bool {
	for _, pp := range publicPaths {
		if path == pp || strings.HasPrefix(path, pp+"/") || strings.HasPrefix(path, pp+"?") {
			return true
		}
	}
	return false
}

// isAllowedIssuer matches an issuer against a list of allowed entries. Each
// entry is either an exact issuer URL or a prefix pattern ending in '*' (e.g.
// "https://auth.example.com/realms/tenant-*"). The wildcard
// matches any non-empty suffix.
func isAllowedIssuer(issuer string, allowed []string) bool {
	for _, a := range allowed {
		if prefix, hasWildcard := strings.CutSuffix(a, "*"); hasWildcard {
			if len(issuer) > len(prefix) && strings.HasPrefix(issuer, prefix) {
				return true
			}
			continue
		}
		if a == issuer {
			return true
		}
	}
	return false
}

func exitUnauthorized(kong *pdk.PDK, message string) {
	body, _ := json.Marshal(map[string]string{
		"error":   "unauthorized",
		"message": message,
	})
	kong.Response.Exit(401, body, map[string][]string{
		"Content-Type": {"application/json"},
	})
}

func exitForbidden(kong *pdk.PDK, message string) {
	body, _ := json.Marshal(map[string]string{
		"error":   "forbidden",
		"message": message,
	})
	kong.Response.Exit(403, body, map[string][]string{
		"Content-Type": {"application/json"},
	})
}
