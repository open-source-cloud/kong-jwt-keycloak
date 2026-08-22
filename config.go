package main

// Config holds the plugin configuration, mapped from KongPlugin CRD config fields.
// All fields use JSON tags matching the Kong plugin schema.
type Config struct {
	// Issuer and discovery
	AllowedIss        []string `json:"allowed_iss"`
	WellKnownTemplate string   `json:"well_known_template"`
	Algorithm         string   `json:"algorithm"`

	// Token location
	HeaderNames   []string `json:"header_names"`
	CookieNames   []string `json:"cookie_names"`
	URIParamNames []string `json:"uri_param_names"`

	// Authorization (OR logic — user needs ANY one of the listed values)
	RealmRoles  []string `json:"realm_roles"`
	ClientRoles []string `json:"client_roles"`
	Scope       []string `json:"scope"`

	// Public paths (skip auth entirely for these path prefixes)
	PublicPaths []string `json:"public_paths"`

	// Behavior
	JWKSCacheTTL      int  `json:"jwks_cache_ttl"`
	KeyGracePeriod    int  `json:"key_grace_period"`
	MaximumExpiration int  `json:"maximum_expiration"`
	RunOnPreflight    bool `json:"run_on_preflight"`

	// Upstream headers
	SetUpstreamHeaders bool `json:"set_upstream_headers"`
	StripAuthHeader    bool `json:"strip_auth_header"`
}

// applyDefaults fills in zero-value fields with sensible defaults.
func (c *Config) applyDefaults() {
	if c.WellKnownTemplate == "" {
		c.WellKnownTemplate = "%s/.well-known/openid-configuration"
	}
	if c.Algorithm == "" {
		c.Algorithm = "RS256"
	}
	if len(c.HeaderNames) == 0 {
		c.HeaderNames = []string{"authorization"}
	}
	if c.JWKSCacheTTL == 0 {
		c.JWKSCacheTTL = 3600
	}
	if c.KeyGracePeriod == 0 {
		c.KeyGracePeriod = 10
	}
	// RunOnPreflight defaults to true; since Go zero-value for bool is false,
	// we can't distinguish "not set" from "explicitly false" in JSON.
	// Kong will always send the full config, so this is fine.
}
