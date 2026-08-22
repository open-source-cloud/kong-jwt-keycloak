package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// JWK represents a single JSON Web Key (RSA).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwksResponse is the response from the JWKS endpoint.
type jwksResponse struct {
	Keys []JWK `json:"keys"`
}

// wellKnownResponse is the relevant part of the OpenID Connect discovery document.
type wellKnownResponse struct {
	JWKsURI string `json:"jwks_uri"`
}

// cachedKeys holds the fetched keys and metadata for cache invalidation.
type cachedKeys struct {
	keys        map[string]*rsa.PublicKey
	fetchedAt   time.Time
	jwksURI     string
}

// JWKSProvider fetches and caches JWKS keys from Keycloak.
type JWKSProvider struct {
	mu         sync.RWMutex
	cache      map[string]*cachedKeys // keyed by issuer
	httpClient *http.Client
	template   string
	cacheTTL   time.Duration
}

// NewJWKSProvider creates a new provider with the given configuration.
func NewJWKSProvider(wellKnownTemplate string, cacheTTLSeconds int) *JWKSProvider {
	return &JWKSProvider{
		cache: make(map[string]*cachedKeys),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		template: wellKnownTemplate,
		cacheTTL: time.Duration(cacheTTLSeconds) * time.Second,
	}
}

// GetKey returns the RSA public key for the given issuer and key ID.
// It uses cached keys when available and fresh, and refetches on cache miss.
func (p *JWKSProvider) GetKey(issuer, kid string) (*rsa.PublicKey, error) {
	// Try cache first
	p.mu.RLock()
	cached, exists := p.cache[issuer]
	p.mu.RUnlock()

	if exists && time.Since(cached.fetchedAt) < p.cacheTTL {
		if key, ok := cached.keys[kid]; ok {
			return key, nil
		}
	}

	// Cache miss or expired — refetch
	return p.refetchAndGet(issuer, kid)
}

// RefreshIfStale refetches JWKS for the issuer if the cache is older than gracePeriod.
// Used after a signature verification failure to handle key rotation.
func (p *JWKSProvider) RefreshIfStale(issuer string, gracePeriod time.Duration) bool {
	p.mu.RLock()
	cached, exists := p.cache[issuer]
	p.mu.RUnlock()

	if !exists || time.Since(cached.fetchedAt) > gracePeriod {
		_, err := p.fetchAndCache(issuer)
		return err == nil
	}
	return false
}

func (p *JWKSProvider) refetchAndGet(issuer, kid string) (*rsa.PublicKey, error) {
	cached, err := p.fetchAndCache(issuer)
	if err != nil {
		return nil, err
	}
	key, ok := cached.keys[kid]
	if !ok {
		return nil, fmt.Errorf("key ID %q not found in JWKS for issuer %q", kid, issuer)
	}
	return key, nil
}

func (p *JWKSProvider) fetchAndCache(issuer string) (*cachedKeys, error) {
	jwksURI, err := p.discoverJWKSURI(issuer)
	if err != nil {
		return nil, fmt.Errorf("discovering JWKS URI: %w", err)
	}

	keys, err := p.fetchJWKS(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}

	cached := &cachedKeys{
		keys:      keys,
		fetchedAt: time.Now(),
		jwksURI:   jwksURI,
	}

	p.mu.Lock()
	p.cache[issuer] = cached
	p.mu.Unlock()

	return cached, nil
}

func (p *JWKSProvider) discoverJWKSURI(issuer string) (string, error) {
	url := fmt.Sprintf(p.template, issuer)

	resp, err := p.httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("fetching well-known config from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("well-known endpoint %s returned status %d", url, resp.StatusCode)
	}

	var wk wellKnownResponse
	if err := json.NewDecoder(resp.Body).Decode(&wk); err != nil {
		return "", fmt.Errorf("decoding well-known response: %w", err)
	}

	if wk.JWKsURI == "" {
		return "", fmt.Errorf("well-known response missing jwks_uri")
	}

	return wk.JWKsURI, nil
}

func (p *JWKSProvider) fetchJWKS(jwksURI string) (map[string]*rsa.PublicKey, error) {
	resp, err := p.httpClient.Get(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS from %s: %w", jwksURI, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint %s returned status %d", jwksURI, resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decoding JWKS response: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, jwk := range jwks.Keys {
		if jwk.Kty != "RSA" {
			continue
		}
		pubKey, err := jwkToRSAPublicKey(jwk)
		if err != nil {
			continue
		}
		keys[jwk.Kid] = pubKey
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid RSA keys found in JWKS")
	}

	return keys, nil
}

// jwkToRSAPublicKey converts a JWK with RSA parameters (n, e) to an *rsa.PublicKey.
func jwkToRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("decoding modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("decoding exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	if !e.IsInt64() {
		return nil, fmt.Errorf("exponent too large")
	}

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}
