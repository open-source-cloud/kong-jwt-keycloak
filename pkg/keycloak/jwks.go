package keycloak

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// ErrKeyNotFound is returned when the issuer's JWKS has no key with the requested ID.
var ErrKeyNotFound = errors.New("key ID not found in JWKS")

const (
	// DefaultMinRefetchInterval is how long the provider waits, per issuer,
	// before going back to the issuer after a fetch.
	DefaultMinRefetchInterval = 10 * time.Second

	// defaultMaxFailedIssuers caps how many never-fetched issuers the provider
	// remembers failures for. With a wildcard in the allowed issuers the
	// issuer string is chosen by the client, so this map must stay bounded.
	defaultMaxFailedIssuers = 1024
)

// issuerKeys is the outcome of the last fetch for one issuer. Entries are
// replaced, never modified, so a pointer read under the lock stays valid.
type issuerKeys struct {
	keys        map[string]*rsa.PublicKey // nil until a fetch succeeds
	fetchedAt   time.Time                 // last successful fetch
	attemptedAt time.Time                 // last fetch, successful or not
	err         error                     // error from the last fetch, nil if it succeeded
}

func (e *issuerKeys) lookup(issuer, kid string) (*rsa.PublicKey, error) {
	if e.err != nil {
		return nil, e.err
	}
	key, ok := e.keys[kid]
	if !ok {
		return nil, fmt.Errorf("%w: kid %q, issuer %q", ErrKeyNotFound, kid, issuer)
	}
	return key, nil
}

// fetchCall is a fetch in progress. Concurrent requests for the same issuer
// wait for it instead of starting their own.
type fetchCall struct {
	done  chan struct{}
	entry *issuerKeys
}

// JWKSProvider fetches and caches JWKS keys from Keycloak.
//
// It goes back to an issuer at most once per minimum refetch interval, whether
// the previous fetch succeeded or failed, and coalesces concurrent fetches for
// the same issuer. A token's kid is read before its signature is checked, so
// without this limit any client could make the gateway hit the issuer twice
// per request by sending random kids.
type JWKSProvider struct {
	mu       sync.RWMutex
	cache    map[string]*issuerKeys // issuers with at least one successful fetch
	failed   map[string]*issuerKeys // issuers whose fetches have all failed
	inflight map[string]*fetchCall

	httpClient         *http.Client
	template           string
	cacheTTL           time.Duration
	minRefetchInterval time.Duration
	maxFailedIssuers   int
	now                func() time.Time
}

// Option configures a JWKSProvider.
type Option func(*JWKSProvider)

// WithMinRefetchInterval sets how long to wait, per issuer, before fetching
// the JWKS again after a fetch. A token with an unknown kid inside that window
// is rejected from the cache. The default is DefaultMinRefetchInterval.
func WithMinRefetchInterval(d time.Duration) Option {
	return func(p *JWKSProvider) {
		if d >= 0 {
			p.minRefetchInterval = d
		}
	}
}

// NewJWKSProvider creates a new provider with the given configuration.
func NewJWKSProvider(wellKnownTemplate string, cacheTTLSeconds int, opts ...Option) *JWKSProvider {
	p := &JWKSProvider{
		cache:    make(map[string]*issuerKeys),
		failed:   make(map[string]*issuerKeys),
		inflight: make(map[string]*fetchCall),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		template:           wellKnownTemplate,
		cacheTTL:           time.Duration(cacheTTLSeconds) * time.Second,
		minRefetchInterval: DefaultMinRefetchInterval,
		maxFailedIssuers:   defaultMaxFailedIssuers,
		now:                time.Now,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// GetKey returns the RSA public key for the given issuer and key ID.
// It uses cached keys when available and fresh, and refetches on cache miss,
// at most once per minimum refetch interval.
func (p *JWKSProvider) GetKey(issuer, kid string) (*rsa.PublicKey, error) {
	e := p.entry(issuer)

	if e != nil && e.keys != nil && p.now().Sub(e.fetchedAt) < p.cacheTTL {
		if key, ok := e.keys[kid]; ok {
			return key, nil
		}
	}

	if e == nil || p.now().Sub(e.attemptedAt) >= p.minRefetchInterval {
		e = p.fetch(issuer)
	}
	return e.lookup(issuer, kid)
}

// RefreshIfStale refetches JWKS for the issuer if the last fetch is older than
// gracePeriod (and the minimum refetch interval). Used after a signature
// verification failure to handle key rotation. It reports whether a fetch ran
// and succeeded.
func (p *JWKSProvider) RefreshIfStale(issuer string, gracePeriod time.Duration) bool {
	e := p.entry(issuer)
	wait := max(gracePeriod, p.minRefetchInterval)
	if e != nil && p.now().Sub(e.attemptedAt) <= wait {
		return false
	}
	return p.fetch(issuer).err == nil
}

func (p *JWKSProvider) entry(issuer string) *issuerKeys {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if e, ok := p.cache[issuer]; ok {
		return e
	}
	return p.failed[issuer]
}

// fetch fetches the issuer's JWKS, or waits for a fetch already in progress,
// and records the outcome. The lock is not held during the HTTP requests.
func (p *JWKSProvider) fetch(issuer string) *issuerKeys {
	p.mu.Lock()
	if c, ok := p.inflight[issuer]; ok {
		p.mu.Unlock()
		<-c.done
		return c.entry
	}
	c := &fetchCall{done: make(chan struct{})}
	p.inflight[issuer] = c
	prev := p.cache[issuer]
	p.mu.Unlock()

	keys, err := p.fetchKeys(issuer)
	now := p.now()
	next := &issuerKeys{attemptedAt: now}
	switch {
	case err == nil:
		next.keys, next.fetchedAt = keys, now
	case prev != nil:
		// Keep the keys we have; tokens signed with them still validate
		// until the cache TTL runs out.
		next.keys, next.fetchedAt, next.err = prev.keys, prev.fetchedAt, err
	default:
		next.err = err
	}

	p.mu.Lock()
	p.store(issuer, next)
	delete(p.inflight, issuer)
	p.mu.Unlock()

	c.entry = next
	close(c.done)
	return next
}

// store records a fetch outcome. The caller holds p.mu.
func (p *JWKSProvider) store(issuer string, e *issuerKeys) {
	if e.keys != nil {
		p.cache[issuer] = e
		delete(p.failed, issuer)
		return
	}
	if _, ok := p.failed[issuer]; !ok && len(p.failed) >= p.maxFailedIssuers {
		now := p.now()
		for iss, f := range p.failed {
			if now.Sub(f.attemptedAt) >= p.minRefetchInterval {
				delete(p.failed, iss)
			}
		}
		if len(p.failed) >= p.maxFailedIssuers {
			return
		}
	}
	p.failed[issuer] = e
}

func (p *JWKSProvider) fetchKeys(issuer string) (map[string]*rsa.PublicKey, error) {
	jwksURI, err := p.discoverJWKSURI(issuer)
	if err != nil {
		return nil, fmt.Errorf("discovering JWKS URI: %w", err)
	}

	keys, err := p.fetchJWKS(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}
	return keys, nil
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
