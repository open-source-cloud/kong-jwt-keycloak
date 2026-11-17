package keycloak

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return key
}

func rsaPublicKeyToJWK(pub *rsa.PublicKey, kid string) JWK {
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: kid,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func setupTestJWKSServer(t *testing.T, keys ...*rsa.PrivateKey) (*httptest.Server, []JWK) {
	t.Helper()
	srv, jwks, _ := setupCountingJWKSServer(t, keys...)
	return srv, jwks
}

// setupCountingJWKSServer is setupTestJWKSServer plus a counter of every
// request the fake issuer receives (discovery and JWKS).
func setupCountingJWKSServer(t *testing.T, keys ...*rsa.PrivateKey) (*httptest.Server, []JWK, *atomic.Int64) {
	t.Helper()

	jwks := make([]JWK, len(keys))
	for i, key := range keys {
		jwks[i] = rsaPublicKeyToJWK(&key.PublicKey, "test-kid-"+string(rune('0'+i)))
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		wk := wellKnownResponse{JWKsURI: "http://" + r.Host + "/protocol/openid-connect/certs"}
		json.NewEncoder(w).Encode(wk)
	})

	mux.HandleFunc("/protocol/openid-connect/certs", func(w http.ResponseWriter, r *http.Request) {
		resp := jwksResponse{Keys: jwks}
		json.NewEncoder(w).Encode(resp)
	})

	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, jwks, &hits
}

// fakeClock lets tests move the provider's clock instead of sleeping.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestProvider(clock *fakeClock, opts ...Option) *JWKSProvider {
	p := NewJWKSProvider("%s/.well-known/openid-configuration", 3600, opts...)
	p.now = clock.Now
	return p
}

func TestJWKSProvider_GetKey(t *testing.T) {
	key := generateTestRSAKey(t)
	srv, jwks := setupTestJWKSServer(t, key)

	provider := NewJWKSProvider("%s/.well-known/openid-configuration", 3600)
	kid := jwks[0].Kid

	pubKey, err := provider.GetKey(srv.URL, kid)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if pubKey.N.Cmp(key.PublicKey.N) != 0 {
		t.Fatal("returned key does not match original")
	}
}

func TestJWKSProvider_CacheHit(t *testing.T) {
	key := generateTestRSAKey(t)
	srv, jwks := setupTestJWKSServer(t, key)

	provider := NewJWKSProvider("%s/.well-known/openid-configuration", 3600)
	kid := jwks[0].Kid

	// First call — fetches from server
	_, err := provider.GetKey(srv.URL, kid)
	if err != nil {
		t.Fatalf("first GetKey failed: %v", err)
	}

	// Stop server — second call should use cache
	srv.Close()

	_, err = provider.GetKey(srv.URL, kid)
	if err != nil {
		t.Fatalf("cached GetKey failed: %v", err)
	}
}

func TestJWKSProvider_UnknownKid(t *testing.T) {
	key := generateTestRSAKey(t)
	srv, _ := setupTestJWKSServer(t, key)

	provider := NewJWKSProvider("%s/.well-known/openid-configuration", 3600)

	_, err := provider.GetKey(srv.URL, "nonexistent-kid")
	if err == nil {
		t.Fatal("expected error for unknown kid")
	}
}

func TestJWKSProvider_RefreshIfStale(t *testing.T) {
	key := generateTestRSAKey(t)
	srv, _ := setupTestJWKSServer(t, key)

	clock := newFakeClock()
	provider := newTestProvider(clock)

	// Populate cache
	if _, err := provider.GetKey(srv.URL, "test-kid-0"); err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if provider.RefreshIfStale(srv.URL, 10*time.Second) {
		t.Fatal("expected no refresh right after a fetch")
	}

	clock.Advance(time.Hour)

	if !provider.RefreshIfStale(srv.URL, 10*time.Second) {
		t.Fatal("expected refresh to succeed")
	}
}

// Reproduction from issue #12: five tokens with random kids used to cost the
// issuer ten requests (discovery + JWKS each).
func TestJWKSProvider_UnknownKidsDoNotHammerIssuer(t *testing.T) {
	key := generateTestRSAKey(t)
	srv, _, hits := setupCountingJWKSServer(t, key)

	clock := newFakeClock()
	provider := newTestProvider(clock, WithMinRefetchInterval(10*time.Second))

	for i := 1; i <= 5; i++ {
		_, err := provider.GetKey(srv.URL, "rnd"+strconv.Itoa(i))
		if !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("rnd%d: expected ErrKeyNotFound, got %v", i, err)
		}
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("issuer received %d requests, want 2 (one discovery, one JWKS)", got)
	}

	// The known kid is still served from the cache.
	if _, err := provider.GetKey(srv.URL, "test-kid-0"); err != nil {
		t.Fatalf("known kid: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("known kid caused a fetch: %d requests", got)
	}
}

func TestJWKSProvider_UnknownKidRefetchesOncePerInterval(t *testing.T) {
	key := generateTestRSAKey(t)
	srv, _, hits := setupCountingJWKSServer(t, key)

	clock := newFakeClock()
	provider := newTestProvider(clock, WithMinRefetchInterval(10*time.Second))

	if _, err := provider.GetKey(srv.URL, "test-kid-0"); err != nil {
		t.Fatalf("warm-up: %v", err)
	}
	hits.Store(0)

	// Cache still fresh, interval elapsed: one refetch for the first unknown kid,
	// then nothing until the interval passes again.
	clock.Advance(11 * time.Second)
	for i := 0; i < 5; i++ {
		provider.GetKey(srv.URL, "rnd")
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("after first interval: %d requests, want 2", got)
	}

	clock.Advance(11 * time.Second)
	for i := 0; i < 5; i++ {
		provider.GetKey(srv.URL, "rnd")
	}
	if got := hits.Load(); got != 4 {
		t.Fatalf("after second interval: %d requests, want 4", got)
	}
}

func TestJWKSProvider_RotatedKeyFoundAfterInterval(t *testing.T) {
	oldKey := generateTestRSAKey(t)
	newKey := generateTestRSAKey(t)

	var mu sync.Mutex
	published := []JWK{rsaPublicKeyToJWK(&oldKey.PublicKey, "old")}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(wellKnownResponse{JWKsURI: "http://" + r.Host + "/certs"})
	})
	mux.HandleFunc("/certs", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		json.NewEncoder(w).Encode(jwksResponse{Keys: published})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	clock := newFakeClock()
	provider := newTestProvider(clock, WithMinRefetchInterval(10*time.Second))

	if _, err := provider.GetKey(srv.URL, "old"); err != nil {
		t.Fatalf("old key: %v", err)
	}

	mu.Lock()
	published = append(published, rsaPublicKeyToJWK(&newKey.PublicKey, "new"))
	mu.Unlock()

	// Inside the interval the new kid is answered from the cache.
	if _, err := provider.GetKey(srv.URL, "new"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("new kid inside interval: expected ErrKeyNotFound, got %v", err)
	}

	clock.Advance(11 * time.Second)
	got, err := provider.GetKey(srv.URL, "new")
	if err != nil {
		t.Fatalf("new kid after interval: %v", err)
	}
	if got.N.Cmp(newKey.PublicKey.N) != 0 {
		t.Fatal("returned key does not match the rotated key")
	}
}

func TestJWKSProvider_ConcurrentFetchesAreCoalesced(t *testing.T) {
	key := generateTestRSAKey(t)
	srv, _, hits := setupCountingJWKSServer(t, key)

	provider := newTestProvider(newFakeClock())

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			provider.GetKey(srv.URL, "rnd"+strconv.Itoa(i))
		}(i)
	}
	wg.Wait()

	if got := hits.Load(); got != 2 {
		t.Fatalf("50 concurrent unknown kids caused %d requests, want 2", got)
	}
}

func TestJWKSProvider_FailedFetchIsThrottled(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	clock := newFakeClock()
	provider := newTestProvider(clock, WithMinRefetchInterval(10*time.Second))

	for i := 0; i < 5; i++ {
		if _, err := provider.GetKey(srv.URL, "any"); err == nil {
			t.Fatal("expected an error from a failing issuer")
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("failing issuer received %d requests, want 1", got)
	}

	clock.Advance(11 * time.Second)
	provider.GetKey(srv.URL, "any")
	if got := hits.Load(); got != 2 {
		t.Fatalf("after interval: %d requests, want 2", got)
	}
}

func TestJWKSProvider_FailedRefetchKeepsCachedKeys(t *testing.T) {
	key := generateTestRSAKey(t)
	jwks := []JWK{rsaPublicKeyToJWK(&key.PublicKey, "test-kid-0")}
	var down atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(wellKnownResponse{JWKsURI: "http://" + r.Host + "/certs"})
	})
	mux.HandleFunc("/certs", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwksResponse{Keys: jwks})
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	clock := newFakeClock()
	provider := newTestProvider(clock, WithMinRefetchInterval(10*time.Second))

	if _, err := provider.GetKey(srv.URL, "test-kid-0"); err != nil {
		t.Fatalf("warm-up: %v", err)
	}

	down.Store(true)
	clock.Advance(11 * time.Second)
	if _, err := provider.GetKey(srv.URL, "rnd"); err == nil {
		t.Fatal("expected an error for an unknown kid while the issuer is down")
	}
	if _, err := provider.GetKey(srv.URL, "test-kid-0"); err != nil {
		t.Fatalf("known kid should still validate from the fresh cache: %v", err)
	}
}

func TestJWKSProvider_FailedIssuersAreBounded(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)

	clock := newFakeClock()
	provider := newTestProvider(clock, WithMinRefetchInterval(10*time.Second))
	provider.maxFailedIssuers = 8

	for i := 0; i < 50; i++ {
		provider.GetKey(srv.URL+"/realms/tenant-"+strconv.Itoa(i), "kid")
	}
	if got := len(provider.failed); got > 8 {
		t.Fatalf("failed-issuer map grew to %d entries, cap is 8", got)
	}

	// Once the old failures expire they make room for new ones.
	clock.Advance(11 * time.Second)
	provider.GetKey(srv.URL+"/realms/tenant-new", "kid")
	if _, ok := provider.failed[srv.URL+"/realms/tenant-new"]; !ok {
		t.Fatal("expected expired failures to be pruned for a new issuer")
	}
	if got := len(provider.failed); got > 8 {
		t.Fatalf("failed-issuer map grew to %d entries, cap is 8", got)
	}
}

func TestJWKToRSAPublicKey(t *testing.T) {
	key := generateTestRSAKey(t)
	jwk := rsaPublicKeyToJWK(&key.PublicKey, "test")

	pub, err := jwkToRSAPublicKey(jwk)
	if err != nil {
		t.Fatalf("jwkToRSAPublicKey failed: %v", err)
	}

	if pub.N.Cmp(key.PublicKey.N) != 0 {
		t.Fatal("modulus mismatch")
	}
	if pub.E != key.PublicKey.E {
		t.Fatal("exponent mismatch")
	}
}

func TestJWKToRSAPublicKey_InvalidModulus(t *testing.T) {
	jwk := JWK{Kty: "RSA", N: "!!!invalid!!!", E: "AQAB"}
	_, err := jwkToRSAPublicKey(jwk)
	if err == nil {
		t.Fatal("expected error for invalid modulus")
	}
}
