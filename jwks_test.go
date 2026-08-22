package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
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

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, jwks
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

	provider := NewJWKSProvider("%s/.well-known/openid-configuration", 3600)

	// Populate cache
	provider.GetKey(srv.URL, "test-kid-0")

	// Force cache to be stale
	provider.mu.Lock()
	if cached, ok := provider.cache[srv.URL]; ok {
		cached.fetchedAt = time.Now().Add(-1 * time.Hour)
	}
	provider.mu.Unlock()

	// Should refresh
	refreshed := provider.RefreshIfStale(srv.URL, 10*time.Second)
	if !refreshed {
		t.Fatal("expected refresh to succeed")
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
