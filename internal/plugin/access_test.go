package plugin

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kong/go-pdk/test"
	"github.com/golang-jwt/jwt/v5"
)

// testIssuer is a fake Keycloak realm serving discovery and a one-key JWKS.
type testIssuer struct {
	url string
	key *rsa.PrivateKey
	kid string
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	iss := &testIssuer{key: key, kid: "test-kid"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"jwks_uri": "http://" + r.Host + "/certs"})
	})
	mux.HandleFunc("/certs", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": iss.kid,
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	iss.url = srv.URL

	// The plugin keeps one JWKS provider per process; give each test a fresh one.
	resetProvider()
	t.Cleanup(resetProvider)

	return iss
}

func resetProvider() {
	providerMu.Lock()
	jwksProvider = nil
	providerMu.Unlock()
}

// token signs claims with the issuer's key. iss, iat and exp are filled in
// unless the caller sets them.
func (iss *testIssuer) token(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	full := jwt.MapClaims{
		"iss": iss.url,
		"sub": "user-1",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	for k, v := range claims {
		full[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, full)
	tok.Header["kid"] = iss.kid
	signed, err := tok.SignedString(iss.key)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	return signed
}

func (iss *testIssuer) config() *Config {
	return &Config{AllowedIss: []string{iss.url}, RunOnPreflight: true}
}

// access runs the plugin's Access phase for a GET carrying the given bearer token.
func access(t *testing.T, conf *Config, token string) *test.TestEnv {
	t.Helper()
	headers := http.Header{}
	if token != "" {
		headers.Set("Authorization", "Bearer "+token)
	}
	env, err := test.New(t, test.Request{
		Method:  "GET",
		Url:     "http://gateway.example.com/api",
		Headers: headers,
	})
	if err != nil {
		t.Fatalf("creating test env: %v", err)
	}
	env.DoAccess(conf)
	return env
}

func TestAccess_ValidTokenPasses(t *testing.T) {
	iss := newTestIssuer(t)

	env := access(t, iss.config(), iss.token(t, nil))

	if env.ClientRes.Status != 0 {
		t.Fatalf("valid token rejected with %d: %s", env.ClientRes.Status, env.ClientRes.Body)
	}
}

// Issue #13: 401 responses must not tell the client which check failed or
// which issuers the gateway trusts.
func TestAccess_UnauthorizedBodyIsGeneric(t *testing.T) {
	iss := newTestIssuer(t)

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	badSig := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": iss.url,
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	badSig.Header["kid"] = iss.kid
	badSigToken, _ := badSig.SignedString(otherKey)

	unknownKid := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": iss.url,
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	unknownKid.Header["kid"] = "rnd1"
	unknownKidToken, _ := unknownKid.SignedString(iss.key)

	cases := map[string]string{
		"missing token":   "",
		"malformed token": "not-a-jwt",
		"wrong issuer":    iss.token(t, jwt.MapClaims{"iss": "https://evil.example/realms/x"}),
		"unknown kid":     unknownKidToken,
		"bad signature":   badSigToken,
		"expired":         iss.token(t, jwt.MapClaims{"exp": time.Now().Add(-time.Minute).Unix()}),
	}

	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			env := access(t, iss.config(), token)

			if env.ClientRes.Status != 401 {
				t.Fatalf("status = %d, want 401", env.ClientRes.Status)
			}
			if got := string(env.ClientRes.Body); got != `{"error":"unauthorized"}` {
				t.Fatalf("body = %s, want {\"error\":\"unauthorized\"}", got)
			}
			if strings.Contains(string(env.ClientRes.Body), iss.url) {
				t.Fatal("body leaks the issuer URL")
			}
		})
	}
}

func TestAccess_ForbiddenStillNamesRequirement(t *testing.T) {
	iss := newTestIssuer(t)
	conf := iss.config()
	conf.RealmRoles = []string{"admin"}

	env := access(t, conf, iss.token(t, nil))

	if env.ClientRes.Status != 403 {
		t.Fatalf("status = %d, want 403", env.ClientRes.Status)
	}
	if !strings.Contains(string(env.ClientRes.Body), "admin") {
		t.Fatalf("403 body should name the missing role, got %s", env.ClientRes.Body)
	}
}
