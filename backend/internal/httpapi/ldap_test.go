package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"hycanvas/backend/internal/accounts"
	"hycanvas/backend/internal/ldapauth"
	"hycanvas/backend/internal/oidc"
	"hycanvas/backend/internal/platform/config"
)

func resetRateBuckets() {
	audienceRateMu.Lock()
	audienceRates = map[string]*audienceBucket{}
	audienceRateMu.Unlock()
}

func postJSON(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

// Unconfigured or policy-disabled LDAP answers 403 without touching the DB.
func TestLdapRouteDisabled(t *testing.T) {
	resetRateBuckets()
	for name, tc := range map[string]struct {
		svc    *ldapauth.Service
		policy config.AuthPolicy
	}{
		"not configured": {ldapauth.NewServiceWithConfig(nil), config.AuthPolicy{LdapLogin: true, LdapSignup: true}},
		"policy off":     {ldapauth.NewServiceWithConfig(&ldapauth.Config{URL: "ldap://127.0.0.1:1", BaseDN: "dc=x"}), config.AuthPolicy{}},
	} {
		r := chi.NewRouter()
		r.Route("/api/v1", func(api chi.Router) { mountLDAP(api, tc.svc, accounts.NewService(nil, "s"), false, tc.policy, nil) })
		srv := httptest.NewServer(r)
		resp := postJSON(t, srv.URL+"/api/v1/auth/ldap/login", `{"username":"a","password":"b"}`)
		resp.Body.Close()
		srv.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: got %d, want 403", name, resp.StatusCode)
		}
	}
}

func TestLdapProvidersBlock(t *testing.T) {
	get := func(svc *ldapauth.Service, policy config.AuthPolicy) map[string]any {
		r := chi.NewRouter()
		r.Route("/api/v1", func(api chi.Router) {
			mountOIDC(api, oidc.NewService("s"), accounts.NewService(nil, "s"), false, policy, config.CaptchaConfig{}, svc)
		})
		srv := httptest.NewServer(r)
		defer srv.Close()
		resp, err := http.Get(srv.URL + "/api/v1/auth/providers")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return body
	}
	on := get(ldapauth.NewServiceWithConfig(&ldapauth.Config{URL: "ldaps://dc", BaseDN: "dc=x", Label: "E-Go Staff"}), config.AuthPolicy{LdapLogin: true})
	if l, _ := on["ldap"].(map[string]any); l == nil || l["label"] != "E-Go Staff" {
		t.Fatalf("ldap block missing or wrong: %v", on["ldap"])
	}
	if p, _ := on["policy"].(map[string]any); p["ldapLogin"] != true {
		t.Fatalf("policy should report ldapLogin: %v", on["policy"])
	}
	if off := get(nil, config.AuthPolicy{LdapLogin: true}); off["ldap"] != nil {
		t.Fatalf("ldap block must be null when unconfigured: %v", off["ldap"])
	}
}

func TestLdapBadRequest(t *testing.T) {
	resetRateBuckets()
	svc := ldapauth.NewServiceWithConfig(&ldapauth.Config{URL: "ldap://127.0.0.1:1", BaseDN: "dc=x", Timeout: time.Second})
	r := chi.NewRouter()
	r.Route("/api/v1", func(api chi.Router) {
		mountLDAP(api, svc, accounts.NewService(nil, "s"), false, config.AuthPolicy{LdapLogin: true}, nil)
	})
	srv := httptest.NewServer(r)
	defer srv.Close()
	for _, b := range []string{`{}`, `{"username":"a"}`, `{"password":"b"}`, `not json`} {
		resp := postJSON(t, srv.URL+"/api/v1/auth/ldap/login", b)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", b, resp.StatusCode)
		}
	}
	// An unreachable directory is 503, not 401.
	resp := postJSON(t, srv.URL+"/api/v1/auth/ldap/login", `{"username":"a","password":"b"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("unreachable directory: got %d, want 503", resp.StatusCode)
	}
}

// End to end against a real directory and database (LDAP_TEST_URL + DATABASE_URL).
func TestLdapLoginEndToEnd(t *testing.T) {
	ldapURL, dsn := os.Getenv("LDAP_TEST_URL"), os.Getenv("DATABASE_URL")
	if ldapURL == "" || dsn == "" {
		t.Skip("LDAP_TEST_URL and DATABASE_URL needed; skipping")
	}
	resetRateBuckets()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	// Start clean for the fixture users so the test is repeatable.
	_, _ = pool.Exec(ctx, `DELETE FROM "users" WHERE email IN ('alice@ego.test','bob@ego.test')`)
	defer func() { _, _ = pool.Exec(ctx, `DELETE FROM "users" WHERE email IN ('alice@ego.test','bob@ego.test')`) }()

	svc := ldapauth.NewServiceWithConfig(&ldapauth.Config{
		URL: ldapURL, BaseDN: "ou=people,dc=ego,dc=test",
		BindDN: "cn=svc,ou=service,dc=ego,dc=test", BindPassword: "svcpw",
		UserFilter: "(|(uid={username})(mail={username}))", GroupFilter: "(|(member={dn})(uniqueMember={dn})(memberUid={username}))",
		RequiredGroupDN: "cn=hycanvas-users,ou=groups,dc=ego,dc=test",
		EmailAttr:       "mail", NameAttr: "displayName", Timeout: 5 * time.Second, Label: "E-Go",
	})
	r := chi.NewRouter()
	r.Route("/api/v1", func(api chi.Router) {
		mountLDAP(api, svc, accounts.NewService(pool, "test-jwt-secret"), false, config.AuthPolicy{LdapLogin: true, LdapSignup: true}, nil)
	})
	srv := httptest.NewServer(r)
	defer srv.Close()
	url := srv.URL + "/api/v1/auth/ldap/login"

	// Good credentials: 200, session cookies, user provisioned.
	resp := postJSON(t, url, `{"username":"alice","password":"alicepw"}`)
	var body struct {
		User struct{ Email, Name string } `json:"user"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || body.User.Email != "alice@ego.test" || body.User.Name != "Alice Chan" {
		t.Fatalf("alice: status %d body %+v", resp.StatusCode, body)
	}
	if len(resp.Cookies()) < 2 {
		t.Fatalf("expected access + refresh cookies, got %v", resp.Cookies())
	}
	// Second sign-in reuses the same account.
	resp = postJSON(t, url, `{"username":"alice@ego.test","password":"alicepw"}`)
	resp.Body.Close()
	var n int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM "users" WHERE email='alice@ego.test'`).Scan(&n)
	if resp.StatusCode != http.StatusOK || n != 1 {
		t.Fatalf("returning alice: status %d, users %d", resp.StatusCode, n)
	}

	for _, c := range []struct {
		body string
		want int
	}{
		{`{"username":"alice","password":"wrong"}`, http.StatusUnauthorized},
		{`{"username":"ghost","password":"x"}`, http.StatusUnauthorized},
		{`{"username":"bob","password":"bobpw"}`, http.StatusForbidden}, // not in the group
	} {
		resp := postJSON(t, url, c.body)
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s: got %d want %d", c.body, resp.StatusCode, c.want)
		}
	}
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM "users" WHERE email='bob@ego.test'`).Scan(&n)
	if n != 0 {
		t.Fatal("a user outside the required group must not be provisioned")
	}

	// Per-username throttle: hammering one account trips 429 well before an
	// Active Directory lockout threshold would.
	got429 := false
	for i := 0; i < 10; i++ {
		resp := postJSON(t, url, `{"username":"alice","password":"guess"}`)
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("repeated attempts for one username were never throttled")
	}
}
