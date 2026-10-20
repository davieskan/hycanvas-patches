package ldapauth

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestUserFilterEscapesInjection(t *testing.T) {
	got := UserFilter(defaultUserFilter, "*)(uid=*")
	if strings.Contains(got, "(uid=*)") || !strings.Contains(got, `\2a\29\28uid=\2a`) {
		t.Fatalf("username not escaped: %s", got)
	}
	g := GroupFilter(defaultGroupFilter, "uid=a*,dc=x", "a)")
	if strings.Contains(g, "a*,") || !strings.Contains(g, `a\29`) {
		t.Fatalf("group filter not escaped: %s", g)
	}
}

func TestTransportPolicy(t *testing.T) {
	cases := []struct {
		url             string
		startTLS        bool
		ok, unencrypted bool
	}{
		{"ldaps://dc.example.com", false, true, false},
		{"ldap://127.0.0.1:389", false, true, false},
		{"ldap://localhost", false, true, false},
		{"ldap://192.168.1.10:389", false, true, true}, // plain LAN directory: allowed
		{"ldap://dc.example.com", true, true, false},
		{"http://dc.example.com", false, false, false},
		{"not a url", false, false, false},
	}
	for _, c := range cases {
		cfg := &Config{URL: c.url, StartTLS: c.startTLS}
		if err := cfg.transportOK(); (err == nil) != c.ok {
			t.Errorf("%s starttls=%v: got err=%v want ok=%v", c.url, c.startTLS, err, c.ok)
		}
		if c.ok && cfg.Unencrypted() != c.unencrypted {
			t.Errorf("%s starttls=%v: Unencrypted()=%v want %v", c.url, c.startTLS, cfg.Unencrypted(), c.unencrypted)
		}
	}
}

func TestLoadConfigDefaultsAndGating(t *testing.T) {
	t.Setenv("LDAP_URL", "")
	t.Setenv("LDAP_BASE_DN", "")
	if LoadConfig() != nil {
		t.Fatal("unset LDAP_URL must disable LDAP")
	}
	t.Setenv("LDAP_URL", "ldaps://dc.example.com")
	t.Setenv("LDAP_BASE_DN", "dc=example,dc=com")
	c := LoadConfig()
	if c == nil {
		t.Fatal("expected config")
	}
	if c.UserFilter != defaultUserFilter || c.EmailAttr != "mail" || c.NameAttr != "displayName" || c.Label != "Directory" || c.Timeout != 10*time.Second {
		t.Fatalf("defaults wrong: %+v", c)
	}
	t.Setenv("LDAP_USER_FILTER", "(uid=alice)")
	if LoadConfig() != nil {
		t.Fatal("a filter without {username} must disable LDAP")
	}
	t.Setenv("LDAP_USER_FILTER", "")
	t.Setenv("LDAP_URL", "ldap://192.168.1.10:389")
	if LoadConfig() == nil {
		t.Fatal("plain ldap:// to a LAN directory must be allowed")
	}
}

func TestEmptyPasswordNeverReachesServer(t *testing.T) {
	s := NewServiceWithConfig(&Config{URL: "ldap://127.0.0.1:1", BaseDN: "dc=x", Timeout: time.Second})
	dialed := false
	s.dial = func(context.Context) (conn, error) { dialed = true; return nil, errors.New("no") }
	for _, tc := range [][2]string{{"alice", ""}, {"", "pw"}, {"   ", "pw"}, {strings.Repeat("a", 300), "pw"}} {
		if _, err := s.Authenticate(context.Background(), tc[0], tc[1]); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("%q/%q: want ErrInvalidCredentials, got %v", tc[0], tc[1], err)
		}
	}
	if dialed {
		t.Fatal("an empty password must be refused before connecting (unauthenticated bind)")
	}
}

func TestUnreachableServerIsUnavailable(t *testing.T) {
	s := NewServiceWithConfig(&Config{URL: "ldap://127.0.0.1:1", BaseDN: "dc=x", UserFilter: defaultUserFilter, EmailAttr: "mail", NameAttr: "cn", Timeout: time.Second})
	if _, err := s.Authenticate(context.Background(), "alice", "pw"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

func TestNotConfigured(t *testing.T) {
	var s *Service
	if s.Configured() {
		t.Fatal("nil service must not be configured")
	}
	if _, err := NewServiceWithConfig(nil).Authenticate(context.Background(), "a", "b"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("want ErrNotConfigured, got %v", err)
	}
}

// Integration tests against a real directory. Set LDAP_TEST_URL (for example
// ldap://127.0.0.1:3389) seeded with the fixture in docs (see
// docs/ldap.md, "Testing against a local OpenLDAP"); skipped otherwise.
func liveService(t *testing.T, mutate func(*Config)) *Service {
	t.Helper()
	u := os.Getenv("LDAP_TEST_URL")
	if u == "" {
		t.Skip("LDAP_TEST_URL not set; skipping live directory test")
	}
	cfg := &Config{
		URL: u, BaseDN: "ou=people,dc=ego,dc=test",
		BindDN: "cn=svc,ou=service,dc=ego,dc=test", BindPassword: "svcpw",
		UserFilter: defaultUserFilter, GroupFilter: defaultGroupFilter,
		EmailAttr: "mail", NameAttr: "displayName", Timeout: 5 * time.Second, Label: "E-Go",
	}
	if mutate != nil {
		mutate(cfg)
	}
	return NewServiceWithConfig(cfg)
}

func TestLiveAuthenticate(t *testing.T) {
	s := liveService(t, nil)
	ctx := context.Background()

	p, err := s.Authenticate(ctx, "alice", "alicepw")
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	if p.Email != "alice@ego.test" || p.Name != "Alice Chan" || !strings.HasPrefix(p.Subject, "entryuuid:") {
		t.Fatalf("profile wrong: %+v", p)
	}
	// Sign in by email too (default filter matches uid OR mail).
	p2, err := s.Authenticate(ctx, "alice@ego.test", "alicepw")
	if err != nil || p2.Subject != p.Subject {
		t.Fatalf("email login: %v %+v", err, p2)
	}
	// No displayName: falls back to cn.
	if b, err := s.Authenticate(ctx, "bob", "bobpw"); err != nil || b.Name != "Bob Lee" {
		t.Fatalf("bob: %v %+v", err, b)
	}
	if _, err := s.Authenticate(ctx, "alice", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := s.Authenticate(ctx, "nobody", "x"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user: %v", err)
	}
	if _, err := s.Authenticate(ctx, "*", "alicepw"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wildcard username must not match: %v", err)
	}
	if _, err := s.Authenticate(ctx, "nomail", "nomailpw"); !errors.Is(err, ErrNoEmail) {
		t.Fatalf("no email: %v", err)
	}
}

func TestLiveGroupGate(t *testing.T) {
	s := liveService(t, func(c *Config) { c.RequiredGroupDN = "cn=hycanvas-users,ou=groups,dc=ego,dc=test" })
	ctx := context.Background()
	if _, err := s.Authenticate(ctx, "alice", "alicepw"); err != nil {
		t.Fatalf("alice is in the group: %v", err)
	}
	if _, err := s.Authenticate(ctx, "bob", "bobpw"); !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("bob is not in the group: %v", err)
	}
	// A wrong password is still a credentials error, checked before the group.
	if _, err := s.Authenticate(ctx, "bob", "nope"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("bob wrong password: %v", err)
	}
}

func TestLiveBadServiceAccount(t *testing.T) {
	s := liveService(t, func(c *Config) { c.BindPassword = "wrong" })
	if _, err := s.Authenticate(context.Background(), "alice", "alicepw"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("misconfigured service account must be an outage, not bad credentials: %v", err)
	}
}

func TestLiveAmbiguousMatchRefused(t *testing.T) {
	// A filter that matches every person must never pick one at random.
	s := liveService(t, func(c *Config) { c.UserFilter = "(|(uid={username})(objectClass=inetOrgPerson))" })
	if _, err := s.Authenticate(context.Background(), "alice", "alicepw"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("ambiguous match: %v", err)
	}
}
