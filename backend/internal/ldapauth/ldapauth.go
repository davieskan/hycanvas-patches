// Package ldapauth signs a user in against an LDAP directory (OpenLDAP, Active
// Directory, FreeIPA, Samba, ...) configured via env (LDAP_URL / LDAP_BASE_DN,
// optionally a service account LDAP_BIND_DN / LDAP_BIND_PASSWORD). It uses the
// standard search-then-bind flow: find the user's entry with the service
// account, then bind as that entry with the password the user typed. Account
// linking and session issuance live in internal/accounts (LoginWithLdap).
//
// Security posture:
//   - An empty password is refused before any network call. LDAP treats a bind
//     with a DN and no password as an "unauthenticated bind" that many servers
//     answer with success, which would let anyone in with a blank password.
//   - The typed username is escaped before it is placed in the search filter, so
//     it cannot widen the filter (LDAP injection).
//   - Plain ldap:// is allowed (typical for a directory on a private LAN). It
//     sends passwords unencrypted, so a startup warning says so; ldaps:// or
//     LDAP_START_TLS=true encrypt the connection when wanted.
//   - Unknown user, wrong password, and a search that matches several entries
//     all return ErrInvalidCredentials, so the endpoint does not reveal which
//     usernames exist.
package ldapauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Errors map to 401 / 403 / 503 at the HTTP layer.
var (
	ErrNotConfigured      = errors.New("LDAP is not configured")
	ErrInvalidCredentials = errors.New("invalid directory username or password")
	ErrNotPermitted       = errors.New("this directory account is not permitted to sign in")
	ErrNoEmail            = errors.New("the directory entry has no email address")
	ErrUnavailable        = errors.New("the directory server is unavailable")
)

// maxUsernameLen bounds the typed username; directory names are far shorter and
// a bound keeps a hostile request from building a huge filter.
const maxUsernameLen = 256

// Profile is the resolved identity from the user's directory entry.
type Profile struct {
	// Subject is the stable, server-assigned id of the entry (entryUUID,
	// objectGUID, ipaUniqueID, ...), or the lowercased DN when none is found.
	// It is what auth_identities.provider_subject stores.
	Subject  string
	DN       string
	Username string
	Email    string
	Name     string
}

// Config is the env-derived LDAP configuration. Exported so tests and the
// startup log can inspect it; the bind password is never logged.
type Config struct {
	URL                string
	BaseDN             string
	BindDN             string
	BindPassword       string
	UserFilter         string
	EmailAttr          string
	NameAttr           string
	IDAttr             string
	RequiredGroupDN    string
	GroupFilter        string
	StartTLS           bool
	InsecureSkipVerify bool
	CACertFile         string
	Timeout            time.Duration
	Label              string
}

const (
	defaultUserFilter  = "(|(uid={username})(mail={username}))"
	defaultGroupFilter = "(|(member={dn})(uniqueMember={dn})(memberUid={username}))"
)

// stableIDAttrs are tried in order when LDAP_ID_ATTR is unset: OpenLDAP and
// 389-DS (entryUUID), Active Directory and Samba (objectGUID), FreeIPA
// (ipaUniqueID), Novell/NetIQ eDirectory (GUID), Oracle/Sun (nsUniqueId).
var stableIDAttrs = []string{"entryUUID", "objectGUID", "ipaUniqueID", "GUID", "nsUniqueId"}

// LoadConfig reads the LDAP_* env. It returns nil when LDAP is not configured
// (LDAP_URL or LDAP_BASE_DN unset) or the URL is invalid; the reason is logged.
func LoadConfig() *Config {
	c := &Config{
		URL:                strings.TrimSpace(os.Getenv("LDAP_URL")),
		BaseDN:             strings.TrimSpace(os.Getenv("LDAP_BASE_DN")),
		BindDN:             strings.TrimSpace(os.Getenv("LDAP_BIND_DN")),
		BindPassword:       os.Getenv("LDAP_BIND_PASSWORD"),
		UserFilter:         strings.TrimSpace(os.Getenv("LDAP_USER_FILTER")),
		EmailAttr:          strings.TrimSpace(os.Getenv("LDAP_EMAIL_ATTR")),
		NameAttr:           strings.TrimSpace(os.Getenv("LDAP_NAME_ATTR")),
		IDAttr:             strings.TrimSpace(os.Getenv("LDAP_ID_ATTR")),
		RequiredGroupDN:    strings.TrimSpace(os.Getenv("LDAP_REQUIRED_GROUP_DN")),
		GroupFilter:        strings.TrimSpace(os.Getenv("LDAP_GROUP_FILTER")),
		StartTLS:           os.Getenv("LDAP_START_TLS") == "true",
		InsecureSkipVerify: os.Getenv("LDAP_TLS_INSECURE_SKIP_VERIFY") == "true",
		CACertFile:         strings.TrimSpace(os.Getenv("LDAP_CA_CERT_FILE")),
		Timeout:            10 * time.Second,
		Label:              strings.TrimSpace(os.Getenv("LDAP_LABEL")),
	}
	if c.URL == "" || c.BaseDN == "" {
		return nil
	}
	if d, err := time.ParseDuration(strings.TrimSpace(os.Getenv("LDAP_TIMEOUT"))); err == nil && d > 0 {
		c.Timeout = d
	}
	if c.UserFilter == "" {
		c.UserFilter = defaultUserFilter
	}
	if c.GroupFilter == "" {
		c.GroupFilter = defaultGroupFilter
	}
	if c.EmailAttr == "" {
		c.EmailAttr = "mail"
	}
	if c.NameAttr == "" {
		c.NameAttr = "displayName"
	}
	if c.Label == "" {
		c.Label = "Directory"
	}
	if !strings.Contains(c.UserFilter, "{username}") {
		slog.Warn("ldap: LDAP_USER_FILTER has no {username} placeholder; LDAP sign-in disabled")
		return nil
	}
	if err := c.transportOK(); err != nil {
		slog.Warn("ldap: LDAP sign-in disabled", "reason", err.Error(), "url", c.URL)
		return nil
	}
	if c.Unencrypted() {
		slog.Warn("ldap: connection is unencrypted (plain ldap:// without LDAP_START_TLS); directory passwords cross the network in clear text, so keep the directory on a trusted network", "url", c.URL)
	}
	return c
}

// Unencrypted reports a plain ldap:// connection to a non-localhost host
// without StartTLS. Allowed, but logged at startup.
func (c *Config) Unencrypted() bool {
	u, err := url.Parse(c.URL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, "ldap") && !c.StartTLS && !isLoopback(u.Hostname())
}

// transportOK validates LDAP_URL: an ldap:// or ldaps:// URL with a host.
func (c *Config) transportOK() error {
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("LDAP_URL is not a valid ldap:// or ldaps:// URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "ldap", "ldaps":
		return nil
	default:
		return fmt.Errorf("LDAP_URL scheme must be ldap or ldaps")
	}
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Service authenticates against the configured directory.
type Service struct {
	cfg *Config
	// dial opens a connection; replaced in tests.
	dial func(ctx context.Context) (conn, error)
}

// conn is the subset of *ldap.Conn the service uses, so tests can fake it.
type conn interface {
	Bind(username, password string) error
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

// NewService wires the service from env. A nil config (LDAP off) yields a
// service whose Configured() is false.
func NewService() *Service {
	return NewServiceWithConfig(LoadConfig())
}

// NewServiceWithConfig wires the service from an explicit config (tests).
func NewServiceWithConfig(cfg *Config) *Service {
	s := &Service{cfg: cfg}
	s.dial = s.dialLDAP
	return s
}

// Configured reports whether LDAP sign-in is set up.
func (s *Service) Configured() bool { return s != nil && s.cfg != nil }

// Label is the name the sign-in page shows for the directory (LDAP_LABEL).
func (s *Service) Label() string {
	if !s.Configured() {
		return ""
	}
	return s.cfg.Label
}

func (s *Service) tlsConfig(host string) (*tls.Config, error) {
	tc := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: s.cfg.InsecureSkipVerify} //nolint:gosec // operator opt-in for self-signed lab directories
	if s.cfg.CACertFile != "" {
		pem, err := os.ReadFile(s.cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("read LDAP_CA_CERT_FILE: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("LDAP_CA_CERT_FILE holds no PEM certificates")
		}
		tc.RootCAs = pool
	}
	return tc, nil
}

func (s *Service) dialLDAP(ctx context.Context) (conn, error) {
	u, err := url.Parse(s.cfg.URL)
	if err != nil {
		return nil, err
	}
	tc, err := s.tlsConfig(u.Hostname())
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: s.cfg.Timeout}
	c, err := ldap.DialURL(s.cfg.URL, ldap.DialWithDialer(d), ldap.DialWithTLSConfig(tc))
	if err != nil {
		return nil, err
	}
	c.SetTimeout(s.cfg.Timeout)
	if s.cfg.StartTLS && strings.EqualFold(u.Scheme, "ldap") {
		if err := c.StartTLS(tc); err != nil {
			_ = c.Close()
			return nil, err
		}
	}
	// Abort the connection if the request is cancelled mid-flight.
	go func() {
		<-ctx.Done()
		_ = c.Close()
	}()
	return c, nil
}

// Authenticate verifies username + password against the directory and returns
// the user's profile. Errors are one of the package sentinels.
func (s *Service) Authenticate(ctx context.Context, username, password string) (*Profile, error) {
	if !s.Configured() {
		return nil, ErrNotConfigured
	}
	username = strings.TrimSpace(username)
	if username == "" || password == "" || len(username) > maxUsernameLen {
		return nil, ErrInvalidCredentials
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout+2*time.Second)
	defer cancel()

	c, err := s.dial(ctx)
	if err != nil {
		slog.Warn("ldap: connect failed", "err", err.Error())
		return nil, ErrUnavailable
	}
	defer func() { _ = c.Close() }()

	// 1) Service bind (or stay anonymous when no service account is set).
	if s.cfg.BindDN != "" {
		if err := c.Bind(s.cfg.BindDN, s.cfg.BindPassword); err != nil {
			slog.Error("ldap: service account bind failed; check LDAP_BIND_DN / LDAP_BIND_PASSWORD", "err", err.Error())
			return nil, ErrUnavailable
		}
	}

	// 2) Find exactly one entry for the typed username.
	attrs := []string{"dn", s.cfg.EmailAttr, s.cfg.NameAttr, "cn"}
	if s.cfg.IDAttr != "" {
		attrs = append(attrs, s.cfg.IDAttr)
	} else {
		attrs = append(attrs, stableIDAttrs...)
	}
	res, err := c.Search(ldap.NewSearchRequest(
		s.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, int(s.cfg.Timeout/time.Second), false,
		UserFilter(s.cfg.UserFilter, username), attrs, nil,
	))
	if err != nil {
		// A size-limit error means more than one entry matched.
		if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
			slog.Warn("ldap: username matched more than one directory entry; refusing", "username", username)
			return nil, ErrInvalidCredentials
		}
		slog.Warn("ldap: user search failed", "err", err.Error())
		return nil, ErrUnavailable
	}
	if len(res.Entries) != 1 {
		if len(res.Entries) > 1 {
			slog.Warn("ldap: username matched more than one directory entry; refusing", "username", username)
		}
		return nil, ErrInvalidCredentials
	}
	entry := res.Entries[0]

	// 3) Prove the password by binding as the user.
	if err := c.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, ErrInvalidCredentials
		}
		slog.Warn("ldap: user bind failed", "err", err.Error())
		return nil, ErrInvalidCredentials
	}

	// 4) Optional group gate. Re-bind as the service account first when there is
	// one, since a regular user often cannot read group membership.
	if s.cfg.RequiredGroupDN != "" {
		if s.cfg.BindDN != "" {
			if err := c.Bind(s.cfg.BindDN, s.cfg.BindPassword); err != nil {
				return nil, ErrUnavailable
			}
		}
		gr, err := c.Search(ldap.NewSearchRequest(
			s.cfg.RequiredGroupDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			1, int(s.cfg.Timeout/time.Second), false,
			GroupFilter(s.cfg.GroupFilter, entry.DN, username), []string{"dn"}, nil,
		))
		if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			slog.Warn("ldap: group check failed", "err", err.Error())
			return nil, ErrUnavailable
		}
		if gr == nil || len(gr.Entries) == 0 {
			return nil, ErrNotPermitted
		}
	}

	p := &Profile{
		DN:       entry.DN,
		Username: username,
		Email:    strings.ToLower(strings.TrimSpace(entry.GetAttributeValue(s.cfg.EmailAttr))),
		Name:     strings.TrimSpace(entry.GetAttributeValue(s.cfg.NameAttr)),
		Subject:  s.subject(entry),
	}
	if p.Name == "" {
		p.Name = strings.TrimSpace(entry.GetAttributeValue("cn"))
	}
	if p.Email == "" {
		return nil, ErrNoEmail
	}
	return p, nil
}

// subject picks the entry's stable id. Binary ids (objectGUID) are hex encoded;
// the DN is the last resort, lowercased so case-only differences match.
func (s *Service) subject(e *ldap.Entry) string {
	names := stableIDAttrs
	if s.cfg.IDAttr != "" {
		names = []string{s.cfg.IDAttr}
	}
	for _, n := range names {
		raw := e.GetRawAttributeValue(n)
		if len(raw) == 0 {
			continue
		}
		if strings.EqualFold(n, "objectGUID") || !printable(raw) {
			return strings.ToLower(n) + ":" + hex.EncodeToString(raw)
		}
		return strings.ToLower(n) + ":" + strings.ToLower(string(raw))
	}
	return "dn:" + strings.ToLower(e.DN)
}

func printable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// UserFilter substitutes the escaped username into the configured filter.
func UserFilter(tmpl, username string) string {
	return strings.ReplaceAll(tmpl, "{username}", ldap.EscapeFilter(username))
}

// GroupFilter substitutes the escaped user DN and username into the group
// membership filter.
func GroupFilter(tmpl, dn, username string) string {
	f := strings.ReplaceAll(tmpl, "{dn}", ldap.EscapeFilter(dn))
	return strings.ReplaceAll(f, "{username}", ldap.EscapeFilter(username))
}
