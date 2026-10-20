// LDAP identity linking + session issuance. Mirrors the OIDC flow (see
// oidc_login.go): a returning directory identity signs in; an email match links
// the identity to an existing account under the same trust rules SSO uses;
// otherwise a new passwordless account + personal workspace is created.
//
// Security posture (same guarantees as SSO):
//   - LDAP never downgrades an account's auth assurance: an account with TOTP MFA
//     gets the same MFA challenge the password path returns.
//   - LDAP does not silently bind to a pre-existing password account on a bare
//     email match. That is allowed only when the operator vouches for the
//     directory's authority over the domain via LDAP_ALLOWED_EMAIL_DOMAINS.
package accounts

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// LdapProfile is the resolved identity from the directory entry.
type LdapProfile struct {
	// Subject is the entry's stable id (entryUUID / objectGUID / DN fallback).
	Subject string
	Email   string
	Name    string
}

var (
	ErrLdapNoAccount        = errOidc("account not found")
	ErrLdapNoEmail          = errOidc("the directory entry has no email address")
	ErrLdapLinkRefused      = errOidc("an account with this email already exists; sign in with your password, then ask an administrator to allow directory sign-in for your domain")
	ErrLdapDomainNotAllowed = errOidc("this email domain is not permitted for directory sign-in")
	ErrLdapLoginDisabled    = errOidc("directory sign-in is disabled on this instance")
	ErrLdapSignupDisabled   = errOidc("account creation via directory sign-in is disabled on this instance")
)

// ldapEmailDomainAllowed is emailDomainAllowed for LDAP_ALLOWED_EMAIL_DOMAINS.
func ldapEmailDomainAllowed(email string) (allowed, configured bool) {
	return domainInList(email, os.Getenv("LDAP_ALLOWED_EMAIL_DOMAINS"))
}

func domainInList(email, raw string) (allowed, configured bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return true, false
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false, true
	}
	domain := strings.ToLower(email[at+1:])
	for _, d := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if strings.ToLower(strings.TrimSpace(d)) == domain {
			return true, true
		}
	}
	return false, true
}

// LoginWithLdap links a directory profile to an account and issues a session
// (or an MFA challenge). Returns (user, tokens, mfaToken, err); on
// ErrMFARequired the caller drives the same VerifyMfaLogin step the password
// flow uses. allowLogin gates signing an existing/linked identity in;
// allowSignup gates provisioning a brand-new account (AUTH_LDAP_LOGIN_ENABLED /
// AUTH_LDAP_SIGNUP_ENABLED). The caller must have verified the password against
// the directory already (ldapauth.Service.Authenticate).
func (s *Service) LoginWithLdap(ctx context.Context, p LdapProfile, device, ip string, allowLogin, allowSignup bool) (*AuthUser, *Tokens, string, error) {
	if p.Subject == "" {
		return nil, nil, "", ErrLdapNoAccount
	}
	// 1) Returning directory user: an identity already exists for this entry.
	var existingUserID string
	err := s.db.QueryRow(ctx, `SELECT "user_id" FROM "auth_identities" WHERE provider = 'LDAP' AND "provider_subject" = $1`, p.Subject).Scan(&existingUserID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, "", err
	}
	if existingUserID != "" {
		if !allowLogin {
			return nil, nil, "", ErrLdapLoginDisabled
		}
		u, err := s.findUserByID(ctx, existingUserID)
		if err != nil || u == nil {
			return nil, nil, "", ErrLdapNoAccount
		}
		return s.finishOidcLogin(ctx, u, device, ip)
	}

	email := strings.ToLower(strings.TrimSpace(p.Email))
	if email == "" {
		return nil, nil, "", ErrLdapNoEmail
	}
	allowed, domainConfigured := ldapEmailDomainAllowed(email)
	if domainConfigured && !allowed {
		return nil, nil, "", ErrLdapDomainNotAllowed
	}

	// 2) Existing account with the same email: link the directory identity.
	u, err := s.findUserByEmail(ctx, email)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, "", err
	}
	if err == nil && u != nil {
		if !allowLogin {
			return nil, nil, "", ErrLdapLoginDisabled
		}
		// A password account is linked only when the operator vouched for the
		// directory's authority over this domain (LDAP_ALLOWED_EMAIL_DOMAINS).
		if u.PasswordHash != nil && !domainConfigured {
			return nil, nil, "", ErrLdapLinkRefused
		}
		if _, err := s.db.Exec(ctx,
			`INSERT INTO "auth_identities" (id,"user_id",provider,"provider_subject") VALUES ($1,$2,'LDAP',$3)
			 ON CONFLICT (provider,"provider_subject") DO NOTHING`,
			uuid.NewString(), u.ID, p.Subject); err != nil {
			return nil, nil, "", err
		}
		return s.finishOidcLogin(ctx, u, device, ip)
	}

	// 3) New account: user (no password) + LDAP identity + personal workspace,
	// in one transaction. The directory is operator-run, so its email counts as
	// verified.
	if !allowSignup {
		return nil, nil, "", ErrLdapSignupDisabled
	}
	userID, err := s.createUserWithWorkspace(ctx, email, p.Name, true, func(tx pgx.Tx, userID string) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO "auth_identities" (id,"user_id",provider,"provider_subject") VALUES ($1,$2,'LDAP',$3)`,
			uuid.NewString(), userID, p.Subject)
		return err
	})
	if err != nil {
		return nil, nil, "", err
	}
	nu, err := s.findUserByID(ctx, userID)
	if err != nil || nu == nil {
		return nil, nil, "", ErrLdapNoAccount
	}
	return s.finishOidcLogin(ctx, nu, device, ip)
}

// HasLdapIdentity reports whether the user has a linked directory identity.
func (s *Service) HasLdapIdentity(ctx context.Context, userID string) (bool, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM "auth_identities" WHERE "user_id"=$1 AND provider='LDAP'`, userID).Scan(&n)
	return n > 0, err
}
