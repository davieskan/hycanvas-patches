package httpapi

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"hycanvas/backend/internal/accounts"
	"hycanvas/backend/internal/captcha"
	"hycanvas/backend/internal/ldapauth"
	"hycanvas/backend/internal/platform/config"
)

// Throttles for directory sign-in. Every attempt is a bind against the
// customer's directory, and directories commonly lock an account after a few
// failures (Active Directory's lockout policy), so an unthrottled endpoint
// would let anyone on the internet lock real employees out. Two budgets: per
// client address (stops one host spraying many usernames) and per username
// (stops a botnet hammering one person). Sized so a human retyping a password
// never notices.
const (
	ldapIPRatePerSec   = 1.0 / 6 // 10 per minute sustained
	ldapIPBurst        = 20.0
	ldapUserRatePerSec = 1.0 / 12 // 5 per minute sustained
	ldapUserBurst      = 5.0
)

// mountLDAP attaches POST /auth/ldap/login. The route always exists; when LDAP
// is not configured or AUTH_LDAP_* turns it off it answers 403 with
// signin_method_disabled, like the other gated auth routes.
func mountLDAP(api chi.Router, svc *ldapauth.Service, acct *accounts.Service, secure bool, policy config.AuthPolicy, cap captcha.Verifier) {
	on := svc.Configured() && (policy.LdapLogin || policy.LdapSignup)
	h := ldapLoginHandler(svc, acct, secure, policy)
	if cap != nil {
		next := h
		h = func(w http.ResponseWriter, r *http.Request) {
			if err := cap.Verify(r.Context(), r.Header.Get("X-Captcha-Token"), clientIP(r)); err != nil {
				problemWithCode(w, r, http.StatusForbidden, "Forbidden", "captcha verification failed; please try again", "captcha_failed")
				return
			}
			next(w, r)
		}
	}
	if !on {
		h = func(w http.ResponseWriter, r *http.Request) {
			problemWithCode(w, r, http.StatusForbidden, "Forbidden", "this sign-in method is disabled on this instance", "signin_method_disabled")
		}
	}
	api.Post("/auth/ldap/login", h)
}

func ldapClientHost(r *http.Request) string {
	host := clientIP(r)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}

func ldapLoginHandler(svc *ldapauth.Service, acct *accounts.Service, secure bool, policy config.AuthPolicy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil ||
			strings.TrimSpace(body.Username) == "" || body.Password == "" {
			problemWithCode(w, r, http.StatusBadRequest, "Bad Request", "username and password are required", "username_and_password_are_required")
			return
		}
		now := time.Now()
		userKey := "ldap-u\x1f" + strings.ToLower(strings.TrimSpace(body.Username))
		if !allowAudience("ldap-ip\x1f"+ldapClientHost(r), now, ldapIPRatePerSec, ldapIPBurst) ||
			!allowAudience(userKey, now, ldapUserRatePerSec, ldapUserBurst) {
			w.Header().Set("Retry-After", "30")
			problemWithCode(w, r, http.StatusTooManyRequests, "Too Many Requests", "too many sign-in attempts; wait a moment and try again", "ldap_rate_limited")
			return
		}

		profile, err := svc.Authenticate(r.Context(), body.Username, body.Password)
		if err != nil {
			switch {
			case errors.Is(err, ldapauth.ErrInvalidCredentials):
				problemWithCode(w, r, http.StatusUnauthorized, "Unauthorized", "invalid username or password", "invalid_username_or_password")
			case errors.Is(err, ldapauth.ErrNotPermitted):
				problemWithCode(w, r, http.StatusForbidden, "Forbidden", "your directory account is not permitted to use this application", "ldap_not_permitted")
			case errors.Is(err, ldapauth.ErrNoEmail):
				problemWithCode(w, r, http.StatusForbidden, "Forbidden", "your directory account has no email address; ask your administrator to add one", "ldap_no_email")
			case errors.Is(err, ldapauth.ErrNotConfigured):
				problemWithCode(w, r, http.StatusForbidden, "Forbidden", "this sign-in method is disabled on this instance", "signin_method_disabled")
			default:
				problemWithCode(w, r, http.StatusServiceUnavailable, "Service Unavailable", "the directory server could not be reached; try again shortly", "ldap_unavailable")
			}
			return
		}

		user, tokens, mfaToken, err := acct.LoginWithLdap(r.Context(), accounts.LdapProfile{
			Subject: profile.Subject, Email: profile.Email, Name: profile.Name,
		}, r.UserAgent(), clientIP(r), policy.LdapLogin, policy.LdapSignup)
		if err != nil {
			switch {
			case errors.Is(err, accounts.ErrMFARequired):
				writeJSON(w, http.StatusOK, map[string]any{"mfaRequired": true, "mfaToken": mfaToken})
			case errors.Is(err, accounts.ErrLdapLinkRefused):
				problemWithCode(w, r, http.StatusConflict, "Conflict", err.Error(), "ldap_account_exists")
			case errors.Is(err, accounts.ErrLdapDomainNotAllowed):
				problemWithCode(w, r, http.StatusForbidden, "Forbidden", err.Error(), "ldap_domain_not_allowed")
			case errors.Is(err, accounts.ErrLdapLoginDisabled):
				problemWithCode(w, r, http.StatusForbidden, "Forbidden", err.Error(), "ldap_login_disabled")
			case errors.Is(err, accounts.ErrLdapSignupDisabled):
				problemWithCode(w, r, http.StatusForbidden, "Forbidden", err.Error(), "ldap_signup_disabled")
			default:
				problemWithCode(w, r, http.StatusInternalServerError, "Internal Server Error", "sign-in is temporarily unavailable", "internal_error")
			}
			return
		}
		setAuthCookies(w, tokens.Access, tokens.Refresh, secure)
		writeJSON(w, http.StatusOK, map[string]any{"user": user})
	}
}
