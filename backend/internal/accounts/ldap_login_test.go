package accounts

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestDomainInList(t *testing.T) {
	if ok, conf := domainInList("a@x.com", ""); !ok || conf {
		t.Fatal("empty list: allowed, not configured")
	}
	if ok, conf := domainInList("a@X.com", "y.com, x.com"); !ok || !conf {
		t.Fatal("listed domain must match case-insensitively")
	}
	if ok, conf := domainInList("a@z.com", "y.com,x.com"); ok || !conf {
		t.Fatal("unlisted domain must be refused")
	}
}

func TestLoginWithLdap_DB(t *testing.T) {
	ctx, svc, done := txService(t)
	defer done()

	sub := "entryuuid:" + uuid.NewString()
	email := "ldap+" + uuid.NewString() + "@example.com"

	// 1) First directory sign-in provisions a passwordless, verified account
	// with a personal workspace and an LDAP identity.
	u1, tok1, mfa1, err := svc.LoginWithLdap(ctx, LdapProfile{Subject: sub, Email: email, Name: "Dir User"}, "d", "ip", true, true)
	if err != nil || u1 == nil || tok1 == nil || tok1.Access == "" || mfa1 != "" {
		t.Fatalf("new-account LDAP login: %v", err)
	}
	row, _ := svc.findUserByID(ctx, u1.ID)
	if row.PasswordHash != nil || !row.EmailVerified || row.Name != "Dir User" {
		t.Fatalf("provisioned user wrong: %+v", row)
	}
	var ws int
	_ = svc.db.QueryRow(ctx, `SELECT count(*) FROM "workspace_members" WHERE "user_id"=$1 AND role='OWNER'`, u1.ID).Scan(&ws)
	if ws != 1 {
		t.Fatalf("want one owner workspace, got %d", ws)
	}
	if has, _ := svc.HasLdapIdentity(ctx, u1.ID); !has {
		t.Fatal("LDAP identity missing")
	}

	// 2) Returning entry reuses the account even if the directory email changed.
	u2, _, _, err := svc.LoginWithLdap(ctx, LdapProfile{Subject: sub, Email: "renamed+" + uuid.NewString() + "@example.com"}, "d", "ip", true, true)
	if err != nil || u2.ID != u1.ID {
		t.Fatalf("returning LDAP login should reuse the user: %v", err)
	}

	// 3) Login toggle off: a known identity is refused.
	if _, _, _, err := svc.LoginWithLdap(ctx, LdapProfile{Subject: sub, Email: email}, "d", "ip", false, true); err != ErrLdapLoginDisabled {
		t.Fatalf("want ErrLdapLoginDisabled, got %v", err)
	}
	// 4) Signup toggle off: an unknown entry is not provisioned.
	if _, _, _, err := svc.LoginWithLdap(ctx, LdapProfile{Subject: "entryuuid:" + uuid.NewString(), Email: "new+" + uuid.NewString() + "@example.com"}, "d", "ip", true, false); err != ErrLdapSignupDisabled {
		t.Fatalf("want ErrLdapSignupDisabled, got %v", err)
	}

	// 5) A password account with the same email is NOT silently taken over...
	pwEmail := "pw+" + uuid.NewString() + "@example.com"
	pwUser, _, _, err := svc.Signup(ctx, pwEmail, "a-strong-password", "PW User")
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	linkSub := "entryuuid:" + uuid.NewString()
	if _, _, _, err := svc.LoginWithLdap(ctx, LdapProfile{Subject: linkSub, Email: pwEmail}, "d", "ip", true, true); err != ErrLdapLinkRefused {
		t.Fatalf("want ErrLdapLinkRefused, got %v", err)
	}
	// ...unless the operator vouches for the directory's domain.
	t.Setenv("LDAP_ALLOWED_EMAIL_DOMAINS", "example.com")
	linked, ltok, _, err := svc.LoginWithLdap(ctx, LdapProfile{Subject: linkSub, Email: strings.ToUpper(pwEmail)}, "d", "ip", true, true)
	if err != nil || linked.ID != pwUser.ID || ltok == nil {
		t.Fatalf("allowlisted domain should link to the existing account: %v", err)
	}
	// The password still works after linking.
	if _, _, _, err := svc.Login(ctx, pwEmail, "a-strong-password", "d", "ip"); err != nil {
		t.Fatalf("password login after link: %v", err)
	}

	// 6) Domain outside the allowlist is refused.
	if _, _, _, err := svc.LoginWithLdap(ctx, LdapProfile{Subject: "entryuuid:" + uuid.NewString(), Email: "x@other.com"}, "d", "ip", true, true); err != ErrLdapDomainNotAllowed {
		t.Fatalf("want ErrLdapDomainNotAllowed, got %v", err)
	}
	// 7) Missing email / subject.
	if _, _, _, err := svc.LoginWithLdap(ctx, LdapProfile{Subject: "entryuuid:" + uuid.NewString()}, "d", "ip", true, true); err != ErrLdapNoEmail {
		t.Fatalf("want ErrLdapNoEmail, got %v", err)
	}
	if _, _, _, err := svc.LoginWithLdap(ctx, LdapProfile{Email: email}, "d", "ip", true, true); err != ErrLdapNoAccount {
		t.Fatalf("want ErrLdapNoAccount, got %v", err)
	}

	// 8) Directory sign-in into an MFA account returns the MFA challenge.
	if _, err := svc.db.Exec(ctx, `UPDATE "users" SET "mfa_enabled"=true WHERE id=$1`, pwUser.ID); err != nil {
		t.Fatalf("enable mfa: %v", err)
	}
	mu, mt, tok, err := svc.LoginWithLdap(ctx, LdapProfile{Subject: linkSub, Email: pwEmail}, "d", "ip", true, true)
	if err != ErrMFARequired || tok == "" || mt != nil || mu != nil {
		t.Fatalf("LDAP into an MFA account must challenge, got %v %v %q %v", mu, mt, tok, err)
	}

	// 9) An LDAP identity and an OIDC identity with the same subject string are
	// different identities (provider is part of the key).
	if _, _, _, err := svc.LoginWithOidc(ctx, OidcProfile{Subject: sub, Email: "oidc+" + uuid.NewString() + "@example.com", EmailVerified: true}, "d", "ip", true, true); err != nil {
		t.Fatalf("OIDC with an LDAP-looking subject: %v", err)
	}
}
