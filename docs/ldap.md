# LDAP directory sign-in

HyCanvas can sign people in with their company directory account: Active
Directory, OpenLDAP, FreeIPA, Samba AD, 389 Directory Server, or anything else
that speaks LDAP. When it is configured, the sign-in page shows a
**Sign in with <LDAP_LABEL>** button. The user types their directory username
(or email) and directory password. HyCanvas checks them against the directory
and signs them in. The first time someone signs in, HyCanvas creates their
account and a personal workspace for them.

Nothing changes until `LDAP_URL` and `LDAP_BASE_DN` are set.

## How it works

HyCanvas uses the standard search-then-bind flow:

1. Connect to `LDAP_URL` (plain `ldap://`, `ldaps://`, or StartTLS) and bind as the service
   account `LDAP_BIND_DN` (or stay anonymous when it is empty).
2. Search under `LDAP_BASE_DN` with `LDAP_USER_FILTER`, with the typed
   username escaped into `{username}`. Exactly one entry must match.
3. Bind as that entry with the typed password. This is the actual password
   check, done by your directory, so its password policy, lockout, and
   disabled-account rules all apply.
4. If `LDAP_REQUIRED_GROUP_DN` is set, check that the user is a member.
5. Read the email (`LDAP_EMAIL_ATTR`), display name (`LDAP_NAME_ATTR`), and a
   stable id (`entryUUID` / `objectGUID` / ...), then sign in.

HyCanvas never stores the directory password.

## Quick start

### Active Directory

```env
LDAP_URL="ldaps://dc01.corp.example.com:636"
LDAP_BASE_DN="OU=Staff,DC=corp,DC=example,DC=com"
LDAP_BIND_DN="CN=svc-hycanvas,OU=Service Accounts,DC=corp,DC=example,DC=com"
LDAP_BIND_PASSWORD="..."
LDAP_USER_FILTER="(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(sAMAccountName={username})(userPrincipalName={username})(mail={username})))"
LDAP_LABEL="Company"
# Optional: only members of this group (nested groups included) may sign in.
LDAP_REQUIRED_GROUP_DN="CN=HyCanvas Users,OU=Groups,DC=corp,DC=example,DC=com"
LDAP_GROUP_FILTER="(member:1.2.840.113556.1.4.1941:={dn})"
```

The `userAccountControl` clause skips disabled accounts in the search. The
`1.2.840.113556.1.4.1941` matching rule makes the group check follow nested
groups.

### OpenLDAP / FreeIPA

```env
LDAP_URL="ldap://192.168.1.10:389"   # plain LDAP on the local network
# LDAP_START_TLS="true"              # optional: encrypt with StartTLS
LDAP_BASE_DN="ou=people,dc=example,dc=com"
LDAP_BIND_DN="cn=hycanvas,ou=service,dc=example,dc=com"
LDAP_BIND_PASSWORD="..."
# The default filter matches uid or mail:
# LDAP_USER_FILTER="(|(uid={username})(mail={username}))"
LDAP_REQUIRED_GROUP_DN="cn=hycanvas-users,ou=groups,dc=example,dc=com"
```

FreeIPA users live under `cn=users,cn=accounts,dc=...`.

## All settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `LDAP_URL` | (unset, off) | `ldaps://host:636` or `ldap://host:389` |
| `LDAP_BASE_DN` | (unset, off) | Where to search for users |
| `LDAP_BIND_DN` / `LDAP_BIND_PASSWORD` | anonymous | Service account for the search |
| `LDAP_USER_FILTER` | `(\|(uid={username})(mail={username}))` | Must contain `{username}` |
| `LDAP_EMAIL_ATTR` | `mail` | Attribute holding the email (required on every user) |
| `LDAP_NAME_ATTR` | `displayName` | Display name; falls back to `cn` |
| `LDAP_ID_ATTR` | auto | Stable id; auto tries `entryUUID`, `objectGUID`, `ipaUniqueID`, `GUID`, `nsUniqueId`, then the DN |
| `LDAP_REQUIRED_GROUP_DN` | (none) | Only members may sign in |
| `LDAP_GROUP_FILTER` | `(\|(member={dn})(uniqueMember={dn})(memberUid={username}))` | Evaluated on the group entry; `{dn}` is the user's DN |
| `LDAP_START_TLS` | `false` | Upgrade an `ldap://` connection with StartTLS |
| `LDAP_CA_CERT_FILE` | system roots | PEM file with your internal CA |
| `LDAP_TLS_INSECURE_SKIP_VERIFY` | `false` | Skip certificate checks (lab only) |
| `LDAP_TIMEOUT` | `10s` | Connect and request timeout |
| `LDAP_LABEL` | `Directory` | Button text: "Sign in with <label>" |
| `LDAP_ALLOWED_EMAIL_DOMAINS` | (none) | See "Existing accounts" |
| `AUTH_LDAP_LOGIN_ENABLED` | `true` | Allow directory sign-in |
| `AUTH_LDAP_SIGNUP_ENABLED` | `true` | Let a first directory sign-in create the account |

To make the directory the only way in, also set
`AUTH_PASSWORD_LOGIN_ENABLED`, `AUTH_PASSWORD_SIGNUP_ENABLED` and
`AUTH_MAGICLINK_LOGIN_ENABLED` to `"false"`. The sign-in page then opens
straight on the directory form.

## Security behaviour

- **Plain `ldap://` is allowed**, which suits a directory on your local network.
  Directory passwords then cross the network unencrypted, and the server logs a
  startup warning to say so. For encryption, use `ldaps://` or
  `LDAP_START_TLS=true`.
- **Blank passwords are refused** before contacting the directory. LDAP treats
  a bind with no password as an "unauthenticated bind", which many servers
  accept, so a blank password must never be passed through.
- **No filter injection.** The typed username is escaped, so `*` or `)(` cannot
  widen the search. A search that matches more than one entry is refused.
- **No username enumeration.** Unknown user and wrong password return the same
  "Invalid username or password".
- **Throttled.** At most 5 attempts per minute per username (burst 5) and 10 per
  minute per client address (burst 20). This keeps a guessing attack from
  tripping your Active Directory lockout policy for real employees.
- **Two-step verification still applies.** If the HyCanvas account has an
  authenticator app enabled, a correct directory password is followed by the
  usual code prompt.
- **CAPTCHA** (if configured) also protects the directory form.

## Existing accounts

Directory identities are linked by the entry's stable id, so renaming a user's
email in the directory does not create a second HyCanvas account.

On a first directory sign-in, if a HyCanvas account with the same email
already exists:

- If that account has no password (created via SSO or a magic link), the
  directory identity is linked to it.
- If it has a password, HyCanvas refuses to link it, so that whoever controls
  the directory cannot take over a local account by giving an entry a matching
  email. Set `LDAP_ALLOWED_EMAIL_DOMAINS="yourcompany.com"` to say the directory
  is authoritative for that domain. Linking is then allowed, and the account
  keeps its password as well.

Disabling a user in the directory stops new directory sign-ins straight away.
Sessions already open keep working until they expire, so for an urgent removal
also remove the user's sessions in HyCanvas.

## Troubleshooting

The server logs every failure with an `ldap:` prefix.

| Sign-in page says | Log says | Fix |
| --- | --- | --- |
| Button missing | `ldap: LDAP sign-in disabled` | Read the `reason`: a malformed `LDAP_URL` or a filter without `{username}` |
| "directory server can't be reached" | `ldap: connect failed` | Host, port, firewall, or certificate (`LDAP_CA_CERT_FILE`) |
| "directory server can't be reached" | `service account bind failed` | Wrong `LDAP_BIND_DN` / `LDAP_BIND_PASSWORD` |
| "Invalid username or password" | `matched more than one directory entry` | Tighten `LDAP_USER_FILTER` |
| "isn't allowed to use this app" | (none) | User is not in `LDAP_REQUIRED_GROUP_DN` |
| "has no email address" | (none) | Fill in the user's `mail` (or `LDAP_EMAIL_ATTR`) |

Test the same search from the server host with `ldapsearch`:

```sh
ldapsearch -H "$LDAP_URL" -ZZ -D "$LDAP_BIND_DN" -w "$LDAP_BIND_PASSWORD" \
  -b "$LDAP_BASE_DN" "(uid=alice)" mail displayName entryUUID
```

(Drop `-ZZ` for `ldaps://`.)

## Testing against a local OpenLDAP

The Go tests include live directory tests that run when `LDAP_TEST_URL` is set
(and the end-to-end HTTP test when `DATABASE_URL` is also set). They expect the
fixture in `backend/internal/ldapauth/testdata/fixture.ldif`: suffix `dc=ego,dc=test`, service account
`cn=svc,ou=service,dc=ego,dc=test` / `svcpw`, users under
`ou=people,dc=ego,dc=test`:

| uid | password | mail | displayName | in `cn=hycanvas-users,ou=groups,dc=ego,dc=test` |
| --- | --- | --- | --- | --- |
| alice | alicepw | alice@ego.test | Alice Chan | yes |
| bob | bobpw | bob@ego.test | (none; cn "Bob Lee") | no |
| nomail | nomailpw | (none) | | no |

```sh
cd backend
LDAP_TEST_URL=ldap://127.0.0.1:3389 DATABASE_URL=postgres://... \
  go test ./internal/ldapauth/ ./internal/accounts/ ./internal/httpapi/ -run 'Ldap|Live'
```
