# Group/Role-Based Password Policy Extension

This Keycloak extension adds a custom password policy provider named `group-password-policy`.

It lets you configure different password rules per **user group** or **realm role** inside the same realm.

## Key Syntax

Keys in the configuration identify which users a policy applies to:

| Key format          | Matches                                          |
|---------------------|--------------------------------------------------|
| `group:<path>`      | Users in that group or any child group           |
| `role:<roleName>`   | Users with that realm role                       |
| `*`                 | Fallback — all users not matched by a group/role |

**Priority:** Role > Group > Wildcard (`*`).
If a user matches any role entry, that tier is used and groups are ignored entirely.
If no role matches, group entries are evaluated. The wildcard applies only when nothing else matches.

Within a tier, the entry with the **most fields set** wins. If two entries have the same number of fields, the one with the **highest sum of `min*` values** wins.

## Rule Format

Preferred (JSON):

```json
{
  "*":              { "minLength": 8, "minDigits": 1, "minLowerCase": 1, "minUpperCase": 1, "minSpecialChars": 1, "notUsername": true, "notEmail": true, "notRecentlyUsed": 12, "expireDays": 90 },
  "group:customers": { "minLength": 12, "minDigits": 1 },
  "group:backoffice": { "minLength": 14, "minDigits": 1, "minUpperCase": 1, "minLowerCase": 1, "minSpecialChars": 1, "expireDays": 30 },
  "role:admin":      { "minLength": 16, "minDigits": 2, "minUpperCase": 1, "minLowerCase": 1, "minSpecialChars": 2, "notUsername": true, "notEmail": true, "notRecentlyUsed": 12, "expireDays": 14 }
}
```

Legacy format (semicolon-separated) is still supported:

```
*=minLength:8,minDigits:1,minLowerCase:1,minUpperCase:1,minSpecialChars:1,notUsername:true,notEmail:true,notRecentlyUsed:12,expireDays:90;
group:customers=minLength:12,minDigits:1;
group:backoffice=minLength:14,minDigits:1,minUpperCase:1,minLowerCase:1,minSpecialChars:1,expireDays:30;
role:admin=minLength:16,minDigits:2,minUpperCase:1,minLowerCase:1,minSpecialChars:2,notUsername:true,notEmail:true,notRecentlyUsed:12,expireDays:14
```

## Supported Rules

| Rule                                    | Description                                                      |
|-----------------------------------------|------------------------------------------------------------------|
| `minLength`                             | Minimum password length (must be > 0)                            |
| `maxLength`                             | Maximum password length (must be > 0)                            |
| `minLowerCase` / `minLowerCaseChars`    | Minimum lowercase letters                                        |
| `minUpperCase` / `minUpperCaseChars`    | Minimum uppercase letters                                        |
| `minDigits`                             | Minimum digit characters                                         |
| `minSpecialChars`                       | Minimum non-alphanumeric characters                              |
| `notUsername`                           | `true` — password must not equal the username (case-insensitive) |
| `notEmail`                              | `true` — password must not equal the user's email (case-insensitive) |
| `notRecentlyUsed`                       | Password must not match any of the last N stored passwords       |
| `regex`                                 | Java regex the password must fully match                         |
| `expireDays`                            | Max password age in days (requires the required action below)    |

## Matching Behaviour

- A `group:<path>` rule matches when the user belongs to that exact group **or any child group** of it.
- A `role:<name>` rule matches when the user has that realm role assigned.
- If any role entries match, the **role tier is used exclusively** — group and wildcard entries are ignored.
- If no role matches but group entries match, the **group tier is used**.
- Within a tier, the entry with the most fields configured wins. On a tie, the entry with the highest sum of `min*` values wins.
- If nothing matches, the `*` fallback is applied (if configured).

## Quick Start (Docker)

The repo ships a `Dockerfile` and `docker-compose.yml` that build the extension and start Keycloak with it pre-loaded — no manual JAR copy needed.

```bash
docker compose up --build
```

Keycloak starts on `http://localhost:8080`. Log in with `admin` / `admin`.

To add the policy:

1. Open **Realm Settings → Authentication → Password Policy**.
2. Add policy **Group/Role-based password policy**.
3. Edit the JSON config to define your group/role rules.
4. To enable password expiry, go to **Authentication → Required Actions** and enable **Group password expiration check**.

## Manual Build & Install

```bash
mvn clean package
```

Copy the generated JAR into your Keycloak `providers/` directory and restart:

```bash
cp target/group-password-policy-*.jar /path/to/keycloak/providers/
```
