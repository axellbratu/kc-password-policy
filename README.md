# Group-Based Password Policy Extension

This Keycloak extension adds a custom password policy provider named `group-password-policy`.

It lets you configure different password rules per user group inside the same realm.

## Rule Format

Preferred (JSON in the UI text area):

```
{
  "*": { "minLength": 10, "minDigits": 1 },
  "/endUser": { "minLength": 6, "maxLength": 6, "minDigits": 6, "regex": "^[0-9]{6}$", "expireDays": 90 },
  "/backoffice": { "minLength": 8, "minDigits": 1, "minSpecialChars": 1, "expireDays": 30 }
}
```

Legacy format is still supported:

```
/group/path=rule:value,rule:value; /other/group=rule:value
```

Supported rules:

- `minLength`
- `maxLength`
- `minLowerCase` (or `minLowerCaseChars`)
- `minUpperCase` (or `minUpperCaseChars`)
- `minDigits`
- `minSpecialChars`
- `notUsername` (`true` / `false`)
- `regex` (Java regex)
- `expireDays` (password age in days; requires enabling the custom required action)

Special group path:

- `*` acts as a fallback when no explicit group rule matches.

Matching behavior:

- A rule matches when the user belongs to the exact group path or one of its child groups.
- If multiple rules match, the most specific group path (longest path) is used.

Example:

```
*=minLength:10,minDigits:1;
/customers=minLength:12,minDigits:1,minLowerCase:1;
/backoffice=minLength:14,minDigits:1,minUpperCase:1,minLowerCase:1,minSpecialChars:1,notUsername:true,expireDays:30
```

## Build

```bash
cd extensions/group-password-policy
mvn clean package
```

The provider JAR is generated in:

`extensions/group-password-policy/target/group-password-policy-1.0.0.jar`

## Install in Docker Keycloak

1. Copy the JAR into a local providers directory:
   ```bash
   mkdir -p ./providers
   cp extensions/group-password-policy/target/group-password-policy-1.0.0.jar ./providers/
   ```
2. Restart Keycloak:
   ```bash
   docker compose down
   docker compose up -d
   ```
3. In Admin Console: Realm Settings -> Authentication -> Password Policy -> Add policy -> `Group-based password policy`.
4. In Admin Console: Authentication -> Required Actions -> enable `Group password expiration check`.
