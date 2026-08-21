---
'@gentleduck/auth': major
---

Record email verification on the column, not the profile.

`completeEmailVerification` wrote `emailVerified: true` into the identity's profile, and
the OIDC OP read `email_verified` back out of it for the userinfo claim.

`updateProfile` merges a caller-supplied patch without filtering keys, so a verified-email
flag living in the profile is something the account holder can set on themselves, and any
relying party trusting the `email_verified` claim inherits that. The `emailVerified`
column has been on the identity row the whole time.

Both sides read and write the column now, and `beginSignUp` stops seeding the profile
flag.

BREAKING: `emailVerified` no longer appears in `identity.profile`. Read
`identity.emailVerified` instead. Existing rows keep whatever their profile already
holds; nothing reads it any more. If an application has been trusting
`profile.emailVerified`, treat that value as unverified user input and reconcile it
against the column before relying on it.
