---
'@gentleduck/auth': major
---

The rest of the critical and high findings in `core/flows`: an enumeration oracle, a delete that took three other flows' tokens with it, a signup that produced rows Postgres refuses, and a signup with no rate limit.

**`requestPasswordReset` no longer answers, by clock or by error, whether an address is registered.**

The unknown-address branch was a token gesture — one `sha256` — against a write and two reads on the known one. Separable by response time from anywhere. The library already had the correct version of this defence in `passwords.ts`, which runs a full hash against `NO_IDENTITY_SENTINEL` so the unknown path costs what the real one costs; the reset flow gestured at it without achieving it.

Both branches now mint a token, hash it, and make the same three store calls in the same order, against the same sentinel. What could not be mirrored is the write — `auth_credentials.identity_id` is a foreign key, so there is no row to hang a decoy on — leaving one write against one read on the same table, down from one hash against three round-trips. The residue is pinned as a `FINDING:` rather than papered over.

The louder half was not a timing signal at all: a channel that was not configured **threw** for an address that exists and returned `{ok:true}` for one that does not, saying it in plain language in the response body. The channel check moved above the identity lookup, so a wiring fault is a wiring fault regardless of who asked.

One consequence worth stating: `requireMfa()` now runs on both branches, so a deployment with no MFA provider gets `AUTH_PROVIDER_NOT_REGISTERED` from either — the flow has always needed the provider for a known address, and the asymmetry was itself the oracle.

**`requestEmailVerification` no longer voids three other flows' tokens.**

It ran `deleteByKind(identityId, 'recovery')`. Four different flows share `kind: 'recovery'` — password-reset tokens, email-verification tokens, account-deletion tokens, and signup-flow state — and they are told apart only by a metadata field, which `deleteByKind` cannot read. So asking for a verification mail silently destroyed an in-flight password reset, a pending deletion confirmation, and an in-progress signup, stranding the user with a flow token that no longer resolved.

Now it lists the identity's `recovery` rows and deletes only those whose purpose is `email-verification` — the same list-filter-delete `requestAccountDeletion` already used. It still replaces its own stale token, so two requests never leave two live links.

**One discriminator, written by everything.** That fix is only correct if every flow supplies a purpose, and two did not: signup and password-reset wrote `metadata.kind` while `getCredentialPurpose()` — the helper every guard and every delete reads — reads `metadata.purpose`, and so returned `undefined` for both. All four now write `purpose`, and the two flows that reached into `metadata.kind` by hand read the helper instead.

**`beginSignUp` builds a profile the library's own Postgres adapter accepts.**

`Identities.ProfileMetadataBase` requires `username`. duck-auth's pg schema enforces it with `chk_auth_identities_profile_shape` plus a unique index on `lower(profile->>'username')`. And `beginSignUp` built `{ ...initialProfile, email }` — no username — then cast past its own type with `as unknown as Profile`. Since `initialProfile` is optional, `beginSignUp({ email })`, the documented happy path, produced an INSERT the library's own adapter rejects. Nothing caught it because the sqlite conformance DDL states in its own comment that it omits CHECK constraints, and memory and Redis have no schema at all.

`username` is now derived from the address when the caller supplies none, and the double cast is gone. From the whole address rather than its local part: `username` carries a unique index too, so deriving `sam` would refuse the next `sam@b.com` because `sam@a.com` signed up first — a collision on a handle neither user chose.

**`beginSignUp` consumes the rate limiter.** It was the only flow in the unit that never did; password-reset, email-verification and account-deletion all do. One unauthenticated request equalled one permanent identity row, unbounded. Keyed per canonical address, so hammering one victim's address is what gets capped.

**Breaking:**

- `beginSignUp` throws `AUTH_RATE_LIMITED` when the limiter trips. A host with a tight limiter and a signup retry loop will start seeing it.
- `beginSignUp` writes a `username` into the profile when `initialProfile` omits one. Code asserting the profile has exactly the keys it passed will see one more.
- Credential rows for password-reset and signup-flow state carry `metadata.purpose` instead of `metadata.kind`. **There is no fallback reader**: a token minted by the previous version resolves to no purpose and is refused as invalid. Both are 30-minute-TTL rows, so the exposure is one deployment window, and the failure direction is closed.
- `requestPasswordReset` throws `AUTH_MISCONFIGURED` for a missing channel even when the address does not exist, and `AUTH_PROVIDER_NOT_REGISTERED` when the MFA provider is absent, on both branches.

**Still open — F21's other half.** The rate limit caps how fast identities appear; it does not stop one appearing for an address nobody proved they own, so account pre-emption and the duplicate-address refusal remain. The recommended fix — hold signup state in the credentials store and create the identity at `completeSignUp` — cannot be built, because `fk_auth_credentials_identity` requires the row that fix defers, and `Provider.Context` carries no other store that could hold it. That makes it a schema decision rather than a flow one. Both halves are pinned as `FINDING:` tests.
