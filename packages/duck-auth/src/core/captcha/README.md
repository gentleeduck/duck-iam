# Captcha

One question — *did a human solve a fresh challenge on my site?* — asked of three providers that answer
it in almost the same way.

`auth.captcha` is always a verifier. When `cfg.captcha` was not supplied it is
`AuthUnconfiguredCaptchaVerifier`, which fails every call with `captcha-not-configured` rather than
being `undefined` for each call site to remember to check.

## Nothing here calls it

Configuring `cfg.captcha` makes a verifier reachable and does nothing else. No flow, provider or route
in this package calls `verify`, and `Provider.Context` carries no verifier, so a deployment that sets
`cfg.captcha` and stops there has a captcha in front of nothing. The host owns the call:

```ts
const solved = await auth.captcha.verify({ token: body.captchaToken, remoteIp: req.ip })
if (!solved.success) {
  throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: solved.errorCodes?.join(', ') ?? 'captcha' })
}
await auth.flows.signIn({ providerId: 'password', input: body, ip: req.ip })
```

There is no captcha error code to throw, because `verify` never throws and `errorCodes` is the
provider's vocabulary rather than this package's — naming the refusal is the host's call too.

Put the check wherever the challenge belongs: the route before `signIn`, or inside a provider of your
own, which can close over the verifier it was built with.

## Never throws

`verify` answers `{ success: false }` for everything: a provider that rejected the token, a provider
that timed out, a provider that returned HTML, a DNS failure. Captcha fronts sign-in, and a verifier
that throws turns a bot check into a 500 for everybody.

That makes `errorCodes` the whole story, so it is never empty on a failure. It is `string[]`, not an
`AuthError.Code`: most of what lands there is the provider's own wire vocabulary, passed through
verbatim. The ones this package adds are:

| code | meaning |
| --- | --- |
| `missing-input-response` | no token was supplied |
| `invalid-input-response` | the token was refused before it was sent: not a string, or with the code below |
| `token-too-large` | over `CAPTCHA_TOKEN_MAX_LENGTH` |
| `timeout` | the provider did not answer within `timeoutMs` |
| `network-error` | the call failed; the thrown message is on `detail`, not in this array |
| `provider-http-<status>` | the provider answered non-2xx |
| `malformed-response` | the provider answered, but not with a siteverify body |
| `invalid-expected-hostname` | a per-call `expectedHostname` naming nothing, which would have turned the check off |
| `hostname-mismatch` | the widget ran on a host nobody expected |
| `invalid-expected-action` | a per-call `expectedAction` of `''`, which would have replaced the configured one |
| `action-mismatch` | the response carried a different action than the one asked for, or none |
| `malformed-challenge-ts` | `challenge_ts` was not a date |
| `challenge-expired` | solved longer than `maxChallengeAgeMs` ago |
| `challenge-in-future` | further ahead than `CAPTCHA_FORWARD_SKEW_MS` allows for clock skew |
| `missing-score` | reCAPTCHA v3 reported success with no score, which is not a low one |
| `score-too-low` | under the configured `minScore` |
| `expected-action-unsupported` | an `expectedAction` was asked of hCaptcha, which returns none |
| `captcha-not-configured` | no verifier was configured |
| `provider-rejected` | the provider refused the token and named no reason of its own |

## The shared path

The three siteverify providers differ by endpoint, by whether they return a score, and by whether they
echo an action. Everything else is one function, `siteVerify`.

In order, all of it before any provider-specific code runs:

| | check | code on failure |
| --- | --- | --- |
| 1 | a token is present, a string, and under `CAPTCHA_TOKEN_MAX_LENGTH`; a per-call expectation is not empty | `missing-input-response`, `invalid-input-response`, `token-too-large`, `invalid-expected-hostname`, `invalid-expected-action` |
| 2 | the POST completed inside `timeoutMs`, and the response was 2xx | `timeout`, `network-error`, `provider-http-<status>` |
| 3 | the body is a siteverify body | `malformed-response` |
| 4 | the widget ran on an expected host | `hostname-mismatch` |
| 5 | the response echoes the expected action | `action-mismatch` |
| 6 | `challenge_ts` is a date, neither too old nor in the future | `malformed-challenge-ts`, `challenge-expired`, `challenge-in-future` |

Step 1 fails before anything is sent, so a caller's mistake does not spend the user's single-use token.
A failure from step 4 on still reports `hostname`, `action`, `challengeTs` and the provider's codes, so a
caller can apply its own rule instead of being told only pass or fail.

Two details worth knowing. A non-2xx answer fails at step 2 whatever its body says, because a captive
portal that happens to serialise `{"success":true}` is not a solved challenge. And the POST is made with
`redirect: 'error'`: the endpoint was vetted, a redirect target was not, and a 307 would re-post the
body with the secret in it.

## Verifiers

**`AuthTurnstileVerifier`** — Cloudflare Turnstile. Takes an optional `expectedAction`.

**`AuthHCaptchaVerifier`** — hCaptcha. Refuses an `expectedAction` at construction and answers
`expected-action-unsupported` to a per-call one, because hCaptcha returns no action and asking for one
would otherwise fail every call for a reason nothing named.

**`AuthRecaptchaV3Verifier`** — reCAPTCHA v3. Passes at or above `minScore`, default 0.5. Success with
no score is `missing-score`, not a low score, so `minScore: 0` still refuses a response carrying none.

**`AuthNullCaptchaVerifier`** — passes everything, for tests. Refuses to construct under
`NODE_ENV=production` unless `development: true`, and `strict()` refuses it too, keying on a marker field
rather than on `id`, which any verifier could spell.

**`AuthUnconfiguredCaptchaVerifier`** — the default. Fails everything with `captcha-not-configured`.

Each has a lowercase factory — `authTurnstileVerifier(cfg)` — for a caller who would rather not write
`new`.

## Configuring one

```ts
import { authTurnstileVerifier, createAuth } from '@gentleduck/auth/core'

const auth = createAuth({
  captcha: authTurnstileVerifier({
    secret: process.env.TURNSTILE_SECRET!,
    expectedHostname: 'app.example.com',
    expectedAction: 'signin',
  }),
})
```

Everything optional has a default, and every bound is checked at construction rather than on the first
request: a `minScore` outside 0..1, a `timeoutMs` that is not positive or is past `setTimeout`'s
2^31-1ms, a negative `maxChallengeAgeMs`, an `expectedHostname` that names nothing, an `expectedAction`
that is empty. A misconfigured verifier does not reach production quietly.

`expectedHostname` takes a host or a list, and is compared case-insensitively because a hostname is.
`expectedAction` and `expectedHostname` can also be passed per call, which is how one wiring
distinguishes sign-in from sign-up.

## What this is not

**Not a rate limit.** A solved challenge is a solved challenge, however many arrive. `auth.limiter`
is the other control and they do different jobs.

**Not proof of who.** It says a human was there, not which one. Everything about identity is still
the provider's job afterwards.

**Not a reason to trust the endpoint.** `endpoint` is passed to `assertSafeOutboundUrl`, because the
secret is posted to whatever it points at. `allowInsecureEndpoint` lifts the HTTPS rule and nothing else:
a loopback or private address stays refused, so it cannot point at `localhost` and what it is for is a
mock reachable by name. `strict({ env: 'production' })` refuses a verifier built with it, the way it
refuses `AuthNullCaptchaVerifier` — a cleartext siteverify POST hands the secret to anyone on the path,
and lets them answer `success: true` to every call.

**Not a replay check.** All three providers invalidate a token the first time it is verified, so a
replayed one comes back as a provider rejection. Nothing here dedupes, which matters if you write your
own `IVerifier` against a provider that does not.

**Not exempt from the clock.** A solution older than `maxChallengeAgeMs` (5 minutes by default) is
refused even though the provider still says it is valid, and one more than a minute in the future is
refused as well. Both ends, because a one-sided comparison is true forever on the wrong side of it.
