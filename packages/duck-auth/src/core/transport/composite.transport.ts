import { ABSENT, type Answer, answer } from '~/core/answer'
import { AuthError, asAuthError } from '~/core/errors'
import type { Provider } from '../provider/provider.types'
import type { Sessions } from '../sessions/sessions.types'
import type { Transport } from '../transport/transport.types'
import { COMPOSITE_TOKEN_MAX_LENGTH } from './transport.constants'

/** Extract tries each transport in order; issue and revoke emit from every one, so a cookie and a
 *  bearer token can ride the same response. */
export class CompositeTransport implements Transport.ITransport {
  private readonly _transports: Transport.ITransport[]
  private readonly _onMultiple: 'refuse' | 'first'
  readonly maxTokenLength: number

  constructor(transports: Transport.ITransport[], opts: Transport.CompositeOpts = {}) {
    if (transports.length === 0) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: '@gentleduck/auth AuthCompositeTransport: at least one transport required',
      })
    }
    // A config assembled from two partial lists listed the same instance twice and issued two
    // identical cookies and two identical bodies for it.
    this._transports = [...new Set(transports)]
    this._onMultiple = opts.onMultipleCredentials ?? 'refuse'
    this.maxTokenLength = Math.max(...this._transports.map((t) => t.maxTokenLength ?? COMPOSITE_TOKEN_MAX_LENGTH))
  }

  /** Asks every transport, and refuses a request that presents two different credentials. */
  extract(req: { headers: Headers }): string | null {
    // Every transport is asked, not just up to the first hit, because the question is which credentials
    // the request carries: answering it by array order let a planted cookie outrank a bearer token the
    // client actually sent.
    let failure: unknown
    const found: string[] = []
    for (const t of this._transports) {
      let token: string | null = null
      try {
        token = t.extract(req)
      } catch (err) {
        failure ??= err
        continue
      }
      if (token) found.push(token)
    }
    const first = found[0]
    if (first === undefined) {
      // Nothing usable was found, so the parse failure is the most specific answer available and is
      // raised rather than swallowed into a bare `null`.
      if (failure !== undefined) throw failure
      return null
    }
    // The same token arriving by two methods is one credential presented twice, not two.
    if (found.every((t) => t === first)) return first
    if (this._onMultiple === 'first') return first
    throw new AuthError('AUTH_INVALID_CREDENTIALS', {
      detail: 'request presented different credentials by more than one transport (RFC 6750 section 2)',
    })
  }

  /** Issues through every transport, deliberately not as one transaction. */
  issue(sid: string, session: Sessions.Me, opts: Transport.IssueOpts): Provider.Intent[] {
    // Not transactional on purpose: a transport that throws mid-issue emits nothing at all rather
    // than half a sign-in, so the caller sees the failure and can undo the session row it wrote.
    return assertOneBody(
      this._transports.flatMap((t) => t.issue(sid, session, opts)),
      'issue',
    )
  }

  /** Revokes through every transport. */
  revoke(): Provider.Intent[] {
    return assertOneBody(
      this._transports.flatMap((t) => t.revoke()),
      'revoke',
    )
  }

  /** The first transport to vouch for the token wins; an authoritative refusal ends it. */
  verify(token: string): Answer.Me<Sessions.Me> {
    return answer(async () => {
      if (typeof token !== 'string' || token.length === 0 || token.length > this.maxTokenLength) {
        // A verdict, not a parameter fault: this token came off an untrusted request header, and an
        // oversize one must leave the request anonymous rather than turning it into a 400.
        throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'token is empty or over the length cap' })
      }
      // Sequential, and deliberately so: order is the tiebreak between transports that would both
      // vouch for a token, and asking them at once would decide it by whichever resolved first.
      let failure: unknown
      // As in the engine: a member reaches these two only about a token it authenticated -- every "not a
      // token of mine" rejection is in the absent set -- so they outrank the generic refusal below. A
      // later member may still vouch, so the loop runs on.
      let authenticated: unknown
      for (const t of this._transports) {
        if (!t.verify) continue
        let session: Sessions.Me | null = null
        try {
          // A JWKS fetch failure still throws, and is kept rather than rethrown so a recoverable fault
          // in an optional member cannot take down every transport after it.
          session = await t.verify(token).catch((err: unknown) => {
            // The "does not vouch" verdict, taken as `orNull` would.
            const { code } = asAuthError(err, 'AUTH_ADAPTER_FAILED')
            if (!ABSENT.has(code)) throw err
            if (code === 'AUTH_SESSION_EXPIRED' || code === 'AUTH_IMPERSONATE_WINDOW_CLOSED') {
              authenticated ??= err
            }
            return null
          })
        } catch (err) {
          // An authoritative member is not an optional one. The fall-through exists so a recoverable fault in
          // an optional transport cannot take down the members after it, and applying it here let the next
          // transport answer for a token this one had just refused - the whole thing the flag prevents. Only a
          // refusal spelled with an ABSENT code returned `null` and reached the veto below; every other
          // spelling, which is what a custom transport throws, skipped it. Its own error is rethrown rather
          // than the veto's, so a bad proof and an unreachable JWKS stay tellable apart.
          if (t.authoritative) throw err
          failure ??= err
          continue
        }
        if (session) return session
        // A refusal from a transport that claims the last word is a veto, not a pass to the next one.
        if (t.authoritative) {
          throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'an authoritative transport refused the token' })
        }
      }
      // `!== undefined`, not a truthiness test: a transport that threw `''` still threw.
      if (failure !== undefined) throw failure
      if (authenticated !== undefined) throw authenticated

      throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'no transport vouched for the token' })
    })
  }
}

/** A response has one body. Two body-emitting transports hand the server adapter two json intents, and
 *  which one the client receives comes down to whatever the adapter does with a list nothing told it
 *  could hold duplicates, so one of the two tokens goes missing without a word. */
function assertOneBody(intents: Provider.Intent[], phase: string): Provider.Intent[] {
  if (intents.filter((i) => i.type === 'json').length > 1) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `AuthCompositeTransport: ${phase} produced more than one json body; a response can only carry one`,
    })
  }
  return intents
}

/** Constructs a {@link CompositeTransport} that tries each transport in order. */
export function compositeTransport(
  transports: Transport.ITransport[],
  opts?: Transport.CompositeOpts,
): CompositeTransport {
  return new CompositeTransport(transports, opts)
}
