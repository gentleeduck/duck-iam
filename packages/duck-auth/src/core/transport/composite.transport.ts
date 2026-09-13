import { AuthError } from '~/core/errors'
import type { Provider } from '../provider/provider.types'
import type { Sessions } from '../sessions/sessions.types'
import type { Transport } from '../transport/transport.types'
import { COMPOSITE_TOKEN_MAX_LENGTH } from './transport.constants'

/**
 * Try each transport in order on extract; emit Intents from every transport
 * on issue/revoke (so cookie + bearer co-exist on the same response).
 */
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

  extract(req: { headers: Headers }): string | null {
    // Every transport is asked, not just up to the first hit, because which credentials a request
    // carries is the question - resolving it by array order is what let a planted cookie outrank a
    // bearer token the client actually sent.
    //
    // One transport raising on a header it cannot parse must not stop the later ones being asked, or
    // a malformed cookie denies a request that also carried a usable bearer token - which is a
    // credential the caller did present, refused for one it did not.
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
    if (found.length === 0) {
      // Nothing usable was found, so the parse failure is the most specific answer available and is
      // raised rather than swallowed into a bare `null`.
      if (failure !== undefined) throw failure
      return null
    }
    const first = found[0] as string
    // The same token arriving by two methods is one credential presented twice, not two.
    if (found.every((t) => t === first)) return first
    if (this._onMultiple === 'first') return first
    throw new AuthError('AUTH_INVALID_CREDENTIALS', {
      detail: 'request presented different credentials by more than one transport (RFC 6750 section 2)',
    })
  }

  issue(sid: string, session: Sessions.Me, opts: Transport.IssueOpts): Provider.Intent[] {
    // Not transactional on purpose: a transport that throws mid-issue emits nothing at all rather
    // than half a sign-in, so the caller sees the failure and can undo the session row it wrote.
    return assertOneBody(
      this._transports.flatMap((t) => t.issue(sid, session, opts)),
      'issue',
    )
  }

  revoke(): Provider.Intent[] {
    return assertOneBody(
      this._transports.flatMap((t) => t.revoke()),
      'revoke',
    )
  }

  async verify(token: string): Promise<Sessions.Me | null> {
    if (typeof token !== 'string' || token.length === 0 || token.length > this.maxTokenLength) {
      return null
    }
    // Sequential, and deliberately so: order is the tiebreak between transports that would both
    // vouch for a token, and asking them at once would decide it by whichever resolved first.
    let failure: unknown
    for (const t of this._transports) {
      if (!t.verify) continue
      let session: Sessions.Me | null = null
      try {
        session = await t.verify(token)
      } catch (err) {
        // A JWKS fetch failure in one transport used to take down every transport after it, so a
        // recoverable fault in an optional member broke the primary one.
        failure ??= err
        continue
      }
      if (session) return session
      // A refusal from a transport that claims the last word is a veto, not a pass to the next one.
      if (t.authoritative) return null
    }
    if (failure !== undefined) throw failure
    return null
  }
}

/**
 * A response has one body. Two body-emitting transports handed the server adapter two json intents
 * and which one the client received was decided by whatever the adapter did with a list it was
 * never told could hold duplicates - so one of the two tokens was lost, silently.
 */
function assertOneBody(intents: Provider.Intent[], phase: string): Provider.Intent[] {
  if (intents.filter((i) => i.type === 'json').length > 1) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `AuthCompositeTransport: ${phase} produced more than one json body; a response can only carry one`,
    })
  }
  return intents
}

/** Factory around {@link CompositeTransport} for functional-style config. */
export function compositeTransport(
  transports: Transport.ITransport[],
  opts?: Transport.CompositeOpts,
): CompositeTransport {
  return new CompositeTransport(transports, opts)
}
