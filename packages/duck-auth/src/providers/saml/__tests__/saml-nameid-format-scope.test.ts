/** The email/nameID agreement check keyed on the formats the SP *accepts*, not on the one the assertion
 *  arrived with, so adding `persistent` to the allow-list refused every persistent login. */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { randomToken, sha256, timingSafeEqual } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import type { Identities } from '~/core/identities'
import { MemoryLimiter } from '~/limiters/memory'
import { type Saml, saml } from '../index'

interface MyProfile extends Identities.ProfileMetadataBase {}

const EMAIL_FORMAT = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
const PERSISTENT_FORMAT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'

let adapter: MemoryAdapter<MyProfile>

beforeEach(() => {
  adapter = new MemoryAdapter<MyProfile>()
})

function ctxFor() {
  return {
    baseUrl: 'https://app.test',
    crypto: { authRandomToken: randomToken, authSha256: sha256, authTimingSafeEqual: timingSafeEqual },
    events: new InMemoryEvents(),
    limiter: new MemoryLimiter(),
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    tenant: {},
  }
}

/** One assertion, one SP allow-list: the two knobs the guard reads. */
function complete(opts: { allowed?: readonly string[]; profile: Saml.Profile }) {
  const client: Saml.Client = {
    getAuthorizeUrlAsync: vi.fn(async () => 'https://idp.example/sso'),
    validatePostResponseAsync: vi.fn(async () => ({ loggedOut: false, profile: opts.profile })),
  }
  const provider = saml({
    allowReplay: true,
    allowUnsolicited: true,
    callbackUrl: 'https://app/acs',
    client,
    onSignIn: async () => ({ identityId: 'ident-1' }),
    ...(opts.allowed !== undefined && { allowedNameIdFormats: opts.allowed }),
  })
  return provider.complete(ctxFor(), { SAMLResponse: 'PHNhbWw+' })
}

describe('the email/nameID agreement check', () => {
  it('lets a persistent assertion through when the SP also accepts emailAddress', async () => {
    // Identical to the case below in every way but the allow-list, which the assertion knows nothing about.
    await expect(
      complete({
        allowed: [EMAIL_FORMAT, PERSISTENT_FORMAT],
        profile: { email: 'user@x.com', nameID: 'opaque-abc-123', nameIDFormat: PERSISTENT_FORMAT },
      }),
    ).resolves.toMatchObject([{ identityId: 'ident-1', type: 'startSession' }])
  })

  it('lets the same assertion through when persistent is the only format accepted', async () => {
    await expect(
      complete({
        allowed: [PERSISTENT_FORMAT],
        profile: { email: 'user@x.com', nameID: 'opaque-abc-123', nameIDFormat: PERSISTENT_FORMAT },
      }),
    ).resolves.toMatchObject([{ identityId: 'ident-1', type: 'startSession' }])
  })

  it('still refuses an emailAddress assertion whose email disagrees with its nameID', async () => {
    await expect(
      complete({
        allowed: [EMAIL_FORMAT, PERSISTENT_FORMAT],
        profile: { email: 'admin@victim.com', nameID: 'user@x.com', nameIDFormat: EMAIL_FORMAT },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })

  it('still refuses a disagreeing email when the IdP stated no format at all', async () => {
    // Nothing says which format this is, so the allow-list stays the only evidence and the guard holds.
    await expect(complete({ profile: { email: 'admin@victim.com', nameID: 'user@x.com' } })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
  })

  it('still refuses a disagreeing email with no stated format even where several are accepted', async () => {
    await expect(
      complete({
        allowed: [EMAIL_FORMAT, PERSISTENT_FORMAT],
        profile: { email: 'admin@victim.com', nameID: 'user@x.com' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })

  it('still refuses a format the SP does not accept at all', async () => {
    await expect(
      complete({
        allowed: [EMAIL_FORMAT],
        profile: { email: 'user@x.com', nameID: 'opaque-abc-123', nameIDFormat: PERSISTENT_FORMAT },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })
})
