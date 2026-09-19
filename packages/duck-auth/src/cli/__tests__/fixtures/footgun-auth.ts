/** An `auth.ts` a production deployment must not boot: the memory adapter, no limiter, http, an insecure
 *  cookie and no provider. `doctor` exists to name these, so this is what it is pointed at. */
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'

const adapter = new MemoryAdapter()

export const auth = new AuthEngine({
  baseUrl: 'http://localhost:3000',
  stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
  transport: new CookieTransport({ name: 'duck-sid', secure: false }),
})
