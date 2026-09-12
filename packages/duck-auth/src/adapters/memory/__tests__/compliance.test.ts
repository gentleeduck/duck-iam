import { describe } from 'vitest'
import {
  runAdapterRebindCompliance,
  runCredentialStoreCompliance,
  runIdentityStoreCompliance,
  runSessionStoreCompliance,
} from '~/test/store-compliance'
import { MemoryAdapter } from '../index'

describe('MemoryAdapter compliance matrix', () => {
  runIdentityStoreCompliance(() => new MemoryAdapter<{ username: string; email: string }>().identities)
  // Memory has no transactional driver and so declares no `withClient`. Wired in anyway: the suite skips
  // an adapter that omits it, and a visible skip is the difference between "by design" and "dropped".
  runAdapterRebindCompliance(
    () => new MemoryAdapter<{ username: string; email: string }>(),
    () => undefined,
  )
  runSessionStoreCompliance(() => new MemoryAdapter().sessions)
  runCredentialStoreCompliance(() => new MemoryAdapter().credentials)
})
