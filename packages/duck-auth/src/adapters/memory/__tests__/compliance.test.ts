import { describe } from 'vitest'
import {
  runCredentialStoreCompliance,
  runIdentityStoreCompliance,
  runSessionStoreCompliance,
} from '~/adapters/__compliance__'
import { MemoryAdapter } from '../index'

describe('MemoryAdapter compliance matrix', () => {
  runIdentityStoreCompliance(() => new MemoryAdapter<{ username: string; email: string }>().identities)
  runSessionStoreCompliance(() => new MemoryAdapter().sessions)
  runCredentialStoreCompliance(() => new MemoryAdapter().credentials)
})
