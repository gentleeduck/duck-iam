import { describe } from 'vitest'
import {
  runCredentialStoreCompliance,
  runIdentityStoreCompliance,
  runSessionStoreCompliance,
} from '../../__compliance__'
import { MemoryAuthAdapter } from '../index'

describe('MemoryAuthAdapter compliance matrix', () => {
  runIdentityStoreCompliance(() => new MemoryAuthAdapter<{ email: string }>().identities)
  runSessionStoreCompliance(() => new MemoryAuthAdapter().sessions)
  runCredentialStoreCompliance(() => new MemoryAuthAdapter().credentials)
})
