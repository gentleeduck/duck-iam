import { describe } from 'vitest'
import {
  authRunCredentialStoreCompliance,
  authRunIdentityStoreCompliance,
  authRunSessionStoreCompliance,
} from '../../__compliance__'
import { MemoryAdapter } from '../index'

describe('MemoryAdapter compliance matrix', () => {
  authRunIdentityStoreCompliance(() => new MemoryAdapter<{ email: string }>().identities)
  authRunSessionStoreCompliance(() => new MemoryAdapter().sessions)
  authRunCredentialStoreCompliance(() => new MemoryAdapter().credentials)
})
