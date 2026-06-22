import { describe } from 'vitest'
import {
  authRunCredentialStoreCompliance,
  authRunIdentityStoreCompliance,
  authRunSessionStoreCompliance,
} from '../../__compliance__'
import { AuthMemoryAdapter } from '../index'

describe('AuthMemoryAdapter compliance matrix', () => {
  authRunIdentityStoreCompliance(() => new AuthMemoryAdapter<{ email: string }>().identities)
  authRunSessionStoreCompliance(() => new AuthMemoryAdapter().sessions)
  authRunCredentialStoreCompliance(() => new AuthMemoryAdapter().credentials)
})
