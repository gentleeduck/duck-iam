import { createAuthStore } from '@gentleduck/auth/client/svelte'
import { api } from './api'

export const auth = createAuthStore(api.auth)
