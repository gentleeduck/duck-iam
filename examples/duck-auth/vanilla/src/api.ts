import { createApi, pickedBackend } from '@examples/duck-auth-ui/api'
import { createAuthClient } from '@gentleduck/auth/client/vanilla'

export const api = createApi(`/api/${pickedBackend()}`)
export const client = createAuthClient(api.auth)
