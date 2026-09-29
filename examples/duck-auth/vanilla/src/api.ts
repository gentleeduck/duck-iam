import { createApi, pickedBackend } from '@examples/duck-auth-ui/api'

export const api = createApi(`/api/${pickedBackend()}`)
