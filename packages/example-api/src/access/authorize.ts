import type { AppAction, AppResource, AppScope } from '@gentleduck/example-shared'
import { createTypedAuthorize } from 'access-engine/server/nest'

export const Authorize = createTypedAuthorize<AppAction, AppResource, AppScope>()
