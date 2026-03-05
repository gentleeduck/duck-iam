import type { AppAction, AppResource, AppScope } from '@gentleduck/example-shared'
import { createTypedAuthorize } from 'duck-iam/server/nest'

export const Authorize = createTypedAuthorize<AppAction, AppResource, AppScope>()
