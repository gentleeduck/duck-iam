import type { AppAction, AppResource } from '@blogduck/shared'
import { IamAuthorize, type IamNest } from '@gentleduck/iam/server/nest'

/**
 * `createTypedAuthorize` was removed in 5.0.0. `IamAuthorize` is the decorator
 * itself and is already generic, so the app-level alias is now just a call that
 * pins the action/resource unions - the `@Authorize({ ... })` call sites are
 * unchanged.
 */
export const Authorize = (meta: IamNest.IAuthorizeMeta<AppAction, AppResource>): MethodDecorator =>
  IamAuthorize<AppAction, AppResource>(meta)
