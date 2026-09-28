import { createIamAccessControl } from '@gentleduck/iam/client/react'
import React from 'react'
// Type-only: `./iam/iam` pulls in the drizzle-backed engine, which must never reach a client
// bundle. `import type` is erased at compile time, so only the types cross this boundary.
import type { AppAction, AppResource } from './iam/iam'

export const { AccessProvider, useAccess, usePermissions, Can } = createIamAccessControl<
  AppAction,
  AppResource,
  string
>(React)
