'use client'

import type { AppAction, AppResource, AppScope } from '@gentleduck/example-shared'
import { createAccessControl } from 'duck-iam/client/react'
import React from 'react'

export const { AccessProvider, useAccess, usePermissions, Can, Cannot } = createAccessControl<
  AppAction,
  AppResource,
  AppScope
>(React)
