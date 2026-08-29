'use client'

import { createIamAccessControl } from '@gentleduck/iam/client/react'
import React from 'react'

export const { AccessProvider, useAccess, Can, Cannot } = createIamAccessControl(React)
