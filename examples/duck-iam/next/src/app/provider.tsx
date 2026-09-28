'use client'

import { Provider } from '@gentleduck/auth/client/react'
import type { ReactNode } from 'react'

export function AuthProvider({ children }: { children: ReactNode }) {
  return <Provider baseUrl="/api/auth">{children}</Provider>
}
