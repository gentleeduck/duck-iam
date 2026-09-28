'use client'

import { Provider } from '@gentleduck/auth/client/react'
import type { ReactNode } from 'react'
import { api } from '@/api'

export function AuthProvider({ children }: { children: ReactNode }) {
  return <Provider {...api.auth}>{children}</Provider>
}
