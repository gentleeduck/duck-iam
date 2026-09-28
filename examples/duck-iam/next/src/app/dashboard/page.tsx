'use client'

import { useSession, useSignOut } from '@gentleduck/auth/client/react'
import { useCallback, useState } from 'react'
import { AccessProvider, usePermissions } from '@/access'
import { api } from './api'
import { DuckMarket } from './duck-market'
import { LoginForm } from './login-form'

const EMPTY_PERMISSIONS = {}

export default function DashboardPage() {
  const { status } = useSession()
  const signOut = useSignOut()
  const [me, setMe] = useState<{ subject: string; scope: string | null } | null>(null)

  // Piggybacks on the same `/api/me/permissions` call `usePermissions` already makes, rather than
  // fetching `subject`/`scope` a second time.
  const fetchPermissions = useCallback(async () => {
    if (status !== 'authed') {
      setMe(null)
      return EMPTY_PERMISSIONS
    }
    const res = await api.permissions()
    setMe({ subject: res.subject, scope: res.scope })
    return res.permissions
  }, [status])

  const { permissions, loading, error, refetch } = usePermissions(fetchPermissions, [status])

  if (status === 'loading') {
    return (
      <main>
        <p className="muted">Loading...</p>
      </main>
    )
  }

  if (status === 'guest') {
    return (
      <main>
        <LoginForm />
      </main>
    )
  }

  if (error) {
    return (
      <main>
        <p role="alert" style={{ color: 'var(--danger)' }}>
          Couldn't load your permissions: {error.message}
        </p>
        <button type="button" onClick={() => refetch()}>
          Retry
        </button>
      </main>
    )
  }

  if (loading || !me?.scope) {
    return (
      <main>
        <p className="muted">Loading permissions...</p>
      </main>
    )
  }

  return (
    <AccessProvider permissions={permissions}>
      <DuckMarket userId={me.subject} companyId={me.scope} onSignOut={() => signOut.mutate()} />
    </AccessProvider>
  )
}
