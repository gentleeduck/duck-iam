'use client'

import { Button } from '@gentleduck/registry-ui/button'
import { api } from '@/api'
import { AuthLayout } from '@/components/auth-layout'
import { Notice, useSubmit } from '@/components/form'

export default function MagicLinkPage() {
  const submit = useSubmit(async () => {
    const res = await api.signIn('magic-link', { token: new URLSearchParams(location.search).get('token') ?? '' })
    if (!res.ok) return res
    location.assign('/')
    return null
  })

  return (
    <AuthLayout title="Sign in with your link" description="The link works once and expires soon.">
      <form onSubmit={submit.onSubmit} className="grid gap-4">
        <Notice res={submit.res} />
        <Button type="submit" loading={submit.pending}>
          Sign me in
        </Button>
      </form>
    </AuthLayout>
  )
}
