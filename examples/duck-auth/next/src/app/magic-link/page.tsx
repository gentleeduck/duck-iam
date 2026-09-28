'use client'

import { useSignIn } from '@gentleduck/auth/client/react'
import { Button } from '@gentleduck/registry-ui/button'
import { AuthLayout } from '@/components/auth-layout'
import { Notice, useSubmit } from '@/components/form'

export default function MagicLinkPage() {
  const signIn = useSignIn()
  const submit = useSubmit(async () => {
    const res = await signIn.mutate({
      providerId: 'magic-link',
      input: { token: new URLSearchParams(location.search).get('token') ?? '' },
    })
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
