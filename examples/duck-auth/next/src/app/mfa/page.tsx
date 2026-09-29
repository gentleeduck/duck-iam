'use client'

import { Button } from '@gentleduck/registry-ui/button'
import { api } from '@/api'
import { AuthLayout } from '@/components/auth-layout'
import { Field, Notice, useSubmit } from '@/components/form'

export default function MfaPage() {
  const submit = useSubmit(async (form) => {
    const res = await api.verifyMfa(String(form.get('code')).trim())
    if (!res.ok) return res
    location.assign('/')
    return null
  })

  return (
    <AuthLayout
      title="Two-factor check"
      description="Enter the code from your authenticator app, or one of your backup codes."
      footer={
        <Button variant="link" size="sm" onClick={() => api.signOut().then(() => location.assign('/sign-in'))}>
          Use another account
        </Button>
      }>
      <form onSubmit={submit.onSubmit} className="grid gap-4">
        <Field label="Code" name="code" autoComplete="one-time-code" />
        <Notice res={submit.res} />
        <Button type="submit" loading={submit.pending}>
          Verify
        </Button>
      </form>
    </AuthLayout>
  )
}
