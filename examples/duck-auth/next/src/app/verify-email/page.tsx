'use client'

import { Button } from '@gentleduck/registry-ui/button'
import Link from 'next/link'
import { api } from '@/api'
import { AuthLayout } from '@/components/auth-layout'
import { Notice, useSubmit } from '@/components/form'

export default function VerifyEmailPage() {
  const submit = useSubmit(() => api.verifyEmail(new URLSearchParams(location.search).get('token') ?? ''))

  return (
    <AuthLayout
      title="Verify your email"
      description="Confirm this address belongs to you."
      footer={
        <Link href="/" className="text-foreground">
          Go to the dashboard
        </Link>
      }>
      <form onSubmit={submit.onSubmit} className="grid gap-4">
        <Notice res={submit.res} done="Your email is verified." />
        <Button type="submit" loading={submit.pending}>
          Verify email
        </Button>
      </form>
    </AuthLayout>
  )
}
