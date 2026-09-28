'use client'

import { Button } from '@gentleduck/registry-ui/button'
import Link from 'next/link'
import { api } from '@/api'
import { AuthLayout } from '@/components/auth-layout'
import { Field, Notice, useSubmit } from '@/components/form'

export default function ForgotPasswordPage() {
  const submit = useSubmit((form) => api.forgotPassword(String(form.get('email'))))

  return (
    <AuthLayout
      title="Reset your password"
      description="We will send a reset link to your email."
      footer={
        <Link href="/sign-in" className="text-foreground">
          Back to sign in
        </Link>
      }>
      <form onSubmit={submit.onSubmit} className="grid gap-4">
        <Field label="Email" name="email" type="email" autoComplete="email" />
        <Notice res={submit.res} done="If that email has an account, its reset link is in the backend's terminal." />
        <Button type="submit" loading={submit.pending}>
          Send reset link
        </Button>
      </form>
    </AuthLayout>
  )
}
