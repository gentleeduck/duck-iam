'use client'

import { WEAK_PASSWORD } from '@examples/duck-auth-ui/api'
import { Button } from '@gentleduck/registry-ui/button'
import Link from 'next/link'
import { api } from '@/api'
import { AuthLayout } from '@/components/auth-layout'
import { Field, Notice, useSubmit } from '@/components/form'

export default function SignUpPage() {
  const submit = useSubmit((form) =>
    api.signUp({
      name: String(form.get('name')),
      email: String(form.get('email')),
      password: String(form.get('password')),
    }),
  )

  return (
    <AuthLayout
      title="Create an account"
      description="Eight characters or more for the password."
      footer={
        <>
          Have an account?
          <Link href="/sign-in" className="text-foreground">
            Sign in
          </Link>
        </>
      }>
      <form onSubmit={submit.onSubmit} className="grid gap-4">
        <Field label="Name" name="name" autoComplete="name" />
        <Field label="Email" name="email" type="email" autoComplete="email" />
        <Field label="Password" name="password" type="password" autoComplete="new-password" />
        <Notice
          res={submit.res}
          invalid={WEAK_PASSWORD}
          done="Account created. The verification link is in the backend's terminal."
        />
        <Button type="submit" loading={submit.pending}>
          Sign up
        </Button>
      </form>
    </AuthLayout>
  )
}
