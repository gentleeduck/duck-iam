import { WEAK_PASSWORD } from '@examples/duck-auth-ui/api'
import { Button } from '@gentleduck/registry-ui/button'
import { api } from '../api'
import { Field, Notice, useSubmit } from '../form'
import { AuthLayout } from '../layout'

export function ResetPassword() {
  const token = new URLSearchParams(location.search).get('token') ?? ''
  const submit = useSubmit((form) => api.resetPassword(token, String(form.get('password'))))

  return (
    <AuthLayout
      title="Choose a new password"
      description="Every signed-in device is signed out once it changes."
      footer={
        <a href="/sign-in" className="text-foreground">
          Back to sign in
        </a>
      }>
      <form onSubmit={submit.onSubmit} className="grid gap-4">
        <Field label="New password" name="password" type="password" autoComplete="new-password" />
        <Notice res={submit.res} invalid={WEAK_PASSWORD} done="Password changed. Sign in with the new one." />
        <Button type="submit" loading={submit.pending}>
          Change password
        </Button>
      </form>
    </AuthLayout>
  )
}
