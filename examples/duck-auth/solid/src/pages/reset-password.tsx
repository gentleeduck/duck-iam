import { WEAK_PASSWORD } from '@examples/duck-auth-ui/api'
import * as ui from '@examples/duck-auth-ui/recipes'
import { api } from '../api'
import { createSubmit, Field, Notice } from '../form'
import { AuthLayout } from '../layout'

export function ResetPassword() {
  const token = new URLSearchParams(location.search).get('token') ?? ''
  const submit = createSubmit((form) => api.resetPassword(token, String(form.get('password'))))

  return (
    <AuthLayout
      title="Choose a new password"
      description="Every signed-in device is signed out once it changes."
      footer={
        <a href="/sign-in" class="text-foreground">
          Back to sign in
        </a>
      }>
      <form onSubmit={submit.onSubmit} class="grid gap-4">
        <Field label="New password" name="password" type="password" autocomplete="new-password" />
        <Notice res={submit.res()} invalid={WEAK_PASSWORD} done="Password changed. Sign in with the new one." />
        <button type="submit" class={ui.button()} disabled={submit.pending()}>
          Change password
        </button>
      </form>
    </AuthLayout>
  )
}
