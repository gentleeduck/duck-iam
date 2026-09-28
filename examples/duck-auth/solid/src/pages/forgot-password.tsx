import * as ui from '@examples/duck-auth-ui/recipes'
import { api } from '../api'
import { createSubmit, Field, Notice } from '../form'
import { AuthLayout } from '../layout'

export function ForgotPassword() {
  const submit = createSubmit((form) => api.forgotPassword(String(form.get('email'))))

  return (
    <AuthLayout
      title="Reset your password"
      description="We will send a reset link to your email."
      footer={
        <a href="/sign-in" class="text-foreground">
          Back to sign in
        </a>
      }>
      <form onSubmit={submit.onSubmit} class="grid gap-4">
        <Field label="Email" name="email" type="email" autocomplete="email" />
        <Notice res={submit.res()} done="If that email has an account, its reset link is in the backend's terminal." />
        <button type="submit" class={ui.button()} disabled={submit.pending()}>
          Send reset link
        </button>
      </form>
    </AuthLayout>
  )
}
