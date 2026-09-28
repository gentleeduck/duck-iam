import * as ui from '@examples/duck-auth-ui/recipes'
import { api } from '../api'
import { createSubmit, Notice } from '../form'
import { AuthLayout } from '../layout'

export function VerifyEmail() {
  const token = new URLSearchParams(location.search).get('token') ?? ''
  const submit = createSubmit(() => api.verifyEmail(token))

  return (
    <AuthLayout
      title="Verify your email"
      description="Confirm this address belongs to you."
      footer={
        <a href="/" class="text-foreground">
          Go to the dashboard
        </a>
      }>
      <form onSubmit={submit.onSubmit} class="grid gap-4">
        <Notice res={submit.res()} done="Your email is verified." />
        <button type="submit" class={ui.button()} disabled={submit.pending()}>
          Verify email
        </button>
      </form>
    </AuthLayout>
  )
}
