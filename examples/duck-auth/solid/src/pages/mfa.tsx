import * as ui from '@examples/duck-auth-ui/recipes'
import { authUseSignOut } from '@gentleduck/auth/client/solid'
import { api } from '../api'
import { createSubmit, Field, Notice } from '../form'
import { AuthLayout } from '../layout'

export function Mfa() {
  const signOut = authUseSignOut()
  const submit = createSubmit(async (form) => {
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
        <button
          type="button"
          class={ui.button({ variant: 'link', size: 'sm' })}
          onClick={() => signOut.mutate().then(() => location.assign('/sign-in'))}>
          Use another account
        </button>
      }>
      <form onSubmit={submit.onSubmit} class="grid gap-4">
        <Field label="Code" name="code" autocomplete="one-time-code" />
        <Notice res={submit.res()} />
        <button type="submit" class={ui.button()} disabled={submit.pending()}>
          Verify
        </button>
      </form>
    </AuthLayout>
  )
}
