import * as ui from '@examples/duck-auth-ui/recipes'
import { authUseSignIn } from '@gentleduck/auth/client/solid'
import { createSubmit, Notice } from '../form'
import { AuthLayout } from '../layout'

export function MagicLink() {
  const signIn = authUseSignIn()
  const token = new URLSearchParams(location.search).get('token') ?? ''
  const submit = createSubmit(async () => {
    const res = await signIn.mutate({ providerId: 'magic-link', input: { token } })
    if (!res.ok) return res
    location.assign('/')
    return null
  })

  return (
    <AuthLayout title="Sign in with your link" description="The link works once and expires soon.">
      <form onSubmit={submit.onSubmit} class="grid gap-4">
        <Notice res={submit.res()} />
        <button type="submit" class={ui.button()} disabled={submit.pending()}>
          Sign me in
        </button>
      </form>
    </AuthLayout>
  )
}
