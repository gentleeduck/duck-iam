import { useSignIn } from '@gentleduck/auth/client/react'
import { Button } from '@gentleduck/registry-ui/button'
import { Notice, useSubmit } from '../form'
import { AuthLayout } from '../layout'

export function MagicLink() {
  const signIn = useSignIn()
  const token = new URLSearchParams(location.search).get('token') ?? ''
  const submit = useSubmit(async () => {
    const res = await signIn.mutate({ providerId: 'magic-link', input: { token } })
    if (!res.ok) return res
    location.assign('/')
    return null
  })

  return (
    <AuthLayout title="Sign in with your link" description="The link works once and expires soon.">
      <form onSubmit={submit.onSubmit} className="grid gap-4">
        <Notice res={submit.res} />
        <Button type="submit" loading={submit.pending}>
          Sign me in
        </Button>
      </form>
    </AuthLayout>
  )
}
