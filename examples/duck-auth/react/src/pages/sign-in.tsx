import { landedWith, type Provider } from '@examples/duck-auth-ui/api'
import { Button } from '@gentleduck/registry-ui/button'
import { Separator } from '@gentleduck/registry-ui/separator'
import { useEffect, useState } from 'react'
import { api } from '../api'
import { Field, Notice, useSubmit } from '../form'
import { AuthLayout } from '../layout'

export function SignIn() {
  const [oauth, setOauth] = useState<Provider[]>([])
  const landed = landedWith(new URLSearchParams(location.search).get('error'))

  useEffect(() => {
    api.providers().then((res) => {
      if (res.ok) setOauth(res.data.providers.filter((provider) => provider.kind === 'oauth'))
    })
  }, [])

  const submit = useSubmit(async (form) => {
    const email = form.get('email')
    const intent = form.get('intent')
    if (intent === 'magic-link') return api.beginProvider('magic-link', { email })
    if (typeof intent === 'string') {
      // The page is on its way to the IdP once this succeeds, so only a failure has anything to show.
      const res = await api.beginProvider(intent)
      return res.ok ? null : res
    }
    const res = await api.signIn('password', { email, password: form.get('password') })
    if (!res.ok) return res
    location.assign('/')
    return null
  })

  return (
    <AuthLayout
      title="Sign in"
      description="Welcome back."
      footer={
        <>
          No account?
          <a href="/sign-up" className="text-foreground">
            Sign up
          </a>
        </>
      }>
      <form onSubmit={submit.onSubmit} className="grid gap-4">
        <Field label="Email" name="email" type="email" autoComplete="email" />
        <Field label="Password" name="password" type="password" autoComplete="current-password" />
        <a href="/forgot-password" className="text-muted-foreground text-sm">
          Forgot your password?
        </a>
        <Notice res={submit.res ?? landed} done="Your sign-in link is in the backend's terminal." />
        <Button type="submit" loading={submit.pending}>
          Sign in
        </Button>
        <Button type="submit" name="intent" value="magic-link" variant="outline" formNoValidate>
          Email me a sign-in link
        </Button>
        {oauth.length > 0 && <Separator />}
        {oauth.map((provider) => (
          <Button key={provider.id} type="submit" name="intent" value={provider.id} variant="outline" formNoValidate>
            Continue with {provider.id.replace('oauth:', '')}
          </Button>
        ))}
      </form>
    </AuthLayout>
  )
}
