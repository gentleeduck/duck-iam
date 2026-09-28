import { landedWith, type Provider } from '@examples/duck-auth-ui/api'
import * as ui from '@examples/duck-auth-ui/recipes'
import { authUseClient, authUseSignIn } from '@gentleduck/auth/client/solid'
import { createSignal, For, onMount, Show } from 'solid-js'
import { api } from '../api'
import { createSubmit, Field, Notice } from '../form'
import { AuthLayout } from '../layout'

export function SignIn() {
  const client = authUseClient()
  const signIn = authUseSignIn()
  const [oauth, setOauth] = createSignal<Provider[]>([])
  const landed = landedWith(new URLSearchParams(location.search).get('error'))

  onMount(async () => {
    const res = await api.providers()
    if (res.ok) setOauth(res.data.providers.filter((provider) => provider.kind === 'oauth'))
  })

  const submit = createSubmit(async (form) => {
    const email = form.get('email')
    const intent = form.get('intent')
    if (intent === 'magic-link') return client.beginProvider('magic-link', { email })
    if (typeof intent === 'string') {
      // The page is on its way to the IdP once this succeeds, so only a failure has anything to show.
      const res = await client.beginProvider(intent)
      return res.ok ? null : res
    }
    const res = await signIn.mutate({ providerId: 'password', input: { email, password: form.get('password') } })
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
          <a href="/sign-up" class="text-foreground">
            Sign up
          </a>
        </>
      }>
      <form onSubmit={submit.onSubmit} class="grid gap-4">
        <Field label="Email" name="email" type="email" autocomplete="email" />
        <Field label="Password" name="password" type="password" autocomplete="current-password" />
        <a href="/forgot-password" class="text-muted-foreground text-sm">
          Forgot your password?
        </a>
        <Notice res={submit.res() ?? landed} done="Your sign-in link is in the backend's terminal." />
        <button type="submit" class={ui.button()} disabled={submit.pending()}>
          Sign in
        </button>
        <button type="submit" name="intent" value="magic-link" formNoValidate class={ui.button({ variant: 'outline' })}>
          Email me a sign-in link
        </button>
        <Show when={oauth().length}>
          <div class={ui.separator} />
        </Show>
        <For each={oauth()}>
          {(provider) => (
            <button
              type="submit"
              name="intent"
              value={provider.id}
              formNoValidate
              class={ui.button({ variant: 'outline' })}>
              Continue with {provider.id.replace('oauth:', '')}
            </button>
          )}
        </For>
      </form>
    </AuthLayout>
  )
}
