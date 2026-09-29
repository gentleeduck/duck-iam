<script lang="ts">
  import { landedWith, type Provider } from '@examples/duck-auth-ui/api'
  import * as ui from '@examples/duck-auth-ui/recipes'
  import { onMount } from 'svelte'
  import { api } from '../api'
  import AuthLayout from '../components/AuthLayout.svelte'
  import FormField from '../components/FormField.svelte'
  import FormNotice from '../components/FormNotice.svelte'
  import { createSubmit } from '../submit.svelte'

  let oauth = $state<Provider[]>([])

  onMount(async () => {
    const res = await api.providers()
    if (res.ok) oauth = res.data.providers.filter((provider) => provider.kind === 'oauth')
  })

  const landed = landedWith(new URLSearchParams(location.search).get('error'))

  const submit = createSubmit(async (form) => {
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
</script>

<AuthLayout title="Sign in" description="Welcome back.">
  <form class="grid gap-4" onsubmit={submit.onsubmit}>
    <FormField label="Email" name="email" type="email" autocomplete="email" />
    <FormField label="Password" name="password" type="password" autocomplete="current-password" />
    <a href="/forgot-password" class="text-muted-foreground text-sm">Forgot your password?</a>
    <FormNotice res={submit.res ?? landed} done="Your sign-in link is in the backend's terminal." />
    <button type="submit" class={ui.button()} disabled={submit.pending}>Sign in</button>
    <button type="submit" name="intent" value="magic-link" formnovalidate class={ui.button({ variant: 'outline' })}>
      Email me a sign-in link
    </button>
    {#if oauth.length}
      <div class={ui.separator}></div>
    {/if}
    {#each oauth as provider (provider.id)}
      <button type="submit" name="intent" value={provider.id} formnovalidate class={ui.button({ variant: 'outline' })}>
        Continue with {provider.id.replace('oauth:', '')}
      </button>
    {/each}
  </form>
  {#snippet footer()}
    No account?
    <a href="/sign-up" class="text-foreground">Sign up</a>
  {/snippet}
</AuthLayout>
