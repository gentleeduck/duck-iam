<script lang="ts">
  import * as ui from '@examples/duck-auth-ui/recipes'
  import { api } from '../api'
  import { auth } from '../auth'
  import AuthLayout from '../components/AuthLayout.svelte'
  import FormField from '../components/FormField.svelte'
  import FormNotice from '../components/FormNotice.svelte'
  import { createSubmit } from '../submit.svelte'

  const submit = createSubmit(async (form) => {
    const res = await api.verifyMfa(String(form.get('code')).trim())
    if (!res.ok) return res
    location.assign('/')
    return null
  })

  async function switchAccount() {
    await auth.signOut()
    location.assign('/sign-in')
  }
</script>

<AuthLayout title="Two-factor check" description="Enter the code from your authenticator app, or one of your backup codes.">
  <form class="grid gap-4" onsubmit={submit.onsubmit}>
    <FormField label="Code" name="code" autocomplete="one-time-code" />
    <FormNotice res={submit.res} />
    <button type="submit" class={ui.button()} disabled={submit.pending}>Verify</button>
  </form>
  {#snippet footer()}
    <button type="button" class={ui.button({ variant: 'link', size: 'sm' })} onclick={switchAccount}>Use another account</button>
  {/snippet}
</AuthLayout>
