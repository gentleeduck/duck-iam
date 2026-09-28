<script lang="ts">
  import * as ui from '@examples/duck-auth-ui/recipes'
  import { api } from '../api'
  import AuthLayout from '../components/AuthLayout.svelte'
  import FormNotice from '../components/FormNotice.svelte'
  import { createSubmit } from '../submit.svelte'

  const token = new URLSearchParams(location.search).get('token') ?? ''
  const submit = createSubmit(() => api.verifyEmail(token))
</script>

<AuthLayout title="Verify your email" description="Confirm this address belongs to you.">
  <form class="grid gap-4" onsubmit={submit.onsubmit}>
    <FormNotice res={submit.res} done="Your email is verified." />
    <button type="submit" class={ui.button()} disabled={submit.pending}>Verify email</button>
  </form>
  {#snippet footer()}
    <a href="/" class="text-foreground">Go to the dashboard</a>
  {/snippet}
</AuthLayout>
