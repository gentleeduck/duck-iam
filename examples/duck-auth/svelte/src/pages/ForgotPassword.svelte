<script lang="ts">
  import * as ui from '@examples/duck-auth-ui/recipes'
  import { api } from '../api'
  import AuthLayout from '../components/AuthLayout.svelte'
  import FormField from '../components/FormField.svelte'
  import FormNotice from '../components/FormNotice.svelte'
  import { createSubmit } from '../submit.svelte'

  const submit = createSubmit((form) => api.forgotPassword(String(form.get('email'))))
</script>

<AuthLayout title="Reset your password" description="We will send a reset link to your email.">
  <form class="grid gap-4" onsubmit={submit.onsubmit}>
    <FormField label="Email" name="email" type="email" autocomplete="email" />
    <FormNotice res={submit.res} done="If that email has an account, its reset link is in the backend's terminal." />
    <button type="submit" class={ui.button()} disabled={submit.pending}>Send reset link</button>
  </form>
  {#snippet footer()}
    <a href="/sign-in" class="text-foreground">Back to sign in</a>
  {/snippet}
</AuthLayout>
