<script lang="ts">
  import { WEAK_PASSWORD } from '@examples/duck-auth-ui/api'
  import * as ui from '@examples/duck-auth-ui/recipes'
  import { auth } from '../auth'
  import AuthLayout from '../components/AuthLayout.svelte'
  import FormField from '../components/FormField.svelte'
  import FormNotice from '../components/FormNotice.svelte'
  import { createSubmit } from '../submit.svelte'

  const submit = createSubmit((form) =>
    auth.client.signUp({ name: form.get('name'), email: form.get('email'), password: form.get('password') }),
  )
</script>

<AuthLayout title="Create an account" description="Eight characters or more for the password.">
  <form class="grid gap-4" onsubmit={submit.onsubmit}>
    <FormField label="Name" name="name" autocomplete="name" />
    <FormField label="Email" name="email" type="email" autocomplete="email" />
    <FormField label="Password" name="password" type="password" autocomplete="new-password" />
    <FormNotice
      res={submit.res}
      invalid={WEAK_PASSWORD}
      done="Account created. The verification link is in the backend's terminal."
    />
    <button type="submit" class={ui.button()} disabled={submit.pending}>Sign up</button>
  </form>
  {#snippet footer()}
    Have an account?
    <a href="/sign-in" class="text-foreground">Sign in</a>
  {/snippet}
</AuthLayout>
