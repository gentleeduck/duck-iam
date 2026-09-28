<script lang="ts">
  import * as ui from '@examples/duck-auth-ui/recipes'
  import { auth } from '../auth'
  import AuthLayout from '../components/AuthLayout.svelte'
  import FormNotice from '../components/FormNotice.svelte'
  import { createSubmit } from '../submit.svelte'

  const token = new URLSearchParams(location.search).get('token') ?? ''
  const submit = createSubmit(async () => {
    const res = await auth.signIn({ providerId: 'magic-link', input: { token } })
    if (!res.ok) return res
    location.assign('/')
    return null
  })
</script>

<AuthLayout title="Sign in with your link" description="The link works once and expires soon.">
  <form class="grid gap-4" onsubmit={submit.onsubmit}>
    <FormNotice res={submit.res} />
    <button type="submit" class={ui.button()} disabled={submit.pending}>Sign me in</button>
  </form>
</AuthLayout>
