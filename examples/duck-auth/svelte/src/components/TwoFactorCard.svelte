<script lang="ts">
  import { qrCode } from '@examples/duck-auth-ui/api'
  import * as ui from '@examples/duck-auth-ui/recipes'
  import type { Envelope } from '@gentleduck/auth/client/vanilla'
  import { api } from '../api'
  import { createSubmit } from '../submit.svelte'
  import FormField from './FormField.svelte'
  import FormNotice from './FormNotice.svelte'

  let { enabled }: { enabled: boolean } = $props()
  let res = $state<Envelope<unknown> | null>(null)
  let setup = $state<{ secret: string; uri: string } | null>(null)
  let codes = $state<string[]>([])
  let pending = $state(false)
  const confirm = createSubmit(async (form) => {
    const answer = await api.confirmTotp(String(form.get('code')).trim())
    if (answer.ok) codes = answer.data.backupCodes
    return answer
  })

  async function run<T>(call: () => Promise<Envelope<T>>, then: (data: T) => void) {
    pending = true
    const answer = await call()
    pending = false
    if (answer.ok) then(answer.data)
    res = answer
  }

  const reload = () => location.reload()
</script>

<div class={ui.card.root}>
  <div class={ui.card.header}>
    <div class={ui.card.title}>Two-factor authentication</div>
    <div class={ui.card.description}>A code from an authenticator app on every sign-in.</div>
  </div>
  <div class={[ui.card.content, 'grid gap-4']}>
    {#if codes.length}
      <p class="text-sm">Save these backup codes. Each one works once.</p>
      <ul class="grid grid-cols-2 gap-2 font-mono text-sm">
        {#each codes as code (code)}
          <li>{code}</li>
        {/each}
      </ul>
      <button type="button" class={[ui.button(), 'w-fit']} onclick={reload}>I saved them</button>
    {:else if setup}
      <form class="grid gap-4" onsubmit={confirm.onsubmit}>
        <p class="text-sm">Scan this with an authenticator app, or enter the key below by hand. Then type the code it shows.</p>
        <img src={qrCode(setup.uri)} alt="The key as a QR code" class="size-40 rounded-md" />
        <code class="block break-all rounded-md bg-muted p-2 font-mono text-sm">{setup.secret}</code>
        <FormField label="Code" name="code" autocomplete="one-time-code" />
        <FormNotice res={confirm.res} />
        <button type="submit" class={ui.button()} disabled={confirm.pending}>Turn on</button>
      </form>
    {:else if enabled}
      <div class="flex flex-wrap items-center gap-2">
        <span class={ui.badge({ variant: 'secondary' })}>On</span>
        <button
          type="button"
          class={ui.button({ variant: 'outline', size: 'sm' })}
          disabled={pending}
          onclick={() => run(api.newBackupCodes, (data) => (codes = data.backupCodes))}
        >
          New backup codes
        </button>
        <button type="button" class={ui.button({ variant: 'destructive', size: 'sm' })} disabled={pending} onclick={() => run(api.removeTotp, reload)}>
          Turn off
        </button>
      </div>
    {:else}
      <button type="button" class={[ui.button(), 'w-fit']} disabled={pending} onclick={() => run(api.beginTotp, (data) => (setup = data))}>
        Set up
      </button>
    {/if}
    <FormNotice {res} />
  </div>
</div>
