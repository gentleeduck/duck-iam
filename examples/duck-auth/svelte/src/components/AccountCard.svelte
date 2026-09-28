<script lang="ts">
  import type { Account } from '@examples/duck-auth-ui/api'
  import * as ui from '@examples/duck-auth-ui/recipes'
  import type { Envelope } from '@gentleduck/auth/client/vanilla'
  import { api } from '../api'
  import FormNotice from './FormNotice.svelte'

  let { account }: { account: Account } = $props()
  let res = $state<Envelope<unknown> | null>(null)
  let pending = $state(false)
  const { profile, emailVerified } = $derived(account.identity)
</script>

<div class={ui.card.root}>
  <div class={ui.card.header}>
    <div class={ui.card.title}>Account</div>
    <div class={ui.card.description}>{profile.email}</div>
  </div>
  <div class={[ui.card.content, 'grid gap-4']}>
    <div class="flex items-center justify-between gap-4">
      <span class={ui.badge({ variant: emailVerified ? 'secondary' : 'warning' })}>
        {emailVerified ? 'Email verified' : 'Email not verified'}
      </span>
      {#if !emailVerified}
        <button
          type="button"
          class={ui.button({ variant: 'outline', size: 'sm' })}
          disabled={pending}
          onclick={async () => {
            pending = true
            res = await api.resendVerification()
            pending = false
          }}
        >
          Resend the link
        </button>
      {/if}
    </div>
    <FormNotice {res} done="A new link is in the backend's terminal." />
  </div>
</div>
