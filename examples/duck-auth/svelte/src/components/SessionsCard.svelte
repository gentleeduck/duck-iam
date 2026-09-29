<script lang="ts">
  import { type Account, type Envelope, type Session, sessionLine } from '@examples/duck-auth-ui/api'
  import * as ui from '@examples/duck-auth-ui/recipes'
  import { onMount } from 'svelte'
  import { api } from '../api'
  import FormNotice from './FormNotice.svelte'

  let { session }: { session: Account['session'] } = $props()
  let sessions = $state<Session[]>([])
  let res = $state<Envelope<{ revoked: number }> | null>(null)
  let pending = $state(false)

  onMount(async () => {
    const answer = await api.sessions()
    if (answer.ok) sessions = answer.data.sessions
  })

  async function signOutOthers() {
    pending = true
    res = await api.signOutOthers()
    pending = false
    if (res.ok) sessions = sessions.filter((s) => s.id === session.id)
  }
</script>

<div class={ui.card.root}>
  <div class={ui.card.header}>
    <div class={ui.card.title}>Sessions</div>
    <div class={ui.card.description}>
      This one is at level {session.aal} and ends {new Date(session.expiresAt).toLocaleString()}.
    </div>
  </div>
  <div class={[ui.card.content, 'grid gap-4']}>
    <ul class="grid gap-2 text-sm">
      {#each sessions as s (s.id)}
        <li class="flex items-center justify-between gap-4">
          {sessionLine(s)}
          {#if s.id === session.id}
            <span class={ui.badge({ variant: 'secondary' })}>This device</span>
          {/if}
        </li>
      {/each}
    </ul>
    <button
      type="button"
      class={[ui.button({ variant: 'outline' }), 'w-fit']}
      disabled={pending || sessions.length < 2}
      onclick={signOutOthers}>
      Sign out other devices
    </button>
    <FormNotice {res} done={res?.ok ? `Signed out ${res.data.revoked}.` : undefined} />
  </div>
</div>
