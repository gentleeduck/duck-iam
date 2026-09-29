<script lang="ts">
  import { type Account, leaveTo } from '@examples/duck-auth-ui/api'
  import * as ui from '@examples/duck-auth-ui/recipes'
  import { onMount } from 'svelte'
  import { api } from '../api'
  import AccountCard from '../components/AccountCard.svelte'
  import BackendPicker from '../components/BackendPicker.svelte'
  import SessionsCard from '../components/SessionsCard.svelte'
  import TwoFactorCard from '../components/TwoFactorCard.svelte'

  let account = $state<Account | null>(null)

  onMount(async () => {
    const res = await api.account()
    if (res.ok) account = res.data
    else location.assign(leaveTo(res.error.code))
  })

  async function signOut() {
    if ((await api.signOut()).ok) location.assign('/sign-in')
  }
</script>

<svelte:head><title>Dashboard · duck-auth · Svelte</title></svelte:head>

{#if account}
  <div class="min-h-svh">
    <header class="flex items-center justify-between border-b px-6 py-3">
      <span class="font-semibold">duck-auth</span>
      <div class="flex items-center gap-3">
        <BackendPicker />
        <button type="button" class={ui.button({ variant: 'outline', size: 'sm' })} onclick={signOut}>Sign out</button>
      </div>
    </header>
    <main class="mx-auto grid max-w-2xl gap-6 p-6">
      <h1 class="font-semibold text-2xl">Hello, {account.identity.profile.name}</h1>
      <AccountCard {account} />
      <TwoFactorCard enabled={account.totp} />
      <SessionsCard session={account.session} />
    </main>
  </div>
{/if}
