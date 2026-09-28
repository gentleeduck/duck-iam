<script setup lang="ts">
import { type Account, leaveTo } from '@examples/duck-auth-ui/api'
import * as ui from '@examples/duck-auth-ui/recipes'
import { useAuthSignOut } from '@gentleduck/auth/client/vue'
import { onMounted, shallowRef } from 'vue'
import { api } from '../api'
import AccountCard from '../components/AccountCard.vue'
import BackendPicker from '../components/BackendPicker.vue'
import SessionsCard from '../components/SessionsCard.vue'
import TwoFactorCard from '../components/TwoFactorCard.vue'

document.title = 'Dashboard · duck-auth · Vue'
const signOut = useAuthSignOut()
const account = shallowRef<Account | null>(null)

onMounted(async () => {
  const res = await api.account()
  if (res.ok) account.value = res.data
  else location.assign(leaveTo(res.error.code))
})

async function onSignOut() {
  if ((await signOut.mutate()).ok) location.assign('/sign-in')
}
</script>

<template>
  <div v-if="account" class="min-h-svh">
    <header class="flex items-center justify-between border-b px-6 py-3">
      <span class="font-semibold">duck-auth</span>
      <div class="flex items-center gap-3">
        <BackendPicker />
        <button type="button" :class="ui.button({ variant: 'outline', size: 'sm' })" :disabled="signOut.loading.value" @click="onSignOut">
          Sign out
        </button>
      </div>
    </header>
    <main class="mx-auto grid max-w-2xl gap-6 p-6">
      <h1 class="font-semibold text-2xl">Hello, {{ account.identity.profile.name }}</h1>
      <AccountCard :account="account" />
      <TwoFactorCard :enabled="account.totp" />
      <SessionsCard :session="account.session" />
    </main>
  </div>
</template>
