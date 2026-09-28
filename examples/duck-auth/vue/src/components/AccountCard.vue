<script setup lang="ts">
import type { Account } from '@examples/duck-auth-ui/api'
import * as ui from '@examples/duck-auth-ui/recipes'
import type { Envelope } from '@gentleduck/auth/client/vanilla'
import { shallowRef } from 'vue'
import { api } from '../api'
import FormNotice from './FormNotice.vue'

defineProps<{ account: Account }>()
const res = shallowRef<Envelope<unknown> | null>(null)
const pending = shallowRef(false)

async function resend() {
  pending.value = true
  res.value = await api.resendVerification()
  pending.value = false
}
</script>

<template>
  <div :class="ui.card.root">
    <div :class="ui.card.header">
      <div :class="ui.card.title">Account</div>
      <div :class="ui.card.description">{{ account.identity.profile.email }}</div>
    </div>
    <div :class="[ui.card.content, 'grid gap-4']">
      <div class="flex items-center justify-between gap-4">
        <span :class="ui.badge({ variant: account.identity.emailVerified ? 'secondary' : 'warning' })">
          {{ account.identity.emailVerified ? 'Email verified' : 'Email not verified' }}
        </span>
        <button type="button"
          v-if="!account.identity.emailVerified"
          :class="ui.button({ variant: 'outline', size: 'sm' })"
          :disabled="pending"
          @click="resend"
        >
          Resend the link
        </button>
      </div>
      <FormNotice :res="res" done="A new link is in the backend's terminal." />
    </div>
  </div>
</template>
