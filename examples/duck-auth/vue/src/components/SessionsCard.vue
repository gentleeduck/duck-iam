<script setup lang="ts">
import { type Account, type Envelope, type Session, sessionLine } from '@examples/duck-auth-ui/api'
import * as ui from '@examples/duck-auth-ui/recipes'
import { onMounted, shallowRef } from 'vue'
import { api } from '../api'
import FormNotice from './FormNotice.vue'

const props = defineProps<{ session: Account['session'] }>()
const sessions = shallowRef<Session[]>([])
const res = shallowRef<Envelope<{ revoked: number }> | null>(null)
const pending = shallowRef(false)

onMounted(async () => {
  const answer = await api.sessions()
  if (answer.ok) sessions.value = answer.data.sessions
})

async function signOutOthers() {
  pending.value = true
  res.value = await api.signOutOthers()
  pending.value = false
  if (res.value.ok) sessions.value = sessions.value.filter((s) => s.id === props.session.id)
}
</script>

<template>
  <div :class="ui.card.root">
    <div :class="ui.card.header">
      <div :class="ui.card.title">Sessions</div>
      <div :class="ui.card.description">
        This one is at level {{ session.aal }} and ends {{ new Date(session.expiresAt).toLocaleString() }}.
      </div>
    </div>
    <div :class="[ui.card.content, 'grid gap-4']">
      <ul class="grid gap-2 text-sm">
        <li v-for="s in sessions" :key="s.id" class="flex items-center justify-between gap-4">
          {{ sessionLine(s) }}
          <span v-if="s.id === session.id" :class="ui.badge({ variant: 'secondary' })">This device</span>
        </li>
      </ul>
      <button
        type="button"
        :class="[ui.button({ variant: 'outline' }), 'w-fit']"
        :disabled="pending || sessions.length < 2"
        @click="signOutOthers">
        Sign out other devices
      </button>
      <FormNotice :res="res" :done="res?.ok ? `Signed out ${res.data.revoked}.` : undefined" />
    </div>
  </div>
</template>
