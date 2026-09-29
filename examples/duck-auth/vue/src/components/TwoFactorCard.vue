<script setup lang="ts">
import { type Envelope, qrCode } from '@examples/duck-auth-ui/api'
import * as ui from '@examples/duck-auth-ui/recipes'
import { shallowRef } from 'vue'
import { api } from '../api'
import { useSubmit } from '../submit'
import FormField from './FormField.vue'
import FormNotice from './FormNotice.vue'

defineProps<{ enabled: boolean }>()
const res = shallowRef<Envelope<unknown> | null>(null)
const setup = shallowRef<{ secret: string; uri: string } | null>(null)
const codes = shallowRef<string[]>([])
const pending = shallowRef(false)
const confirm = useSubmit(async (form) => {
  const res = await api.confirmTotp(String(form.get('code')).trim())
  if (res.ok) codes.value = res.data.backupCodes
  return res
})

async function run<T>(call: () => Promise<Envelope<T>>, then: (data: T) => void) {
  pending.value = true
  const answer = await call()
  pending.value = false
  if (answer.ok) then(answer.data)
  res.value = answer
}

const reload = () => location.reload()
</script>

<template>
  <div :class="ui.card.root">
    <div :class="ui.card.header">
      <div :class="ui.card.title">Two-factor authentication</div>
      <div :class="ui.card.description">A code from an authenticator app on every sign-in.</div>
    </div>
    <div :class="[ui.card.content, 'grid gap-4']">
      <template v-if="codes.length">
        <p class="text-sm">Save these backup codes. Each one works once.</p>
        <ul class="grid grid-cols-2 gap-2 font-mono text-sm">
          <li v-for="code in codes" :key="code">{{ code }}</li>
        </ul>
        <button type="button" :class="[ui.button(), 'w-fit']" @click="reload">I saved them</button>
      </template>
      <form v-else-if="setup" class="grid gap-4" @submit.prevent="confirm.onSubmit">
        <p class="text-sm">Scan this with an authenticator app, or enter the key below by hand. Then type the code it shows.</p>
        <img :src="qrCode(setup.uri)" alt="The key as a QR code" class="size-40 rounded-md" />
        <code class="block break-all rounded-md bg-muted p-2 font-mono text-sm">{{ setup.secret }}</code>
        <FormField label="Code" name="code" autocomplete="one-time-code" />
        <FormNotice :res="confirm.res" />
        <button type="submit" :class="ui.button()" :disabled="confirm.pending">Turn on</button>
      </form>
      <div v-else-if="enabled" class="flex flex-wrap items-center gap-2">
        <span :class="ui.badge({ variant: 'secondary' })">On</span>
        <button type="button"
          :class="ui.button({ variant: 'outline', size: 'sm' })"
          :disabled="pending"
          @click="run(api.newBackupCodes, (data) => (codes = data.backupCodes))"
        >
          New backup codes
        </button>
        <button type="button" :class="ui.button({ variant: 'destructive', size: 'sm' })" :disabled="pending" @click="run(api.removeTotp, reload)">
          Turn off
        </button>
      </div>
      <button type="button" v-else :class="[ui.button(), 'w-fit']" :disabled="pending" @click="run(api.beginTotp, (data) => (setup = data))">Set up</button>
      <FormNotice :res="res" />
    </div>
  </div>
</template>
