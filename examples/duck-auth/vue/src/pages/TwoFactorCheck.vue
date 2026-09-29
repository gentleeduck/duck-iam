<script setup lang="ts">
import * as ui from '@examples/duck-auth-ui/recipes'
import { api } from '../api'
import AuthLayout from '../components/AuthLayout.vue'
import FormField from '../components/FormField.vue'
import FormNotice from '../components/FormNotice.vue'
import { useSubmit } from '../submit'

const submit = useSubmit(async (form) => {
  const res = await api.verifyMfa(String(form.get('code')).trim())
  if (!res.ok) return res
  location.assign('/')
  return null
})

async function switchAccount() {
  await api.signOut()
  location.assign('/sign-in')
}
</script>

<template>
  <AuthLayout
    title="Two-factor check"
    description="Enter the code from your authenticator app, or one of your backup codes."
  >
    <form class="grid gap-4" @submit.prevent="submit.onSubmit">
      <FormField label="Code" name="code" autocomplete="one-time-code" />
      <FormNotice :res="submit.res" />
      <button type="submit" :class="ui.button()" :disabled="submit.pending">Verify</button>
    </form>
    <template #footer>
      <button type="button" :class="ui.button({ variant: 'link', size: 'sm' })" @click="switchAccount">Use another account</button>
    </template>
  </AuthLayout>
</template>
