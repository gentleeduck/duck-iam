<script setup lang="ts">
import { landedWith, type Provider } from '@examples/duck-auth-ui/api'
import * as ui from '@examples/duck-auth-ui/recipes'
import { useAuthClient, useAuthSignIn } from '@gentleduck/auth/client/vue'
import { onMounted, shallowRef } from 'vue'
import { api } from '../api'
import AuthLayout from '../components/AuthLayout.vue'
import FormField from '../components/FormField.vue'
import FormNotice from '../components/FormNotice.vue'
import { useSubmit } from '../submit'

const client = useAuthClient()
const signIn = useAuthSignIn()
const oauth = shallowRef<Provider[]>([])

onMounted(async () => {
  const res = await api.providers()
  if (res.ok) oauth.value = res.data.providers.filter((provider) => provider.kind === 'oauth')
})

const landed = landedWith(new URLSearchParams(location.search).get('error'))

const submit = useSubmit(async (form) => {
  const email = form.get('email')
  const intent = form.get('intent')
  if (intent === 'magic-link') return client.beginProvider('magic-link', { email })
  if (typeof intent === 'string') {
    // The page is on its way to the IdP once this succeeds, so only a failure has anything to show.
    const res = await client.beginProvider(intent)
    return res.ok ? null : res
  }
  const res = await signIn.mutate({ providerId: 'password', input: { email, password: form.get('password') } })
  if (!res.ok) return res
  location.assign('/')
  return null
})
</script>

<template>
  <AuthLayout title="Sign in" description="Welcome back.">
    <form class="grid gap-4" @submit.prevent="submit.onSubmit">
      <FormField label="Email" name="email" type="email" autocomplete="email" />
      <FormField label="Password" name="password" type="password" autocomplete="current-password" />
      <a href="/forgot-password" class="text-muted-foreground text-sm">Forgot your password?</a>
      <FormNotice :res="submit.res ?? landed" done="Your sign-in link is in the backend's terminal." />
      <button type="submit" :class="ui.button()" :disabled="submit.pending">Sign in</button>
      <button type="submit" name="intent" value="magic-link" formnovalidate :class="ui.button({ variant: 'outline' })">
        Email me a sign-in link
      </button>
      <div v-if="oauth.length" :class="ui.separator" />
      <button
        v-for="provider in oauth"
        :key="provider.id"
        type="submit"
        name="intent"
        :value="provider.id"
        formnovalidate
        :class="ui.button({ variant: 'outline' })"
      >
        Continue with {{ provider.id.replace('oauth:', '') }}
      </button>
    </form>
    <template #footer>
      No account?
      <a href="/sign-up" class="text-foreground">Sign up</a>
    </template>
  </AuthLayout>
</template>
