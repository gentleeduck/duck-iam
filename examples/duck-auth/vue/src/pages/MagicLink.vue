<script setup lang="ts">
import * as ui from '@examples/duck-auth-ui/recipes'
import { useAuthSignIn } from '@gentleduck/auth/client/vue'
import AuthLayout from '../components/AuthLayout.vue'
import FormNotice from '../components/FormNotice.vue'
import { useSubmit } from '../submit'

const signIn = useAuthSignIn()
const token = new URLSearchParams(location.search).get('token') ?? ''
const submit = useSubmit(async () => {
  const res = await signIn.mutate({ providerId: 'magic-link', input: { token } })
  if (!res.ok) return res
  location.assign('/')
  return null
})
</script>

<template>
  <AuthLayout title="Sign in with your link" description="The link works once and expires soon.">
    <form class="grid gap-4" @submit.prevent="submit.onSubmit">
      <FormNotice :res="submit.res" />
      <button type="submit" :class="ui.button()" :disabled="submit.pending">Sign me in</button>
    </form>
  </AuthLayout>
</template>
