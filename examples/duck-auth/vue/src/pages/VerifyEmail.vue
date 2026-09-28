<script setup lang="ts">
import * as ui from '@examples/duck-auth-ui/recipes'
import { api } from '../api'
import AuthLayout from '../components/AuthLayout.vue'
import FormNotice from '../components/FormNotice.vue'
import { useSubmit } from '../submit'

const token = new URLSearchParams(location.search).get('token') ?? ''
const submit = useSubmit(() => api.verifyEmail(token))
</script>

<template>
  <AuthLayout title="Verify your email" description="Confirm this address belongs to you.">
    <form class="grid gap-4" @submit.prevent="submit.onSubmit">
      <FormNotice :res="submit.res" done="Your email is verified." />
      <button type="submit" :class="ui.button()" :disabled="submit.pending">Verify email</button>
    </form>
    <template #footer>
      <a href="/" class="text-foreground">Go to the dashboard</a>
    </template>
  </AuthLayout>
</template>
