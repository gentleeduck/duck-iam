<script setup lang="ts">
import { WEAK_PASSWORD } from '@examples/duck-auth-ui/api'
import * as ui from '@examples/duck-auth-ui/recipes'
import { api } from '../api'
import AuthLayout from '../components/AuthLayout.vue'
import FormField from '../components/FormField.vue'
import FormNotice from '../components/FormNotice.vue'
import { useSubmit } from '../submit'

const token = new URLSearchParams(location.search).get('token') ?? ''
const submit = useSubmit((form) => api.resetPassword(token, String(form.get('password'))))
</script>

<template>
  <AuthLayout title="Choose a new password" description="Every signed-in device is signed out once it changes.">
    <form class="grid gap-4" @submit.prevent="submit.onSubmit">
      <FormField label="New password" name="password" type="password" autocomplete="new-password" />
      <FormNotice :res="submit.res" :invalid="WEAK_PASSWORD" done="Password changed. Sign in with the new one." />
      <button type="submit" :class="ui.button()" :disabled="submit.pending">Change password</button>
    </form>
    <template #footer>
      <a href="/sign-in" class="text-foreground">Back to sign in</a>
    </template>
  </AuthLayout>
</template>
