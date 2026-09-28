<script setup lang="ts">
import * as ui from '@examples/duck-auth-ui/recipes'
import { api } from '../api'
import AuthLayout from '../components/AuthLayout.vue'
import FormField from '../components/FormField.vue'
import FormNotice from '../components/FormNotice.vue'
import { useSubmit } from '../submit'

const submit = useSubmit((form) => api.forgotPassword(String(form.get('email'))))
</script>

<template>
  <AuthLayout title="Reset your password" description="We will send a reset link to your email.">
    <form class="grid gap-4" @submit.prevent="submit.onSubmit">
      <FormField label="Email" name="email" type="email" autocomplete="email" />
      <FormNotice :res="submit.res" done="If that email has an account, its reset link is in the backend's terminal." />
      <button type="submit" :class="ui.button()" :disabled="submit.pending">Send reset link</button>
    </form>
    <template #footer>
      <a href="/sign-in" class="text-foreground">Back to sign in</a>
    </template>
  </AuthLayout>
</template>
