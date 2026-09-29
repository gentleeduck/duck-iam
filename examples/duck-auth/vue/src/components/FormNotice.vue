<script setup lang="ts">
import { type Envelope, errorText } from '@examples/duck-auth-ui/api'
import * as ui from '@examples/duck-auth-ui/recipes'

// The last answer: a failure as an alert, a success as `done` when there is one to say.
defineProps<{ res: Envelope<unknown> | null; done?: string; invalid?: string }>()
</script>

<template>
  <div v-if="res && (!res.ok || done)" role="alert" :class="ui.alert({ variant: res.ok ? 'default' : 'destructive' })">
    <p :class="ui.alertDescription">{{ res.ok ? done : errorText(res, invalid) }}</p>
  </div>
</template>
