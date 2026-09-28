<script setup lang="ts">
import * as ui from '@examples/duck-auth-ui/recipes'
import BackendPicker from './BackendPicker.vue'

const props = defineProps<{ title: string; description: string }>()
document.title = `${props.title} · duck-auth · Vue`
</script>

<template>
  <main class="flex min-h-svh flex-col items-center justify-center gap-6 p-6">
    <div :class="[ui.card.root, 'w-full max-w-sm']">
      <div :class="ui.card.header">
        <h1 :class="[ui.card.title, 'text-xl']">{{ title }}</h1>
        <div :class="ui.card.description">{{ description }}</div>
      </div>
      <div :class="ui.card.content"><slot /></div>
      <div v-if="$slots.footer" :class="[ui.card.footer, 'justify-center text-muted-foreground text-sm']">
        <slot name="footer" />
      </div>
    </div>
    <BackendPicker />
  </main>
</template>
