<script setup lang="ts">
import * as ui from '@examples/duck-auth-ui/recipes'

defineOptions({ inheritAttrs: false })
defineProps<{ label: string; name: string }>()
</script>

<template>
  <div class="grid gap-2">
    <label :for="name" :class="ui.label">{{ label }}</label>
    <input :id="name" :name="name" required :class="ui.input" v-bind="$attrs" />
  </div>
</template>
