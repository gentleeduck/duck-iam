<script setup lang="ts">
import { BACKENDS, pickBackend, pickedBackend } from '@examples/duck-auth-ui/api'
import * as ui from '@examples/duck-auth-ui/recipes'

function onChange(event: Event) {
  if (event.target instanceof HTMLSelectElement) pickBackend(event.target.value)
}
</script>

<template>
  <select aria-label="Backend" :class="ui.select" :value="pickedBackend()" @change="onChange">
    <option v-for="name in Object.keys(BACKENDS)" :key="name" :value="name">{{ name }}</option>
  </select>
</template>
