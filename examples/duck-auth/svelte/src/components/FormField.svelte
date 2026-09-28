<script lang="ts">
  import * as ui from '@examples/duck-auth-ui/recipes'
  import type { HTMLInputAttributes } from 'svelte/elements'

  let { label, name, ...rest }: { label: string; name: string } & HTMLInputAttributes = $props()
</script>

<div class="grid gap-2">
  <label for={name} class={ui.label}>{label}</label>
  <input id={name} {name} required class={ui.input} {...rest} />
</div>
