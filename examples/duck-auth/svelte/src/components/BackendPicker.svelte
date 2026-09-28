<script lang="ts">
  import { BACKENDS, pickBackend, pickedBackend } from '@examples/duck-auth-ui/api'
  import * as ui from '@examples/duck-auth-ui/recipes'
</script>

<select aria-label="Backend" class={ui.select} value={pickedBackend()} onchange={(event) => pickBackend(event.currentTarget.value)}>
  {#each Object.keys(BACKENDS) as name (name)}
    <option value={name}>{name}</option>
  {/each}
</select>
