<script lang="ts">
  import * as ui from '@examples/duck-auth-ui/recipes'
  import type { Snippet } from 'svelte'
  import BackendPicker from './BackendPicker.svelte'

  let { title, description, children, footer }: { title: string; description: string; children: Snippet; footer?: Snippet } =
    $props()
</script>

<svelte:head><title>{title} · duck-auth · Svelte</title></svelte:head>

<main class="flex min-h-svh flex-col items-center justify-center gap-6 p-6">
  <div class={[ui.card.root, 'w-full max-w-sm']}>
    <div class={ui.card.header}>
      <h1 class={[ui.card.title, 'text-xl']}>{title}</h1>
      <div class={ui.card.description}>{description}</div>
    </div>
    <div class={ui.card.content}>{@render children()}</div>
    {#if footer}
      <div class={[ui.card.footer, 'justify-center text-muted-foreground text-sm']}>{@render footer()}</div>
    {/if}
  </div>
  <BackendPicker />
</main>
