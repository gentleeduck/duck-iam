<script lang="ts">
  import { errorText } from '@examples/duck-auth-ui/api'
  import * as ui from '@examples/duck-auth-ui/recipes'
  import type { Envelope } from '@gentleduck/auth/client/vanilla'

  // The last answer: a failure as an alert, a success as `done` when there is one to say.
  let { res, done, invalid }: { res: Envelope<unknown> | null; done?: string; invalid?: string } = $props()
</script>

{#if res && (!res.ok || done)}
  <div role="alert" class={ui.alert({ variant: res.ok ? 'default' : 'destructive' })}>
    <p class={ui.alertDescription}>{res.ok ? done : errorText(res, invalid)}</p>
  </div>
{/if}
