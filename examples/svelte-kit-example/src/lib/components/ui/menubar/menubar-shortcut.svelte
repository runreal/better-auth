<script lang="ts">
import { cn } from "$lib/utils.js";
import type { HTMLAttributes } from "svelte/elements";

type $$Props = HTMLAttributes<HTMLSpanElement>;
let className: $$Props["class"] = undefined;
export { className as class };
</script>

<span
	class={cn("text-muted-foreground ml-auto text-xs tracking-widest", className)}
	{...$$restProps}
>
	<slot />
</span>
