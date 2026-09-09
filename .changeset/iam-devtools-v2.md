---
'@gentleduck/iam': minor
---

Add a second devtools build, `@gentleduck/iam/dt/v2`, written on duck-ui.

`./dt` and `./dt/v2` are two implementations of the same seven panels with
deliberately opposite dependency contracts, published side by side so a
consumer picks the trade rather than inheriting it:

| | `./dt` | `./dt/v2` |
| --- | --- | --- |
| Styling | own stylesheet, `iam-dt-*` classes, `--iam-dt-*` tokens | duck-ui components on the host's Tailwind theme |
| Peers | none | `@gentleduck/registry-ui`, `@gentleduck/libs`, `lucide-react` (all optional) |
| Looks like | itself, everywhere | whatever the host app looks like |

`./dt` is unchanged and stays self-contained — that is the point of keeping it.
Reach for `./dt/v2` when the host already runs duck-ui and Tailwind v4 and you
want the devtool to inherit its theme; it needs one line in the host stylesheet
so Tailwind scans the shipped panels:

```css
@source "../node_modules/@gentleduck/iam/dist/dt/v2";
```

v2 is a rebuild, not a re-skin. It is assembled from duck-ui's own components
rather than lookalikes — `Alert`, `Avatar`, `Badge`, `Button`, `ButtonGroup`,
`Card`, `Empty`, `Field`, `Input`, `InputGroup`, `Item`, `Kbd`, `Label`,
`Progress`, `ScrollArea`, `Separator`, `Skeleton`, `Switch`, `Table`, `Tabs`,
`Textarea` and `Tooltip` — because a `div` with a border is a card only the
devtool knows about, while a `Card` is one the host's theme can reach. The Flow
log is a real data table, cache and allow rates are real `Progress` bars, the
verdict filters are real `Switch`es, and every toolbar button carries a
`Tooltip`. A contract test names that component set and fails if v2 stops using
one of them or hand-rolls a `<table>` or progress bar instead.

What is deliberately not duck-ui: a new tone system (`lib/tone.ts`) keeps the
five decision colours on a fixed palette while the chrome floats with the host;
tabs get arrow-key roving focus, because `TabsTrigger` does roving `tabIndex`
and no key handling; sections are hand-rolled disclosures inside a `Card`,
because `Collapsible` drives its open state through a DOM attribute and renders
closed on the server; and the dockable shell's resize edge is a real
window-splitter separator — pointer drag plus arrow/Home/End,
`aria-valuemin`/`max`/`now`, Escape to close and focus returned to the
launcher — which `Separator` (an `<hr>`) cannot be.

Every v2 panel calls `isDevtoolsAllowed(engine)` itself, because each is
exported individually; a source sweep in the v2 tests fails any future panel
that reads `engine.` without the guard. A contract test asserts the split from
both sides: v2 really imports duck-ui, is really outside `./dt`'s
self-containment sweep, and carries none of v1's styling layer.
