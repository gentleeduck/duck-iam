import React from 'react'

const STYLE_ID = '__iam_dt_styles__'

/**
 * The devtools' whole visual layer, scoped under `.iam-dt`; hosts restyle via `:root .iam-dt { --iam-dt-*: ... }`.
 * NOTE: never read host CSS vars or Tailwind here - consumers of `./dt` may have neither.
 */
const CSS = `
/* Tokens land on the outermost \`.iam-dt\` only. Every panel carries the class,
   because \`package.json\` exports each one individually and a panel mounted on
   its own is its own root - but nested inside \`IamDevtools\` a second token
   block would re-derive the theme from \`prefers-color-scheme\` and quietly
   overrule the explicit \`theme\` the root was given. \`:not(.iam-dt *)\` says
   "no \`.iam-dt\` above me", which is exactly the condition for being a root. */
.iam-dt:not(.iam-dt *) {
  --iam-dt-bg: #0d1117;
  --iam-dt-surface: #161b22;
  --iam-dt-surface-2: #21262d;
  --iam-dt-border: #30363d;
  --iam-dt-border-subtle: #21262d;
  --iam-dt-fg: #e6edf3;
  --iam-dt-fg-muted: #9198a1;
  --iam-dt-fg-subtle: #6e7681;
  --iam-dt-accent: #58a6ff;
  --iam-dt-accent-soft: rgba(88, 166, 255, 0.14);
  --iam-dt-ring: #58a6ff;
  --iam-dt-allow: #3fb950;
  --iam-dt-allow-soft: rgba(63, 185, 80, 0.14);
  --iam-dt-deny: #f85149;
  --iam-dt-deny-soft: rgba(248, 81, 73, 0.14);
  --iam-dt-warn: #d29922;
  --iam-dt-warn-soft: rgba(210, 153, 34, 0.14);
  --iam-dt-action: #79c0ff;
  --iam-dt-resource: #ffa657;
  --iam-dt-string: #7ee787;
  --iam-dt-number: #ffa657;
  --iam-dt-bool: #79c0ff;
  --iam-dt-shadow: 0 16px 48px rgba(1, 4, 9, 0.55);
  --iam-dt-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  --iam-dt-sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  color-scheme: dark;
}

@media (prefers-color-scheme: light) {
  .iam-dt:not(.iam-dt *):not([data-iam-dt-theme="dark"]) {
    --iam-dt-bg: #ffffff;
    --iam-dt-surface: #f6f8fa;
    --iam-dt-surface-2: #eaeef2;
    --iam-dt-border: #d1d9e0;
    --iam-dt-border-subtle: #e4e8ec;
    --iam-dt-fg: #1f2328;
    --iam-dt-fg-muted: #59636e;
    --iam-dt-fg-subtle: #818b98;
    --iam-dt-accent: #0969da;
    --iam-dt-accent-soft: rgba(9, 105, 218, 0.1);
    --iam-dt-ring: #0969da;
    --iam-dt-allow: #1a7f37;
    --iam-dt-allow-soft: rgba(26, 127, 55, 0.1);
    --iam-dt-deny: #cf222e;
    --iam-dt-deny-soft: rgba(207, 34, 46, 0.1);
    --iam-dt-warn: #9a6700;
    --iam-dt-warn-soft: rgba(154, 103, 0, 0.1);
    --iam-dt-action: #0550ae;
    --iam-dt-resource: #953800;
    --iam-dt-string: #0a3069;
    --iam-dt-number: #953800;
    --iam-dt-bool: #0550ae;
    --iam-dt-shadow: 0 16px 48px rgba(31, 35, 40, 0.16);
    color-scheme: light;
  }
}

.iam-dt:not(.iam-dt *)[data-iam-dt-theme="light"] {
  --iam-dt-bg: #ffffff;
  --iam-dt-surface: #f6f8fa;
  --iam-dt-surface-2: #eaeef2;
  --iam-dt-border: #d1d9e0;
  --iam-dt-border-subtle: #e4e8ec;
  --iam-dt-fg: #1f2328;
  --iam-dt-fg-muted: #59636e;
  --iam-dt-fg-subtle: #818b98;
  --iam-dt-accent: #0969da;
  --iam-dt-accent-soft: rgba(9, 105, 218, 0.1);
  --iam-dt-ring: #0969da;
  --iam-dt-allow: #1a7f37;
  --iam-dt-allow-soft: rgba(26, 127, 55, 0.1);
  --iam-dt-deny: #cf222e;
  --iam-dt-deny-soft: rgba(207, 34, 46, 0.1);
  --iam-dt-warn: #9a6700;
  --iam-dt-warn-soft: rgba(154, 103, 0, 0.1);
  --iam-dt-action: #0550ae;
  --iam-dt-resource: #953800;
  --iam-dt-string: #0a3069;
  --iam-dt-number: #953800;
  --iam-dt-bool: #0550ae;
  --iam-dt-shadow: 0 16px 48px rgba(31, 35, 40, 0.16);
  color-scheme: light;
}

/* Reset. Scoped to the subtree so the host page is untouched, and broad enough
   that a host's own element selectors cannot reach in and reshape a control. */
.iam-dt, .iam-dt *, .iam-dt *::before, .iam-dt *::after { box-sizing: border-box; }
.iam-dt {
  font-family: var(--iam-dt-sans);
  font-size: 12px;
  line-height: 1.45;
  color: var(--iam-dt-fg);
  -webkit-font-smoothing: antialiased;
  text-align: left;
}
.iam-dt button, .iam-dt input, .iam-dt textarea, .iam-dt select {
  font: inherit; color: inherit; margin: 0;
}
.iam-dt button { background: none; border: none; padding: 0; cursor: pointer; }
.iam-dt button:disabled { cursor: not-allowed; opacity: 0.5; }
.iam-dt code, .iam-dt pre { font-family: var(--iam-dt-mono); }
.iam-dt p, .iam-dt h3, .iam-dt h4 { margin: 0; }
.iam-dt :focus-visible {
  outline: 2px solid var(--iam-dt-ring);
  outline-offset: 1px;
  border-radius: 4px;
}
.iam-dt ::-webkit-scrollbar { width: 10px; height: 10px; }
.iam-dt ::-webkit-scrollbar-thumb {
  background: var(--iam-dt-border); border-radius: 6px;
  border: 3px solid transparent; background-clip: content-box;
}
.iam-dt ::-webkit-scrollbar-thumb:hover { background: var(--iam-dt-fg-subtle); background-clip: content-box; }
.iam-dt ::-webkit-scrollbar-track { background: transparent; }

/* Chrome: the launcher, the docked panel and its resize edge. */
.iam-dt-btn-wrap { position: fixed; z-index: 99998; }
.iam-dt-btn-wrap[data-pos="bottom-right"] { bottom: 20px; right: 20px; }
.iam-dt-btn-wrap[data-pos="bottom-left"]  { bottom: 20px; left: 20px; }
.iam-dt-btn-wrap[data-pos="top-right"]    { top: 20px; right: 20px; }
.iam-dt-btn-wrap[data-pos="top-left"]     { top: 20px; left: 20px; }

.iam-dt-launch {
  display: inline-flex; align-items: center; justify-content: center;
  width: 44px; height: 44px; border-radius: 12px;
  border: 1px solid var(--iam-dt-border); background: var(--iam-dt-surface);
  box-shadow: var(--iam-dt-shadow);
  transition: transform 160ms ease, opacity 160ms ease, border-color 160ms ease;
}
.iam-dt-launch:hover { transform: translateY(-2px); border-color: var(--iam-dt-fg-muted); }
.iam-dt-launch:active { transform: scale(0.95); }
.iam-dt-launch[data-hidden="1"] { pointer-events: none; opacity: 0; transform: scale(0.5); }
.iam-dt-launch img { width: 24px; height: 24px; object-fit: contain; display: block; }

.iam-dt-panel-wrap {
  position: fixed; z-index: 99999;
  display: flex; flex-direction: column;
  transition: transform 240ms cubic-bezier(.32,.72,0,1), opacity 240ms ease;
  will-change: transform, opacity;
}
.iam-dt-panel-wrap[data-pos="bottom"] { left: 0; right: 0; bottom: 0; }
.iam-dt-panel-wrap[data-pos="top"]    { left: 0; right: 0; top: 0; }
.iam-dt-panel-wrap[data-pos="left"]   { top: 0; bottom: 0; left: 0; }
.iam-dt-panel-wrap[data-pos="right"]  { top: 0; bottom: 0; right: 0; }
.iam-dt-panel-wrap[data-inset="1"]    { padding: 12px; }

.iam-dt-dock {
  display: flex; flex-direction: column; height: 100%; min-height: 0; overflow: hidden;
  background: var(--iam-dt-bg); border: 1px solid var(--iam-dt-border);
  box-shadow: var(--iam-dt-shadow);
}
.iam-dt-dock[data-inset="1"] { border-radius: 12px; }
.iam-dt-dock[data-flush="bottom"] { border-left: 0; border-right: 0; border-bottom: 0; }
.iam-dt-dock[data-flush="top"]    { border-left: 0; border-right: 0; border-top: 0; }
.iam-dt-dock[data-flush="left"]   { border-top: 0; border-bottom: 0; border-left: 0; }
.iam-dt-dock[data-flush="right"]  { border-top: 0; border-bottom: 0; border-right: 0; }

.iam-dt-resize { position: absolute; background: transparent; transition: background 160ms ease; }
.iam-dt-resize:hover, .iam-dt-resize:focus-visible { background: var(--iam-dt-ring); }
.iam-dt-resize--ns { left: 0; right: 0; height: 5px; cursor: ns-resize; }
.iam-dt-resize--ew { top: 0; bottom: 0; width: 5px; cursor: ew-resize; }
.iam-dt-panel-wrap[data-pos="bottom"] .iam-dt-resize { top: 0; }
.iam-dt-panel-wrap[data-pos="top"] .iam-dt-resize    { bottom: 0; }
.iam-dt-panel-wrap[data-pos="left"] .iam-dt-resize   { right: 0; }
.iam-dt-panel-wrap[data-pos="right"] .iam-dt-resize  { left: 0; }

@keyframes iam-dt-spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
@keyframes iam-dt-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.35; } }
.iam-dt-spin { animation: iam-dt-spin 0.9s linear infinite; }

/* Header. */
.iam-dt-header {
  display: flex; align-items: center; justify-content: space-between; gap: 16px;
  flex-shrink: 0; padding: 8px 12px;
  background: var(--iam-dt-surface); border-bottom: 1px solid var(--iam-dt-border);
}
.iam-dt-header__brand { display: flex; align-items: center; gap: 8px; min-width: 0; }
.iam-dt-header__logo {
  display: inline-flex; align-items: center; justify-content: center;
  width: 28px; height: 28px; flex-shrink: 0; border-radius: 6px;
  border: 1px solid var(--iam-dt-border); background: var(--iam-dt-bg);
}
.iam-dt-header__logo img { width: 16px; height: 16px; object-fit: contain; display: block; }
.iam-dt-header__names { display: flex; flex-direction: column; min-width: 0; line-height: 1.2; }
.iam-dt-header__title { font-size: 12px; font-weight: 700; letter-spacing: -0.01em; }
.iam-dt-header__sub {
  font-family: var(--iam-dt-mono); font-size: 9px; text-transform: uppercase;
  letter-spacing: 0.2em; color: var(--iam-dt-fg-muted);
}
.iam-dt-header__actions { display: flex; align-items: center; gap: 4px; flex-shrink: 0; }
.iam-dt-live {
  display: inline-flex; align-items: center; gap: 4px; margin-left: 8px;
  padding: 1px 8px; border-radius: 999px;
  border: 1px solid var(--iam-dt-allow); background: var(--iam-dt-allow-soft);
  color: var(--iam-dt-allow); font-family: var(--iam-dt-mono);
  font-size: 9px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em;
}
.iam-dt-live__dot {
  width: 4px; height: 4px; border-radius: 50%; background: currentColor;
  animation: iam-dt-pulse 2s ease-in-out infinite;
}

/* Tabs. */
.iam-dt-tabs {
  display: flex; flex-wrap: wrap; align-items: center; gap: 4px; flex-shrink: 0;
  padding: 6px 8px; background: var(--iam-dt-surface);
  border-bottom: 1px solid var(--iam-dt-border);
}
.iam-dt-tab {
  display: inline-flex; align-items: center; gap: 6px; height: 28px; padding: 0 10px;
  border-radius: 6px; border: 1px solid transparent;
  font-size: 11px; font-weight: 500; color: var(--iam-dt-fg-muted);
  transition: background 160ms ease, color 160ms ease, border-color 160ms ease;
}
.iam-dt-tab:hover { background: var(--iam-dt-surface-2); color: var(--iam-dt-fg); }
.iam-dt-tab[aria-selected="true"] {
  background: var(--iam-dt-bg); border-color: var(--iam-dt-border);
  color: var(--iam-dt-fg); font-weight: 600;
}
.iam-dt-tab__dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; opacity: 0.55; }
.iam-dt-tab[aria-selected="true"] .iam-dt-tab__dot { opacity: 1; }

/* Frames. */
.iam-dt-frame { display: flex; flex-direction: column; height: 100%; min-height: 0; overflow: hidden; }
.iam-dt-body { display: flex; flex-direction: column; flex: 1 1 auto; min-height: 0; overflow: hidden; }
.iam-dt-shell {
  display: flex; flex-direction: column; height: 100%; min-height: 0; overflow: hidden;
  border-radius: 12px; border: 1px solid var(--iam-dt-border);
  background: var(--iam-dt-bg);
}
.iam-dt-split { display: grid; grid-template-columns: 300px 1fr; height: 100%; min-height: 0; overflow: hidden; }
.iam-dt-split__aside {
  display: flex; flex-direction: column; height: 100%; min-height: 0; overflow: hidden;
  border-right: 1px solid var(--iam-dt-border); background: var(--iam-dt-surface);
}
.iam-dt-split__main {
  display: flex; flex-direction: column; height: 100%; min-height: 0; overflow: hidden;
  background: var(--iam-dt-bg);
}
@media (max-width: 720px) {
  .iam-dt-split { grid-template-columns: 1fr; grid-template-rows: minmax(0, 40%) minmax(0, 60%); }
  .iam-dt-split__aside { border-right: 0; border-bottom: 1px solid var(--iam-dt-border); }
}

/* List pane. */
.iam-dt-list { display: flex; flex-direction: column; height: 100%; min-height: 0; }
.iam-dt-list__head {
  display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-shrink: 0;
  padding: 8px 12px; background: var(--iam-dt-surface);
  border-bottom: 1px solid var(--iam-dt-border);
}
.iam-dt-list__titles { display: flex; align-items: center; gap: 8px; }
.iam-dt-list__count {
  display: inline-flex; align-items: center; padding: 1px 6px; border-radius: 999px;
  background: var(--iam-dt-surface-2); color: var(--iam-dt-fg-muted);
  font-family: var(--iam-dt-mono); font-size: 9px; font-weight: 600;
}
.iam-dt-list__body { flex: 1 1 auto; overflow: auto; min-height: 0; }

.iam-dt-item {
  display: flex; width: 100%; align-items: center; gap: 8px; text-align: left;
  padding: 6px 12px; border-bottom: 1px solid var(--iam-dt-border-subtle);
  transition: background 120ms ease;
}
.iam-dt-item:hover { background: var(--iam-dt-surface-2); }
.iam-dt-item[data-active="1"] { background: var(--iam-dt-accent-soft); box-shadow: inset 2px 0 0 var(--iam-dt-accent); }
.iam-dt-item__dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
.iam-dt-item__text { display: flex; flex-direction: column; gap: 2px; min-width: 0; flex: 1 1 auto; }
.iam-dt-item__primary {
  font-family: var(--iam-dt-mono); font-size: 11px; color: var(--iam-dt-fg);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.iam-dt-item[data-active="1"] .iam-dt-item__primary { font-weight: 600; }
.iam-dt-item__secondary {
  font-family: var(--iam-dt-mono); font-size: 9px; color: var(--iam-dt-fg-muted);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}

/* Filter bar. */
.iam-dt-filter {
  display: flex; align-items: center; gap: 8px; flex-shrink: 0;
  padding: 6px 8px; background: var(--iam-dt-surface);
  border-bottom: 1px solid var(--iam-dt-border);
}
.iam-dt-filter__wrap { position: relative; display: flex; align-items: center; flex: 1 1 auto; }
.iam-dt-filter__icon {
  position: absolute; left: 8px; pointer-events: none; color: var(--iam-dt-fg-muted);
  display: inline-flex;
}
.iam-dt-filter .iam-dt-input { padding-left: 26px; }

/* Sections. */
.iam-dt-section { border-bottom: 1px solid var(--iam-dt-border); }
.iam-dt-section__head {
  display: flex; align-items: center; justify-content: space-between; gap: 8px;
  padding: 6px 12px; background: var(--iam-dt-surface);
}
.iam-dt-section__btn { display: flex; flex: 1 1 auto; align-items: center; gap: 8px; text-align: left; }
.iam-dt-section__chev {
  display: inline-flex; width: 12px; align-items: center; justify-content: center;
  color: var(--iam-dt-fg-muted); flex-shrink: 0;
}
.iam-dt-section__title, .iam-dt-list__title {
  font-size: 10px; font-weight: 600; color: var(--iam-dt-fg-muted);
  text-transform: uppercase; letter-spacing: 0.18em;
}
.iam-dt-section__body { padding: 8px 12px; }

/* Controls. */
.iam-dt-btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 5px;
  height: 28px; padding: 0 10px; border-radius: 6px;
  border: 1px solid var(--iam-dt-border); background: var(--iam-dt-surface);
  color: var(--iam-dt-fg); font-size: 11px; font-weight: 500; white-space: nowrap;
  transition: background 140ms ease, border-color 140ms ease, color 140ms ease;
}
.iam-dt-btn:hover:not(:disabled) { background: var(--iam-dt-surface-2); border-color: var(--iam-dt-fg-subtle); }
.iam-dt-btn--primary {
  background: var(--iam-dt-accent); border-color: var(--iam-dt-accent); color: #ffffff; font-weight: 600;
}
.iam-dt-btn--primary:hover:not(:disabled) { filter: brightness(1.1); background: var(--iam-dt-accent); }
.iam-dt-btn--ghost { background: transparent; border-color: transparent; color: var(--iam-dt-fg-muted); }
.iam-dt-btn--ghost:hover:not(:disabled) { background: var(--iam-dt-surface-2); color: var(--iam-dt-fg); }
.iam-dt-btn--danger { color: var(--iam-dt-deny); border-color: var(--iam-dt-deny); background: var(--iam-dt-deny-soft); }
.iam-dt-btn--danger:hover:not(:disabled) { background: var(--iam-dt-deny); color: #ffffff; }
.iam-dt-btn--icon { width: 28px; padding: 0; }
.iam-dt-btn--dock { font-family: var(--iam-dt-mono); font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; }

.iam-dt-input, .iam-dt-textarea {
  width: 100%; border-radius: 6px;
  border: 1px solid var(--iam-dt-border); background: var(--iam-dt-bg);
  color: var(--iam-dt-fg); transition: border-color 140ms ease;
}
.iam-dt-input { height: 28px; padding: 0 8px; font-size: 11px; }
.iam-dt-textarea {
  padding: 6px 8px; font-family: var(--iam-dt-mono); font-size: 11px; line-height: 1.6; resize: vertical;
}
.iam-dt-input::placeholder, .iam-dt-textarea::placeholder { color: var(--iam-dt-fg-subtle); }
.iam-dt-input:hover, .iam-dt-textarea:hover { border-color: var(--iam-dt-fg-subtle); }

.iam-dt-field { display: flex; flex-direction: column; gap: 5px; }
.iam-dt-field__label {
  font-size: 10px; font-weight: 600; color: var(--iam-dt-fg-muted);
  text-transform: uppercase; letter-spacing: 0.14em;
}

.iam-dt-badge {
  display: inline-flex; align-items: center; height: 18px; padding: 0 8px; border-radius: 999px;
  border: 1px solid var(--iam-dt-border); background: var(--iam-dt-surface-2);
  color: var(--iam-dt-fg-muted);
  font-size: 9px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; white-space: nowrap;
}
.iam-dt-badge--allow { border-color: var(--iam-dt-allow); background: var(--iam-dt-allow-soft); color: var(--iam-dt-allow); }
.iam-dt-badge--deny { border-color: var(--iam-dt-deny); background: var(--iam-dt-deny-soft); color: var(--iam-dt-deny); }
.iam-dt-badge--info { border-color: var(--iam-dt-accent); background: var(--iam-dt-accent-soft); color: var(--iam-dt-accent); }
.iam-dt-badge--warn { border-color: var(--iam-dt-warn); background: var(--iam-dt-warn-soft); color: var(--iam-dt-warn); }

.iam-dt-card {
  border-radius: 8px; border: 1px solid var(--iam-dt-border);
  background: var(--iam-dt-surface); overflow: hidden;
}
.iam-dt-card__head {
  display: flex; align-items: center; justify-content: space-between; gap: 8px;
  padding: 6px 12px; border-bottom: 1px solid var(--iam-dt-border);
}
.iam-dt-card__title {
  font-size: 11px; font-weight: 600; color: var(--iam-dt-fg-muted);
  text-transform: uppercase; letter-spacing: 0.12em;
}
.iam-dt-card__body { padding: 12px; font-size: 11px; }

.iam-dt-alert {
  margin: 8px; padding: 6px 12px; border-radius: 6px;
  font-size: 11px; font-weight: 500; border: 1px solid transparent;
}
.iam-dt-alert--error { border-color: var(--iam-dt-deny); background: var(--iam-dt-deny-soft); color: var(--iam-dt-deny); }
.iam-dt-alert--success { border-color: var(--iam-dt-allow); background: var(--iam-dt-allow-soft); color: var(--iam-dt-allow); }

/* Detail pane. */
.iam-dt-detail { flex: 1 1 auto; overflow: auto; min-height: 0; }
.iam-dt-detail__head {
  display: flex; flex-wrap: wrap; align-items: center; gap: 8px;
  padding: 8px 12px; background: var(--iam-dt-surface); border-bottom: 1px solid var(--iam-dt-border);
  position: sticky; top: 0; z-index: 1;
}
.iam-dt-detail__head code { font-family: var(--iam-dt-mono); font-size: 11px; color: var(--iam-dt-fg); font-weight: 600; }
.iam-dt-detail__meta { margin-left: auto; font-family: var(--iam-dt-mono); font-size: 10px; color: var(--iam-dt-fg-muted); }

.iam-dt-listshell { display: flex; flex-direction: column; height: 100%; min-height: 0; }
.iam-dt-listshell__head {
  display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-shrink: 0;
  padding: 8px 12px; background: var(--iam-dt-surface); border-bottom: 1px solid var(--iam-dt-border);
}
.iam-dt-listshell__title {
  font-size: 10px; font-weight: 600; color: var(--iam-dt-fg-muted);
  text-transform: uppercase; letter-spacing: 0.18em;
}

/* Trace tree. */
.iam-dt-trace__group {
  background: var(--iam-dt-surface); border: 1px solid var(--iam-dt-border);
  border-radius: 6px; overflow: hidden;
}
.iam-dt-trace__group-head {
  display: flex; width: 100%; align-items: center; gap: 8px; flex-wrap: wrap;
  padding: 6px 10px; text-align: left; font-size: 11px;
  transition: background 160ms ease;
}
.iam-dt-trace__group-head:hover:not(:disabled) { background: var(--iam-dt-surface-2); }
.iam-dt-trace__group-body {
  display: flex; flex-direction: column; gap: 6px;
  padding: 8px 10px 10px 20px; border-top: 1px solid var(--iam-dt-border);
}
.iam-dt-trace__row {
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
  padding: 6px 10px; background: var(--iam-dt-surface);
  border: 1px solid var(--iam-dt-border); border-radius: 6px;
}
.iam-dt-trace__row code { font-family: var(--iam-dt-mono); font-size: 11px; color: var(--iam-dt-fg); }

/* Stats. */
.iam-dt-stat {
  display: flex; flex-direction: column; gap: 4px; padding: 10px 12px;
  background: var(--iam-dt-surface); border: 1px solid var(--iam-dt-border); border-radius: 8px;
}
.iam-dt-stat__label {
  font-size: 9px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.14em;
  color: var(--iam-dt-fg-muted);
}
.iam-dt-stat__value {
  font-family: var(--iam-dt-mono); font-size: 18px; font-weight: 700;
  color: var(--iam-dt-fg); line-height: 1.1; letter-spacing: -0.02em;
}
.iam-dt-stat__hint { font-family: var(--iam-dt-mono); font-size: 9px; color: var(--iam-dt-fg-muted); }
.iam-dt-stat-grid { display: grid; gap: 8px; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); }

/* Flow panel. */
.iam-dt-flow__filters {
  display: flex; align-items: center; gap: 6px; padding: 8px 12px;
  background: var(--iam-dt-surface); border-bottom: 1px solid var(--iam-dt-border);
}
.iam-dt-flow__head {
  display: flex; flex-wrap: wrap; align-items: center; gap: 8px; flex-shrink: 0;
  position: sticky; top: 0; z-index: 1; padding: 10px 16px;
  background: var(--iam-dt-surface); border-bottom: 1px solid var(--iam-dt-border);
}
.iam-dt-flow__time {
  margin-left: auto; display: inline-flex; align-items: center; gap: 6px;
  font-family: var(--iam-dt-mono); font-size: 10px; color: var(--iam-dt-fg-muted);
}
.iam-dt-flow__scroll { flex: 1 1 auto; overflow: auto; min-height: 0; }
.iam-dt-flow__foot {
  display: flex; align-items: center; justify-content: flex-end; gap: 6px; flex-shrink: 0;
  padding: 8px 12px; background: var(--iam-dt-surface); border-top: 1px solid var(--iam-dt-border);
}
.iam-dt-flow__reason {
  white-space: pre-wrap; font-family: var(--iam-dt-mono); font-size: 11px;
  line-height: 1.6; color: var(--iam-dt-fg);
}

.iam-dt-pill {
  display: inline-flex; align-items: center; gap: 6px; height: 24px; padding: 0 10px;
  border-radius: 999px; border: 1px solid var(--iam-dt-border); background: transparent;
  color: var(--iam-dt-fg-muted); font-family: var(--iam-dt-mono);
  font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em;
  transition: background 140ms ease, color 140ms ease, border-color 140ms ease;
}
.iam-dt-pill[aria-pressed="false"] { opacity: 0.55; }
.iam-dt-pill[aria-pressed="false"]:hover { opacity: 1; }
.iam-dt-pill--allow[aria-pressed="true"] {
  border-color: var(--iam-dt-allow); background: var(--iam-dt-allow-soft); color: var(--iam-dt-allow);
}
.iam-dt-pill--deny[aria-pressed="true"] {
  border-color: var(--iam-dt-deny); background: var(--iam-dt-deny-soft); color: var(--iam-dt-deny);
}
.iam-dt-pill__count { opacity: 0.7; }

.iam-dt-chip {
  display: inline-flex; align-items: center; gap: 4px; height: 24px; padding: 0 8px;
  border-radius: 6px; border: 1px solid var(--iam-dt-border); background: var(--iam-dt-surface-2);
  font-family: var(--iam-dt-mono); font-size: 11px; font-weight: 600;
}
.iam-dt-chip--action { border-color: var(--iam-dt-accent); background: var(--iam-dt-accent-soft); color: var(--iam-dt-action); }
.iam-dt-chip--resource { border-color: var(--iam-dt-warn); background: var(--iam-dt-warn-soft); color: var(--iam-dt-resource); }
.iam-dt-chip__id { opacity: 0.6; }

.iam-dt-subject {
  display: inline-flex; align-items: center; gap: 8px; padding: 4px 8px;
  border-radius: 6px; border: 1px solid var(--iam-dt-border); background: var(--iam-dt-surface);
}
.iam-dt-subject__avatar {
  display: inline-flex; align-items: center; justify-content: center;
  width: 20px; height: 20px; border-radius: 50%;
  background: var(--iam-dt-accent-soft); color: var(--iam-dt-accent);
  font-family: var(--iam-dt-mono); font-size: 10px; font-weight: 700;
}
.iam-dt-subject code { font-family: var(--iam-dt-mono); font-size: 11px; font-weight: 600; color: var(--iam-dt-fg); }

.iam-dt-kv {
  display: inline-flex; align-items: center; gap: 6px; padding: 4px 8px;
  border-radius: 6px; border: 1px solid var(--iam-dt-border); background: var(--iam-dt-surface);
}
.iam-dt-kv__k {
  font-family: var(--iam-dt-mono); font-size: 9px; color: var(--iam-dt-fg-muted);
  text-transform: uppercase; letter-spacing: 0.12em;
}
.iam-dt-kv__v { font-family: var(--iam-dt-mono); font-size: 11px; font-weight: 600; color: var(--iam-dt-fg); }

/* JSON tree. */
.iam-dt-json { font-family: var(--iam-dt-mono); font-size: 11px; line-height: 1.6; }
.iam-dt-json__leaf { display: flex; align-items: baseline; gap: 6px; padding-left: 16px; }
.iam-dt-json__btn {
  display: flex; width: 100%; align-items: baseline; gap: 4px; text-align: left;
  padding: 1px 4px; border-radius: 4px; transition: background 120ms ease;
}
.iam-dt-json__btn:hover { background: var(--iam-dt-surface-2); }
.iam-dt-json__chev { display: inline-flex; width: 12px; flex-shrink: 0; color: var(--iam-dt-fg-muted); }
.iam-dt-json__key { color: var(--iam-dt-accent); }
.iam-dt-json__punct { color: var(--iam-dt-fg-muted); }
.iam-dt-json__summary { margin-left: 6px; font-size: 9px; font-style: italic; color: var(--iam-dt-fg-subtle); }
.iam-dt-json__children { margin-left: 12px; padding-left: 8px; border-left: 1px solid var(--iam-dt-border); }
.iam-dt-json__close { padding-left: 4px; color: var(--iam-dt-fg-muted); }
.iam-dt-json-string { color: var(--iam-dt-string); }
.iam-dt-json-number { color: var(--iam-dt-number); }
.iam-dt-json-bool { color: var(--iam-dt-bool); font-weight: 600; }
.iam-dt-json-nullish { color: var(--iam-dt-fg-subtle); font-style: italic; }

/* Shared bits. */
.iam-dt-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.iam-dt-col { display: flex; flex-direction: column; gap: 8px; }
.iam-dt-grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
@media (max-width: 600px) { .iam-dt-grid-2 { grid-template-columns: 1fr; } }
.iam-dt-mute { color: var(--iam-dt-fg-muted); font-family: var(--iam-dt-mono); font-size: 10px; }
.iam-dt-soft { color: var(--iam-dt-fg-muted); }
.iam-dt-pad { padding: 12px; }
.iam-dt-scroll { overflow: auto; min-height: 0; }
.iam-dt-sep { display: inline-block; width: 3px; height: 3px; background: currentColor; opacity: 0.5; border-radius: 50%; flex-shrink: 0; }
.iam-dt-dot { display: inline-block; width: 3px; height: 3px; border-radius: 50%; background: currentColor; opacity: 0.4; flex-shrink: 0; }

.iam-dt-action { color: var(--iam-dt-action); font-weight: 600; }
.iam-dt-resource { color: var(--iam-dt-resource); font-weight: 600; }
.iam-dt-effect-allow { color: var(--iam-dt-allow); font-weight: 700; }
.iam-dt-effect-deny { color: var(--iam-dt-deny); font-weight: 700; }

.iam-dt-empty { padding: 32px 20px; text-align: center; font-size: 12px; color: var(--iam-dt-fg-muted); }
.iam-dt-empty--dashed {
  margin: 12px; padding: 20px; border: 1px dashed var(--iam-dt-border);
  border-radius: 8px; background: var(--iam-dt-surface);
}
.iam-dt-empty--fill { display: flex; height: 100%; align-items: center; justify-content: center; padding: 24px; }
.iam-dt-empty code { font-family: var(--iam-dt-mono); color: var(--iam-dt-fg); }

/* A devtools overlay is exactly the kind of thing that slides, spins and
   pulses in the corner of someone's eye all day. Honour the OS switch. */
@media (prefers-reduced-motion: reduce) {
  .iam-dt, .iam-dt *, .iam-dt-panel-wrap, .iam-dt-launch {
    animation-duration: 0.001ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.001ms !important;
  }
}
`

/**
 * Injects the devtools stylesheet into `document.head` once per document; a no-op under SSR.
 * NOTE: a `<style>` tag, not a CSS import, so consumer bundlers need no CSS pipeline.
 */
export function ensureStylesInjected() {
  if (typeof document === 'undefined') return
  if (document.getElementById(STYLE_ID)) return
  const style = document.createElement('style')
  style.id = STYLE_ID
  style.textContent = CSS
  document.head.appendChild(style)
}

/** Which palette to use; `'auto'` (the default) follows `prefers-color-scheme`. */
export type IamDevtoolsTheme = 'auto' | 'dark' | 'light'

/**
 * The `data-iam-dt-theme` value for a theme, or `undefined` for `'auto'`.
 * NOTE: the attribute must be absent for `'auto'`; the CSS follows `prefers-color-scheme` only when it is unset.
 */
export function iamDevtoolsThemeAttr(theme: IamDevtoolsTheme = 'auto'): 'dark' | 'light' | undefined {
  return theme === 'auto' ? undefined : theme
}

/**
 * Injects the stylesheet on mount, never during SSR.
 * NOTE: every panel calls this, since each is exported individually and may be the only one mounted.
 */
export function useIamDevtoolsStyles(): void {
  React.useEffect(() => {
    ensureStylesInjected()
  }, [])
}
