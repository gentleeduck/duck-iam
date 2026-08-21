---
'@gentleduck/auth': patch
---

Roll back a plugin install that fails.

`use()` claimed the plugin id first, then subscribed its event handlers, exposed its
facet and awaited `install`. A throw from any of those left the id claimed, the handlers
subscribed and the facet reachable, so retrying under the same id hit "already installed"
while the half-wired plugin kept receiving events.

Providers register first, before the id is committed, so a duplicate provider id throws
where the author can fix the collision and reinstall under the same id. Everything after
that is undone on a throw, and the id is committed last.

`Providers` has no unregister, so a provider registered by a plugin that fails later
stays registered. That limit is named in the code rather than papered over.
