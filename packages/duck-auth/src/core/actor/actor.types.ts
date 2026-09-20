/** Fills the `created_by` / `updated_by` columns every mutable table declares. Adapters bind it per
 *  request, as they bind `TenantContext`; an app that tracks no actor leaves it undefined and the
 *  columns stay NULL, which is then a statement rather than an accident. */
export interface ActorContext {
  /** Opaque: a user id, a service account, `system`. Written verbatim and never resolved, so it need
   *  not name an identity in this database. */
  actorId?: string
}
