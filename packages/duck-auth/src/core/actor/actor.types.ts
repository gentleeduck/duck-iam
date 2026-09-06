/**
 * Who is performing a write.
 *
 * The schema declares `created_by` / `updated_by` on every mutable table, and
 * until this existed nothing could fill them: the columns were always NULL, so
 * a row recorded that it had provenance and never what it was. Framework
 * adapters bind this per request the same way they bind {@link TenantContext};
 * apps that do not track an actor leave `actorId` undefined and the columns
 * stay NULL, which is now a statement rather than an accident.
 */
export interface ActorContext {
  /**
   * Opaque to the library - a user id, a service account, `system`. It is
   * written verbatim and never resolved, so nothing here has to exist as an
   * identity in this database.
   */
  actorId?: string
}
