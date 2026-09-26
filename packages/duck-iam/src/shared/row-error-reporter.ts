import type { IamAdapter } from '../core/types'

/**
 * Builds an adapter's `_reportPolicyError`: routes a bad row to `onPolicyError`, or warns when no handler is set,
 * so a dropped row never vanishes unseen. Shared by every adapter whose config carries `onPolicyError`.
 */
export function iamRowErrorReporter<TAdapter extends string>(
  adapter: TAdapter,
  onPolicyError: IamAdapter.RowErrorHandler<TAdapter> | undefined,
): (err: Error, rowId: string) => void {
  return (err, rowId) => {
    if (onPolicyError) {
      onPolicyError(err, { adapter, rowId })
      return
    }
    console.warn(`[@gentleduck/iam:${adapter}] dropped malformed row "${rowId}": ${err.message}`)
  }
}
