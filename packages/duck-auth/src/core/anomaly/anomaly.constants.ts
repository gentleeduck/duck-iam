import type { Anomaly } from './anomaly.types'

/** Conservative defaults. Step-up at 0.7; deny at 0.95. */
export const DEFAULT_ANOMALY_CONFIG: Anomaly.Cfg = {
  denyAt: 0.95,
  detectorTimeoutMs: 1_000,
  stepUpAt: 0.7,
  threshold: 0.7,
}

/** Separates a detector id from a signal kind in a scoped `reactions` key. */
export const REACTION_SCOPE = '#'

/**
 * Combine independent signals, saturating at 1.
 *
 * A plain sum calibrates the ladder against how many detectors are registered rather than against
 * how severe they are: five mild 0.2 signals crossed a deny nothing asked for. Noisy-or keeps the
 * aggregate inside the 0..1 range a single signal is documented to use, so `denyAt: 0.95` means one
 * near-certain signal or several strong ones whatever the detector count is.
 */
export function combineScores(scores: number[]): number {
  let remainder = 1
  for (const score of scores) remainder *= 1 - score
  // Rounded because the complement arithmetic leaves 0.19999999999999996 where a lone 0.2 went in,
  // and the score is compared against operator-written thresholds and written to an audit record.
  return Number((1 - remainder).toFixed(10))
}

/** Signals are documented as 0..1; a detector outside that range is a bug, not a veto. */
export function clampScore(score: number): number {
  return Math.min(1, Math.max(0, score))
}
