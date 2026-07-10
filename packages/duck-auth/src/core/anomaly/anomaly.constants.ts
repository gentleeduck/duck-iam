import type { Anomaly } from './anomaly.types'

/** Conservative defaults. Step-up at 0.7; deny at 0.95. */
export const DEFAULT_ANOMALY_CONFIG: Anomaly.Cfg = {
  threshold: 0.7,
  stepUpAt: 0.7,
  denyAt: 0.95,
}
