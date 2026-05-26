/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { Anomaly } from '../types/anomaly'

/**
 * Impossible-travel detector. Compares the request's geo coordinates
 * with the session's last-known coords (set by the framework adapter at
 * session.create). When the implied speed between the two locations
 * exceeds `maxKmPerHour` (default 900, faster than a commercial jet),
 * emit a signal.
 *
 * Notes
 *   - Requires a GeoIP provider on the caller side; library does not
 *     ship MaxMind or ipinfo by default (licensing). Apps pass
 *     coordinates pre-resolved via the request snapshot.
 *   - Score scales linearly with overshoot above the threshold and
 *     caps at 1.0 at 2x the threshold.
 */
export interface ImpossibleTravelConfig {
  /** Max speed (km/h) above which the gap counts as suspicious. Default 900. */
  maxKmPerHour: number
  /** Minimum elapsed time between samples (ms) before evaluating. Default 60s
   *  (sub-minute gaps are usually NAT mobility, not travel). */
  minElapsedMs: number
}

const DEFAULT_CONFIG: ImpossibleTravelConfig = {
  maxKmPerHour: 900,
  minElapsedMs: 60_000,
}

/** Haversine distance in km between two (lat, lon) pairs. */
function haversineKm(a: { lat: number; lon: number }, b: { lat: number; lon: number }): number {
  const toRad = (x: number): number => (x * Math.PI) / 180
  const R = 6371
  const dLat = toRad(b.lat - a.lat)
  const dLon = toRad(b.lon - a.lon)
  const s = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(a.lat)) * Math.cos(toRad(b.lat)) * Math.sin(dLon / 2) ** 2
  return 2 * R * Math.asin(Math.sqrt(s))
}

/**
 * Build an impossible-travel detector. Pass `getLastSeen(identityId)`
 * so the detector can read the prior coords from wherever the app
 * persists them (often `Identity.attributes.lastSeen`).
 */
export function impossibleTravelDetector(opts: {
  getLastSeen: (identityId: string) => Promise<{ lat: number; lon: number; at: number } | null>
  config?: Partial<ImpossibleTravelConfig>
}): Anomaly.IDetector {
  const cfg: ImpossibleTravelConfig = { ...DEFAULT_CONFIG, ...(opts.config ?? {}) }
  return {
    id: 'impossible-travel',
    async evaluate({ identity, req }) {
      if (!req.geo?.lat || !req.geo?.lon) return []
      const last = await opts.getLastSeen(identity.id)
      if (!last) return []
      const elapsedMs = req.now - last.at
      if (elapsedMs < cfg.minElapsedMs) return []
      const distanceKm = haversineKm({ lat: last.lat, lon: last.lon }, { lat: req.geo.lat, lon: req.geo.lon })
      const speedKmH = distanceKm / (elapsedMs / 3_600_000)
      if (speedKmH <= cfg.maxKmPerHour) return []
      const overshoot = speedKmH / cfg.maxKmPerHour
      const score = Math.min(1, (overshoot - 1) / 1)
      return [
        {
          kind: 'impossible-travel',
          score,
          evidence: {
            from: { lat: last.lat, lon: last.lon },
            to: { lat: req.geo.lat, lon: req.geo.lon },
            distanceKm: Math.round(distanceKm),
            elapsedMs,
            speedKmH: Math.round(speedKmH),
            threshold: cfg.maxKmPerHour,
          },
        },
      ]
    },
  }
}
