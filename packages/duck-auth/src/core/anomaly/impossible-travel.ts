import type { AuthAnomaly } from '../types/anomaly'

const DEFAULT_CONFIG: AuthImpossibleTravel.IConfig = {
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
 * persists them (often `AuthIdentity.attributes.lastSeen`).
 */
export function authImpossibleTravelDetector(opts: {
  getLastSeen: (identityId: string) => Promise<{ lat: number; lon: number; at: number } | null>
  config?: Partial<AuthImpossibleTravel.IConfig>
}): AuthAnomaly.IDetector {
  const cfg: AuthImpossibleTravel.IConfig = { ...DEFAULT_CONFIG, ...(opts.config ?? {}) }
  if (!Number.isFinite(cfg.maxKmPerHour) || cfg.maxKmPerHour <= 0) {
    throw new Error(`authImpossibleTravelDetector: maxKmPerHour must be a finite positive number (got ${cfg.maxKmPerHour})`)
  }
  return {
    id: 'impossible-travel',
    async evaluate({ identity, req }) {
      // `=== undefined` (not truthy) so lat/lon=0 stays a valid signal.
      if (req.geo?.lat === undefined || req.geo?.lon === undefined) return []
      if (!Number.isFinite(req.geo.lat) || !Number.isFinite(req.geo.lon)) return []
      const last = await opts.getLastSeen(identity.id)
      if (!last) return []
      if (!Number.isFinite(last.lat) || !Number.isFinite(last.lon) || !Number.isFinite(last.at)) return []
      const elapsedMs = req.now - last.at
      // Math.abs handles negative clock skew; otherwise negative speed <= max == bypass.
      if (Math.abs(elapsedMs) < cfg.minElapsedMs) return []
      const distanceKm = haversineKm({ lat: last.lat, lon: last.lon }, { lat: req.geo.lat, lon: req.geo.lon })
      const speedKmH = distanceKm / (Math.abs(elapsedMs) / 3_600_000)
      if (!Number.isFinite(speedKmH)) return []
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

export namespace AuthImpossibleTravel {
  export interface IConfig {
    /** Max speed (km/h) above which the gap counts as suspicious. Default 900. */
    maxKmPerHour: number
    /** Minimum elapsed time between samples (ms) before evaluating. Default 60s
     *  (sub-minute gaps are usually NAT mobility, not travel).
     */
    minElapsedMs: number
  }
}
