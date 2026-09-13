import { AuthError } from '~/core/errors'
import type { Anomaly } from './anomaly.types'

const DEFAULT_CONFIG: AuthImpossibleTravel.Cfg = {
  maxKmPerHour: 900,
  minElapsedMs: 60_000,
}

/**
 * The overshoot at which the score reaches 1.
 *
 * The score used to be `overshoot - 1`, so crossing the limit was worth nothing and only twice the
 * limit scored at all: a sustained 1500 km/h, impossible for a person, decided allow. Dividing by
 * this instead starts the ramp at half a point the moment the limit is passed.
 */
const FULL_SCORE_OVERSHOOT = 2

/** Whether a pair is a place on earth. `Number.isFinite` alone let a latitude of 900 be scored. */
function isCoordinate(lat: number, lon: number): boolean {
  return Number.isFinite(lat) && Number.isFinite(lon) && Math.abs(lat) <= 90 && Math.abs(lon) <= 180
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
export function authImpossibleTravelDetector(opts: {
  getLastSeen: (identityId: string) => Promise<{ lat: number; lon: number; at: number } | null>
  config?: Partial<AuthImpossibleTravel.Cfg>
}): Anomaly.Detector {
  const cfg: AuthImpossibleTravel.Cfg = { ...DEFAULT_CONFIG, ...(opts.config ?? {}) }
  if (!Number.isFinite(cfg.maxKmPerHour) || cfg.maxKmPerHour <= 0) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `authImpossibleTravelDetector: maxKmPerHour must be a finite positive number (got ${cfg.maxKmPerHour})`,
    })
  }
  // Zero is the interval the speed is divided by, so it turns the most extreme possible teleport
  // into an infinite speed and the finite check then discards it.
  if (!Number.isFinite(cfg.minElapsedMs) || cfg.minElapsedMs <= 0) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `authImpossibleTravelDetector: minElapsedMs must be a finite positive number (got ${cfg.minElapsedMs})`,
    })
  }
  return {
    id: 'impossible-travel',
    async evaluate({ identity, req }) {
      // `=== undefined` (not truthy) so lat/lon=0 stays a valid signal.
      if (req.geo?.lat === undefined || req.geo?.lon === undefined) return []
      if (!isCoordinate(req.geo.lat, req.geo.lon)) return []
      const last = await opts.getLastSeen(identity.id)
      if (!last) return []
      if (!isCoordinate(last.lat, last.lon) || !Number.isFinite(last.at)) return []
      const elapsedMs = req.now - last.at
      // `minElapsedMs` is a floor on the interval, not a reason to skip: applied as a skip it made
      // two sign-ins from opposite sides of the planet fifty seconds apart, the least plausible
      // pattern there is, the one case that reported nothing. A last-seen in the future is not a
      // long gap either - clamped to zero and then floored, so writing tomorrow's date into the
      // store no longer turns the detector off.
      const intervalMs = Math.max(Math.max(0, elapsedMs), cfg.minElapsedMs)
      const distanceKm = haversineKm({ lat: last.lat, lon: last.lon }, { lat: req.geo.lat, lon: req.geo.lon })
      const speedKmH = distanceKm / (intervalMs / 3_600_000)
      if (!Number.isFinite(speedKmH)) return []
      if (speedKmH <= cfg.maxKmPerHour) return []
      const overshoot = speedKmH / cfg.maxKmPerHour
      const score = Math.min(1, overshoot / FULL_SCORE_OVERSHOOT)
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
  export interface Cfg {
    /** Max speed (km/h) above which the gap counts as suspicious. Default 900. */
    maxKmPerHour: number
    /**
     * Floor on the interval the speed is computed over, ms. Default 60s: sub-minute gaps are
     * usually NAT mobility, and dividing a real distance by one of them reports a speed the
     * sampling resolution invented. Must be positive.
     */
    minElapsedMs: number
  }
}
