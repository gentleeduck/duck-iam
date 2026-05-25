// @ts-nocheck
function stryNS_9fa48() {
  var g = typeof globalThis === 'object' && globalThis && globalThis.Math === Math && globalThis || new Function("return this")();
  var ns = g.__stryker__ || (g.__stryker__ = {});
  if (ns.activeMutant === undefined && g.process && g.process.env && g.process.env.__STRYKER_ACTIVE_MUTANT__) {
    ns.activeMutant = g.process.env.__STRYKER_ACTIVE_MUTANT__;
  }
  function retrieveNS() {
    return ns;
  }
  stryNS_9fa48 = retrieveNS;
  return retrieveNS();
}
stryNS_9fa48();
function stryCov_9fa48() {
  var ns = stryNS_9fa48();
  var cov = ns.mutantCoverage || (ns.mutantCoverage = {
    static: {},
    perTest: {}
  });
  function cover() {
    var c = cov.static;
    if (ns.currentTestId) {
      c = cov.perTest[ns.currentTestId] = cov.perTest[ns.currentTestId] || {};
    }
    var a = arguments;
    for (var i = 0; i < a.length; i++) {
      c[a[i]] = (c[a[i]] || 0) + 1;
    }
  }
  stryCov_9fa48 = cover;
  cover.apply(null, arguments);
}
function stryMutAct_9fa48(id) {
  var ns = stryNS_9fa48();
  function isActive(id) {
    if (ns.activeMutant === id) {
      if (ns.hitCount !== void 0 && ++ns.hitCount > ns.hitLimit) {
        throw new Error('Stryker: Hit count limit reached (' + ns.hitCount + ')');
      }
      return true;
    }
    return false;
  }
  stryMutAct_9fa48 = isActive;
  return isActive(id);
}
import type { AccessControl, Adapter, Primitives, Request } from '../types';
import type { Validate } from '../validate/validate.types';
import type { EngineTypes } from './engine.types';

/**
 * Lazy validator binding. The `../validate` module is ~12 KB gzipped; users who
 * never call `engine.admin.savePolicy/saveRole/import` shouldn't pay for it at
 * import time. Loaded on first admin write and memoised.
 */
let _validateBindings: {
  validatePolicy: typeof import('../validate').validatePolicy;
  validateRole: typeof import('../validate').validateRole;
} | null = null;
async function _getValidate() {
  if (stryMutAct_9fa48("0")) {
    {}
  } else {
    stryCov_9fa48("0");
    if (stryMutAct_9fa48("3") ? false : stryMutAct_9fa48("2") ? true : stryMutAct_9fa48("1") ? _validateBindings : (stryCov_9fa48("1", "2", "3"), !_validateBindings)) {
      if (stryMutAct_9fa48("4")) {
        {}
      } else {
        stryCov_9fa48("4");
        const v = await import('../validate');
        _validateBindings = stryMutAct_9fa48("5") ? {} : (stryCov_9fa48("5"), {
          validatePolicy: v.validatePolicy,
          validateRole: v.validateRole
        });
      }
    }
    return _validateBindings;
  }
}

/**
 * Single-flight helper for single-slot in-flight promises.
 *
 * Encapsulates the sentinel-compare pattern used by `_loadPolicies`,
 * `_loadRoles`, `_loadRbacPolicy`, `_loadAllPolicies`. A concurrent caller
 * sees the same `pending` promise; an `invalidate*()` mid-await nulls the
 * slot, and the sentinel check prevents the late resolver from writing
 * stale data into the now-cleared cache.
 *
 * @template T - Resolved value type.
 * @param getSlot - Reads the current in-flight slot (returns `null` if empty).
 * @param setSlot - Writes the in-flight slot (`null` clears it).
 * @param produce - Async producer for the value.
 * @param onResolve - Called only when the slot still holds the original
 *   pending promise. Use this to populate the cache.
 * @returns The pending promise (also stored in the slot until resolved).
 */
export function runSingleFlight<T>(getSlot: () => Promise<T> | null, setSlot: (p: Promise<T> | null) => void, produce: () => Promise<T>, onResolve: (value: T) => void): Promise<T> {
  if (stryMutAct_9fa48("6")) {
    {}
  } else {
    stryCov_9fa48("6");
    let pending!: Promise<T>;
    pending = (async () => {
      if (stryMutAct_9fa48("7")) {
        {}
      } else {
        stryCov_9fa48("7");
        try {
          if (stryMutAct_9fa48("8")) {
            {}
          } else {
            stryCov_9fa48("8");
            const value = await produce();
            if (stryMutAct_9fa48("11") ? getSlot() !== pending : stryMutAct_9fa48("10") ? false : stryMutAct_9fa48("9") ? true : (stryCov_9fa48("9", "10", "11"), getSlot() === pending)) onResolve(value);
            return value;
          }
        } finally {
          if (stryMutAct_9fa48("12")) {
            {}
          } else {
            stryCov_9fa48("12");
            if (stryMutAct_9fa48("15") ? getSlot() !== pending : stryMutAct_9fa48("14") ? false : stryMutAct_9fa48("13") ? true : (stryCov_9fa48("13", "14", "15"), getSlot() === pending)) setSlot(null);
          }
        }
      }
    })();
    setSlot(pending);
    return pending;
  }
}

/**
 * Keyed single-flight for per-key in-flight maps (subjects).
 *
 * Same shape as {@link runSingleFlight} but keyed on a Map entry. Identity
 * equality on the Promise reference disambiguates concurrent callers.
 */
export function runSingleFlightKeyed<K, T>(map: Map<K, Promise<T>>, key: K, produce: () => Promise<T>, onResolve: (value: T) => void): Promise<T> {
  if (stryMutAct_9fa48("16")) {
    {}
  } else {
    stryCov_9fa48("16");
    let pending!: Promise<T>;
    pending = (async () => {
      if (stryMutAct_9fa48("17")) {
        {}
      } else {
        stryCov_9fa48("17");
        try {
          if (stryMutAct_9fa48("18")) {
            {}
          } else {
            stryCov_9fa48("18");
            const value = await produce();
            if (stryMutAct_9fa48("21") ? map.get(key) !== pending : stryMutAct_9fa48("20") ? false : stryMutAct_9fa48("19") ? true : (stryCov_9fa48("19", "20", "21"), map.get(key) === pending)) onResolve(value);
            return value;
          }
        } finally {
          if (stryMutAct_9fa48("22")) {
            {}
          } else {
            stryCov_9fa48("22");
            if (stryMutAct_9fa48("25") ? map.get(key) !== pending : stryMutAct_9fa48("24") ? false : stryMutAct_9fa48("23") ? true : (stryCov_9fa48("23", "24", "25"), map.get(key) === pending)) map.delete(key);
          }
        }
      }
    })();
    map.set(key, pending);
    return pending;
  }
}

/**
 * Throw if the validate result has any `error`-type issue.
 *
 * Admin write paths run this before persisting so a hostile or buggy admin
 * UI cannot store a policy that the read-side validators (`_safeParsePolicy`
 * in file/redis/drizzle) would silently drop, leaving the tenant with zero
 * policies and the `defaultEffect` in charge of every request.
 *
 * The throw text omits attacker-controlled values (e.g. `algorithm`,
 * `operator`); only the validator code enum + dot-path are reflected, so an
 * operator who echoes `err.message` to an HTTP body or audit sink cannot
 * leak the submitted payload. Full structured issues remain available on
 * the validator result itself.
 */
function assertValidOrThrow(kind: 'policy' | 'role', result: Validate.IResult): void {
  if (stryMutAct_9fa48("26")) {
    {}
  } else {
    stryCov_9fa48("26");
    if (stryMutAct_9fa48("28") ? false : stryMutAct_9fa48("27") ? true : (stryCov_9fa48("27", "28"), result.valid)) return;
    const errs = stryMutAct_9fa48("29") ? result.issues.map(i => i.path ? `${i.code} at "${i.path}"` : i.code) : (stryCov_9fa48("29"), result.issues.filter(stryMutAct_9fa48("30") ? () => undefined : (stryCov_9fa48("30"), i => stryMutAct_9fa48("33") ? i.type !== 'error' : stryMutAct_9fa48("32") ? false : stryMutAct_9fa48("31") ? true : (stryCov_9fa48("31", "32", "33"), i.type === (stryMutAct_9fa48("34") ? "" : (stryCov_9fa48("34"), 'error'))))).map(stryMutAct_9fa48("35") ? () => undefined : (stryCov_9fa48("35"), i => i.path ? stryMutAct_9fa48("36") ? `` : (stryCov_9fa48("36"), `${i.code} at "${i.path}"`) : i.code)));
    throw new Error(stryMutAct_9fa48("37") ? `` : (stryCov_9fa48("37"), `duck-iam: ${kind} rejected by validator — ${errs.join(stryMutAct_9fa48("38") ? "" : (stryCov_9fa48("38"), '; '))}`));
  }
}

/**
 * Recursively freeze a policy's rules, condition groups, and condition leaves.
 *
 * The RBAC policy is shared across every evaluation, so any consumer that
 * mutates `policy.rules[0].actions` would silently corrupt subsequent
 * requests. Shallow `Object.freeze(rules)` only protects the array - not the
 * rule objects or their nested condition trees. This helper covers all
 * paths.
 *
 * @template TPolicy - Specific policy shape, preserved on return.
 *
 * @param policy - The policy to freeze in place.
 * @returns The same policy reference, frozen at every level.
 */
export function deepFreezePolicy<TPolicy extends AccessControl.IPolicy>(policy: TPolicy): TPolicy {
  if (stryMutAct_9fa48("39")) {
    {}
  } else {
    stryCov_9fa48("39");
    for (const rule of policy.rules) {
      if (stryMutAct_9fa48("40")) {
        {}
      } else {
        stryCov_9fa48("40");
        if (stryMutAct_9fa48("42") ? false : stryMutAct_9fa48("41") ? true : (stryCov_9fa48("41", "42"), Array.isArray(rule.actions))) Object.freeze(rule.actions);
        if (stryMutAct_9fa48("44") ? false : stryMutAct_9fa48("43") ? true : (stryCov_9fa48("43", "44"), Array.isArray(rule.resources))) Object.freeze(rule.resources);
        if (stryMutAct_9fa48("46") ? false : stryMutAct_9fa48("45") ? true : (stryCov_9fa48("45", "46"), rule.conditions)) freezeConditionGroup(rule.conditions);
        Object.freeze(rule);
      }
    }
    Object.freeze(policy.rules);
    return Object.freeze(policy);
  }
}
function freezeConditionGroup(group: AccessControl.IConditionGroup): void {
  if (stryMutAct_9fa48("47")) {
    {}
  } else {
    stryCov_9fa48("47");
    const obj = group as Record<'all' | 'any' | 'none', ReadonlyArray<AccessControl.ICondition | AccessControl.IConditionGroup> | undefined>;
    for (const key of ['all', 'any', 'none'] as const) {
      if (stryMutAct_9fa48("48")) {
        {}
      } else {
        stryCov_9fa48("48");
        const arr = obj[key];
        if (stryMutAct_9fa48("51") ? false : stryMutAct_9fa48("50") ? true : stryMutAct_9fa48("49") ? Array.isArray(arr) : (stryCov_9fa48("49", "50", "51"), !Array.isArray(arr))) continue;
        for (const item of arr) {
          if (stryMutAct_9fa48("52")) {
            {}
          } else {
            stryCov_9fa48("52");
            if (stryMutAct_9fa48("54") ? false : stryMutAct_9fa48("53") ? true : (stryCov_9fa48("53", "54"), (stryMutAct_9fa48("55") ? "" : (stryCov_9fa48("55"), 'field')) in item)) Object.freeze(item);else freezeConditionGroup(item);
          }
        }
        Object.freeze(arr);
      }
    }
    Object.freeze(group);
  }
}
/**
 * Enrich a subject's roles with scoped role assignments matching the request scope.
 *
 * If a user has role `'editor'` scoped to `'org-1'` and the request scope is `'org-1'`,
 * `'editor'` is added to `subject.roles` for this evaluation. Returns the original
 * subject unchanged when no scoped roles match.
 *
 * @template TScope - Union of valid scope strings.
 *
 * @param subject - The resolved subject with potential scoped role assignments
 * @param scope   - The scope to match against scoped role assignments
 * @returns A new subject with merged roles, or the original subject if no matches
 */
export function enrichSubjectWithScopedRoles<TScope extends string = string>(subject: Request.ISubject, scope: TScope | undefined): Request.ISubject {
  if (stryMutAct_9fa48("56")) {
    {}
  } else {
    stryCov_9fa48("56");
    if (stryMutAct_9fa48("59") ? scope == null && !subject.scopedRoles?.length : stryMutAct_9fa48("58") ? false : stryMutAct_9fa48("57") ? true : (stryCov_9fa48("57", "58", "59"), (stryMutAct_9fa48("61") ? scope != null : stryMutAct_9fa48("60") ? false : (stryCov_9fa48("60", "61"), scope == null)) || (stryMutAct_9fa48("62") ? subject.scopedRoles?.length : (stryCov_9fa48("62"), !(stryMutAct_9fa48("63") ? subject.scopedRoles.length : (stryCov_9fa48("63"), subject.scopedRoles?.length)))))) return subject;
    const extraRoles = stryMutAct_9fa48("64") ? subject.scopedRoles.map(sr => sr.role) : (stryCov_9fa48("64"), subject.scopedRoles.filter(stryMutAct_9fa48("65") ? () => undefined : (stryCov_9fa48("65"), sr => stryMutAct_9fa48("68") ? sr.scope !== scope : stryMutAct_9fa48("67") ? false : stryMutAct_9fa48("66") ? true : (stryCov_9fa48("66", "67", "68"), sr.scope === scope))).map(stryMutAct_9fa48("69") ? () => undefined : (stryCov_9fa48("69"), sr => sr.role)));
    if (stryMutAct_9fa48("72") ? extraRoles.length !== 0 : stryMutAct_9fa48("71") ? false : stryMutAct_9fa48("70") ? true : (stryCov_9fa48("70", "71", "72"), extraRoles.length === 0)) return subject;
    const mergedRoles = stryMutAct_9fa48("73") ? [] : (stryCov_9fa48("73"), [...new Set(stryMutAct_9fa48("74") ? [] : (stryCov_9fa48("74"), [...subject.roles, ...extraRoles]))]);
    return stryMutAct_9fa48("75") ? {} : (stryCov_9fa48("75"), {
      ...subject,
      roles: mergedRoles
    });
  }
}

/**
 * Create an {@link EngineTypes.IAdmin} instance that delegates storage operations to the
 * given adapter and invalidates the engine's caches after mutations.
 *
 * @template TAction   - Union of valid action strings.
 * @template TResource - Union of valid resource strings.
 * @template TRole     - Union of valid role IDs.
 * @template TScope    - Union of valid scope strings.
 *
 * @param adapter - The storage adapter for policies, roles, and subject data
 * @param engine  - The engine instance whose caches should be invalidated on writes
 * @returns An {@link EngineTypes.IAdmin} object wired to the adapter and engine
 */
export function createAdmin<TAction extends string = string, TResource extends string = string, TRole extends string = string, TScope extends string = string>(adapter: Adapter.IAdapter<TAction, TResource, TRole, TScope>, engine: {
  invalidatePolicies(): void;
  invalidateRoles(roleId?: TRole): void;
  invalidateSubject(subjectId: string): void;
}): EngineTypes.IAdmin<TAction, TResource, TRole, TScope> {
  if (stryMutAct_9fa48("76")) {
    {}
  } else {
    stryCov_9fa48("76");
    return stryMutAct_9fa48("77") ? {} : (stryCov_9fa48("77"), {
      async listPolicies() {
        if (stryMutAct_9fa48("78")) {
          {}
        } else {
          stryCov_9fa48("78");
          return adapter.listPolicies();
        }
      },
      async getPolicy(id: string) {
        if (stryMutAct_9fa48("79")) {
          {}
        } else {
          stryCov_9fa48("79");
          return adapter.getPolicy(id);
        }
      },
      async savePolicy(policy: AccessControl.IPolicy<TAction, TResource, TRole>) {
        if (stryMutAct_9fa48("80")) {
          {}
        } else {
          stryCov_9fa48("80");
          const {
            validatePolicy
          } = await _getValidate();
          assertValidOrThrow(stryMutAct_9fa48("81") ? "" : (stryCov_9fa48("81"), 'policy'), validatePolicy(policy));
          await adapter.savePolicy(policy);
          engine.invalidatePolicies();
        }
      },
      async deletePolicy(id: string) {
        if (stryMutAct_9fa48("82")) {
          {}
        } else {
          stryCov_9fa48("82");
          await adapter.deletePolicy(id);
          engine.invalidatePolicies();
        }
      },
      async listRoles() {
        if (stryMutAct_9fa48("83")) {
          {}
        } else {
          stryCov_9fa48("83");
          return adapter.listRoles();
        }
      },
      async getRole(id: string) {
        if (stryMutAct_9fa48("84")) {
          {}
        } else {
          stryCov_9fa48("84");
          return adapter.getRole(id);
        }
      },
      async saveRole(role: AccessControl.IRole<TAction, TResource, TRole, TScope>) {
        if (stryMutAct_9fa48("85")) {
          {}
        } else {
          stryCov_9fa48("85");
          const {
            validateRole
          } = await _getValidate();
          assertValidOrThrow(stryMutAct_9fa48("86") ? "" : (stryCov_9fa48("86"), 'role'), validateRole(role));
          await adapter.saveRole(role);
          engine.invalidateRoles(role.id);
        }
      },
      async deleteRole(id: string) {
        if (stryMutAct_9fa48("87")) {
          {}
        } else {
          stryCov_9fa48("87");
          await adapter.deleteRole(id);
          engine.invalidateRoles(id as TRole);
        }
      },
      async assignRole(subjectId: string, roleId: TRole, scope?: TScope) {
        if (stryMutAct_9fa48("88")) {
          {}
        } else {
          stryCov_9fa48("88");
          await adapter.assignRole(subjectId, roleId, scope);
          engine.invalidateSubject(subjectId);
        }
      },
      async revokeRole(subjectId: string, roleId: TRole, scope?: TScope) {
        if (stryMutAct_9fa48("89")) {
          {}
        } else {
          stryCov_9fa48("89");
          await adapter.revokeRole(subjectId, roleId, scope);
          engine.invalidateSubject(subjectId);
        }
      },
      async setAttributes(subjectId: string, attrs: Primitives.Attributes) {
        if (stryMutAct_9fa48("90")) {
          {}
        } else {
          stryCov_9fa48("90");
          await adapter.setSubjectAttributes(subjectId, attrs);
          engine.invalidateSubject(subjectId);
        }
      },
      async getAttributes(subjectId: string) {
        if (stryMutAct_9fa48("91")) {
          {}
        } else {
          stryCov_9fa48("91");
          return adapter.getSubjectAttributes(subjectId);
        }
      },
      async export(): Promise<EngineTypes.ISnapshot<TAction, TResource, TRole, TScope>> {
        if (stryMutAct_9fa48("92")) {
          {}
        } else {
          stryCov_9fa48("92");
          const [policies, roles] = await Promise.all(stryMutAct_9fa48("93") ? [] : (stryCov_9fa48("93"), [adapter.listPolicies(), adapter.listRoles()]));
          return stryMutAct_9fa48("94") ? {} : (stryCov_9fa48("94"), {
            schemaVersion: 1 as const,
            exportedAt: new Date().toISOString(),
            policies,
            roles
          });
        }
      },
      async import(snapshot: EngineTypes.ISnapshot<TAction, TResource, TRole, TScope>, options: EngineTypes.IImportOptions = {}): Promise<EngineTypes.IImportResult> {
        if (stryMutAct_9fa48("95")) {
          {}
        } else {
          stryCov_9fa48("95");
          if (stryMutAct_9fa48("98") ? snapshot?.schemaVersion === 1 : stryMutAct_9fa48("97") ? false : stryMutAct_9fa48("96") ? true : (stryCov_9fa48("96", "97", "98"), (stryMutAct_9fa48("99") ? snapshot.schemaVersion : (stryCov_9fa48("99"), snapshot?.schemaVersion)) !== 1)) {
            if (stryMutAct_9fa48("100")) {
              {}
            } else {
              stryCov_9fa48("100");
              throw new Error(stryMutAct_9fa48("101") ? `` : (stryCov_9fa48("101"), `duck-iam: unsupported snapshot schemaVersion ${stryMutAct_9fa48("102") ? (snapshot as {
                schemaVersion?: unknown;
              }).schemaVersion : (stryCov_9fa48("102"), (snapshot as {
                schemaVersion?: unknown;
              })?.schemaVersion)}; expected 1`));
            }
          }
          const mode = stryMutAct_9fa48("103") ? options.mode && 'merge' : (stryCov_9fa48("103"), options.mode ?? (stryMutAct_9fa48("104") ? "" : (stryCov_9fa48("104"), 'merge')));
          let policiesDeleted = 0;
          let rolesDeleted = 0;
          if (stryMutAct_9fa48("107") ? mode !== 'replace' : stryMutAct_9fa48("106") ? false : stryMutAct_9fa48("105") ? true : (stryCov_9fa48("105", "106", "107"), mode === (stryMutAct_9fa48("108") ? "" : (stryCov_9fa48("108"), 'replace')))) {
            if (stryMutAct_9fa48("109")) {
              {}
            } else {
              stryCov_9fa48("109");
              const [existingPolicies, existingRoles] = await Promise.all(stryMutAct_9fa48("110") ? [] : (stryCov_9fa48("110"), [adapter.listPolicies(), adapter.listRoles()]));
              const incomingPolicyIds = new Set(snapshot.policies.map(stryMutAct_9fa48("111") ? () => undefined : (stryCov_9fa48("111"), p => p.id)));
              const incomingRoleIds = new Set(snapshot.roles.map(stryMutAct_9fa48("112") ? () => undefined : (stryCov_9fa48("112"), r => r.id)));
              for (const p of existingPolicies) {
                if (stryMutAct_9fa48("113")) {
                  {}
                } else {
                  stryCov_9fa48("113");
                  if (stryMutAct_9fa48("116") ? false : stryMutAct_9fa48("115") ? true : stryMutAct_9fa48("114") ? incomingPolicyIds.has(p.id) : (stryCov_9fa48("114", "115", "116"), !incomingPolicyIds.has(p.id))) {
                    if (stryMutAct_9fa48("117")) {
                      {}
                    } else {
                      stryCov_9fa48("117");
                      await adapter.deletePolicy(p.id);
                      stryMutAct_9fa48("118") ? policiesDeleted-- : (stryCov_9fa48("118"), policiesDeleted++);
                    }
                  }
                }
              }
              for (const r of existingRoles) {
                if (stryMutAct_9fa48("119")) {
                  {}
                } else {
                  stryCov_9fa48("119");
                  if (stryMutAct_9fa48("122") ? false : stryMutAct_9fa48("121") ? true : stryMutAct_9fa48("120") ? incomingRoleIds.has(r.id) : (stryCov_9fa48("120", "121", "122"), !incomingRoleIds.has(r.id))) {
                    if (stryMutAct_9fa48("123")) {
                      {}
                    } else {
                      stryCov_9fa48("123");
                      await adapter.deleteRole(r.id);
                      stryMutAct_9fa48("124") ? rolesDeleted-- : (stryCov_9fa48("124"), rolesDeleted++);
                    }
                  }
                }
              }
            }
          }
          const {
            validatePolicy,
            validateRole
          } = await _getValidate();
          for (const p of snapshot.policies) {
            if (stryMutAct_9fa48("125")) {
              {}
            } else {
              stryCov_9fa48("125");
              assertValidOrThrow(stryMutAct_9fa48("126") ? "" : (stryCov_9fa48("126"), 'policy'), validatePolicy(p));
              await adapter.savePolicy(p);
            }
          }
          for (const r of snapshot.roles) {
            if (stryMutAct_9fa48("127")) {
              {}
            } else {
              stryCov_9fa48("127");
              assertValidOrThrow(stryMutAct_9fa48("128") ? "" : (stryCov_9fa48("128"), 'role'), validateRole(r));
              await adapter.saveRole(r);
            }
          }
          // Bulk write touched every cache; invalidate once instead of per-row.
          engine.invalidatePolicies();
          engine.invalidateRoles();
          return stryMutAct_9fa48("129") ? {} : (stryCov_9fa48("129"), {
            policiesAdded: snapshot.policies.length,
            policiesDeleted,
            rolesAdded: snapshot.roles.length,
            rolesDeleted
          });
        }
      }
    });
  }
}