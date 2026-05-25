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
import type { Engine } from '..';
import { MAX_CONDITION_DEPTH, MAX_REGEX_LENGTH } from '../conditions/conditions.libs';
import { ALLOWED_ROOTS } from '../resolve/resolve';
import type { Validate } from './validate.types';

/**
 * Maximum number of unbounded quantifiers (`+`, `*`, `{n,}`) allowed in a
 * single `matches` pattern. Beyond this the surface area for catastrophic
 * backtracking gets impractical to reason about, so we refuse outright.
 */
export const MAX_UNBOUNDED_QUANTIFIERS = 4;

/**
 * Largest finite upper bound permitted in a `{n,m}` quantifier. The matcher
 * walks `m` iterations worst-case, so anything above ~1000 starts to look
 * like a DoS vector even though it isn't technically unbounded.
 */
export const MAX_BOUNDED_QUANTIFIER = 1_000;

/**
 * Pure-JS heuristic for catastrophic-backtracking regex patterns. Cheap
 * enough to run at validate-time on every `matches` operator, and tight
 * enough to refuse the common ReDoS shapes:
 *   - nested quantifiers: `(a+)+`, `(a*)*`, `(a+)*`, `(a*)+`
 *   - alternation inside a quantifier: `(a|a)+`, `(foo|bar)*`
 *   - more than {@link MAX_UNBOUNDED_QUANTIFIERS} unbounded quantifiers in
 *     a single pattern
 *   - backreference followed by a quantifier (`(\w+)\1+`, `(?<n>\w+)\k<n>+`)
 *   - bounded quantifier with large upper bound (`a{1,1000000}`)
 *   - lookaround group containing a quantifier (`(?=(a+)+)`)
 *
 * Not a complete safe-regex linter — it deliberately errs on the side of
 * rejection. Patterns deemed unsafe should not even compile, so the runtime
 * never sees them.
 *
 * @param pattern - Raw regex source.
 * @returns `{ safe: true }` when the pattern looks benign, otherwise
 *   `{ safe: false, reason }` with a short human-readable reason.
 */
export function detectCatastrophicRegex(pattern: string): {
  safe: boolean;
  reason?: string;
} {
  if (stryMutAct_9fa48("0")) {
    {}
  } else {
    stryCov_9fa48("0");
    if (stryMutAct_9fa48("3") ? typeof pattern === 'string' : stryMutAct_9fa48("2") ? false : stryMutAct_9fa48("1") ? true : (stryCov_9fa48("1", "2", "3"), typeof pattern !== (stryMutAct_9fa48("4") ? "" : (stryCov_9fa48("4"), 'string')))) return stryMutAct_9fa48("5") ? {} : (stryCov_9fa48("5"), {
      safe: stryMutAct_9fa48("6") ? true : (stryCov_9fa48("6"), false),
      reason: stryMutAct_9fa48("7") ? "" : (stryCov_9fa48("7"), 'pattern must be a string')
    });
    if (stryMutAct_9fa48("11") ? pattern.length <= MAX_REGEX_LENGTH : stryMutAct_9fa48("10") ? pattern.length >= MAX_REGEX_LENGTH : stryMutAct_9fa48("9") ? false : stryMutAct_9fa48("8") ? true : (stryCov_9fa48("8", "9", "10", "11"), pattern.length > MAX_REGEX_LENGTH)) {
      if (stryMutAct_9fa48("12")) {
        {}
      } else {
        stryCov_9fa48("12");
        return stryMutAct_9fa48("13") ? {} : (stryCov_9fa48("13"), {
          safe: stryMutAct_9fa48("14") ? true : (stryCov_9fa48("14"), false),
          reason: stryMutAct_9fa48("15") ? `` : (stryCov_9fa48("15"), `pattern length ${pattern.length} exceeds MAX_REGEX_LENGTH (${MAX_REGEX_LENGTH})`)
        });
      }
    }

    // Backreference followed by a quantifier — run before the nested-quantifier
    // scan so the more specific reason wins for shapes like `(\w+)\1+`. Numeric
    // (`\1+`, `\3*`, `\2{1,5}`) and named (`\k<name>+`) forms can drive
    // exponential backtracking when the captured group matches a variable-length
    // pattern. Flag any backref+quantifier pair.
    if (stryMutAct_9fa48("18") ? /\\[1-9]\d*\s*[+*?{]/.test(pattern) && /\\k<[^>]+>\s*[+*?{]/.test(pattern) : stryMutAct_9fa48("17") ? false : stryMutAct_9fa48("16") ? true : (stryCov_9fa48("16", "17", "18"), (stryMutAct_9fa48("24") ? /\\[1-9]\d*\s*[^+*?{]/ : stryMutAct_9fa48("23") ? /\\[1-9]\d*\S*[+*?{]/ : stryMutAct_9fa48("22") ? /\\[1-9]\d*\s[+*?{]/ : stryMutAct_9fa48("21") ? /\\[1-9]\D*\s*[+*?{]/ : stryMutAct_9fa48("20") ? /\\[1-9]\d\s*[+*?{]/ : stryMutAct_9fa48("19") ? /\\[^1-9]\d*\s*[+*?{]/ : (stryCov_9fa48("19", "20", "21", "22", "23", "24"), /\\[1-9]\d*\s*[+*?{]/)).test(pattern) || (stryMutAct_9fa48("29") ? /\\k<[^>]+>\s*[^+*?{]/ : stryMutAct_9fa48("28") ? /\\k<[^>]+>\S*[+*?{]/ : stryMutAct_9fa48("27") ? /\\k<[^>]+>\s[+*?{]/ : stryMutAct_9fa48("26") ? /\\k<[>]+>\s*[+*?{]/ : stryMutAct_9fa48("25") ? /\\k<[^>]>\s*[+*?{]/ : (stryCov_9fa48("25", "26", "27", "28", "29"), /\\k<[^>]+>\s*[+*?{]/)).test(pattern))) {
      if (stryMutAct_9fa48("30")) {
        {}
      } else {
        stryCov_9fa48("30");
        return stryMutAct_9fa48("31") ? {} : (stryCov_9fa48("31"), {
          safe: stryMutAct_9fa48("32") ? true : (stryCov_9fa48("32"), false),
          reason: stryMutAct_9fa48("33") ? "" : (stryCov_9fa48("33"), 'backref-quantifier')
        });
      }
    }

    // Lookaround group whose body contains a quantifier. Run before the
    // nested-quantifier scan so `(?=(a+)+)` is reported with the more specific
    // reason. JS supports `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`. Walk
    // paren depth and inspect the body of any lookaround for `+`, `*`, or
    // `{...}`.
    for (let i = 0; stryMutAct_9fa48("36") ? i >= pattern.length : stryMutAct_9fa48("35") ? i <= pattern.length : stryMutAct_9fa48("34") ? false : (stryCov_9fa48("34", "35", "36"), i < pattern.length); stryMutAct_9fa48("37") ? i-- : (stryCov_9fa48("37"), i++)) {
      if (stryMutAct_9fa48("38")) {
        {}
      } else {
        stryCov_9fa48("38");
        const ch = pattern[i];
        if (stryMutAct_9fa48("41") ? ch !== '\\' : stryMutAct_9fa48("40") ? false : stryMutAct_9fa48("39") ? true : (stryCov_9fa48("39", "40", "41"), ch === (stryMutAct_9fa48("42") ? "" : (stryCov_9fa48("42"), '\\')))) {
          if (stryMutAct_9fa48("43")) {
            {}
          } else {
            stryCov_9fa48("43");
            stryMutAct_9fa48("44") ? i-- : (stryCov_9fa48("44"), i++);
            continue;
          }
        }
        if (stryMutAct_9fa48("47") ? ch === '(' : stryMutAct_9fa48("46") ? false : stryMutAct_9fa48("45") ? true : (stryCov_9fa48("45", "46", "47"), ch !== (stryMutAct_9fa48("48") ? "" : (stryCov_9fa48("48"), '(')))) continue;
        const tail3 = stryMutAct_9fa48("49") ? pattern : (stryCov_9fa48("49"), pattern.slice(i, stryMutAct_9fa48("50") ? i - 3 : (stryCov_9fa48("50"), i + 3)));
        const tail4 = stryMutAct_9fa48("51") ? pattern : (stryCov_9fa48("51"), pattern.slice(i, stryMutAct_9fa48("52") ? i - 4 : (stryCov_9fa48("52"), i + 4)));
        const isLookahead = stryMutAct_9fa48("55") ? tail3 === '(?=' && tail3 === '(?!' : stryMutAct_9fa48("54") ? false : stryMutAct_9fa48("53") ? true : (stryCov_9fa48("53", "54", "55"), (stryMutAct_9fa48("57") ? tail3 !== '(?=' : stryMutAct_9fa48("56") ? false : (stryCov_9fa48("56", "57"), tail3 === (stryMutAct_9fa48("58") ? "" : (stryCov_9fa48("58"), '(?=')))) || (stryMutAct_9fa48("60") ? tail3 !== '(?!' : stryMutAct_9fa48("59") ? false : (stryCov_9fa48("59", "60"), tail3 === (stryMutAct_9fa48("61") ? "" : (stryCov_9fa48("61"), '(?!')))));
        const isLookbehind = stryMutAct_9fa48("64") ? tail4 === '(?<=' && tail4 === '(?<!' : stryMutAct_9fa48("63") ? false : stryMutAct_9fa48("62") ? true : (stryCov_9fa48("62", "63", "64"), (stryMutAct_9fa48("66") ? tail4 !== '(?<=' : stryMutAct_9fa48("65") ? false : (stryCov_9fa48("65", "66"), tail4 === (stryMutAct_9fa48("67") ? "" : (stryCov_9fa48("67"), '(?<=')))) || (stryMutAct_9fa48("69") ? tail4 !== '(?<!' : stryMutAct_9fa48("68") ? false : (stryCov_9fa48("68", "69"), tail4 === (stryMutAct_9fa48("70") ? "" : (stryCov_9fa48("70"), '(?<!')))));
        if (stryMutAct_9fa48("73") ? !isLookahead || !isLookbehind : stryMutAct_9fa48("72") ? false : stryMutAct_9fa48("71") ? true : (stryCov_9fa48("71", "72", "73"), (stryMutAct_9fa48("74") ? isLookahead : (stryCov_9fa48("74"), !isLookahead)) && (stryMutAct_9fa48("75") ? isLookbehind : (stryCov_9fa48("75"), !isLookbehind)))) continue;
        const bodyStart = stryMutAct_9fa48("76") ? i - (isLookahead ? 3 : 4) : (stryCov_9fa48("76"), i + (isLookahead ? 3 : 4));
        let depth = 1;
        let j = bodyStart;
        while (stryMutAct_9fa48("78") ? j < pattern.length || depth > 0 : stryMutAct_9fa48("77") ? false : (stryCov_9fa48("77", "78"), (stryMutAct_9fa48("81") ? j >= pattern.length : stryMutAct_9fa48("80") ? j <= pattern.length : stryMutAct_9fa48("79") ? true : (stryCov_9fa48("79", "80", "81"), j < pattern.length)) && (stryMutAct_9fa48("84") ? depth <= 0 : stryMutAct_9fa48("83") ? depth >= 0 : stryMutAct_9fa48("82") ? true : (stryCov_9fa48("82", "83", "84"), depth > 0)))) {
          if (stryMutAct_9fa48("85")) {
            {}
          } else {
            stryCov_9fa48("85");
            const cj = pattern[j];
            if (stryMutAct_9fa48("88") ? cj !== '\\' : stryMutAct_9fa48("87") ? false : stryMutAct_9fa48("86") ? true : (stryCov_9fa48("86", "87", "88"), cj === (stryMutAct_9fa48("89") ? "" : (stryCov_9fa48("89"), '\\')))) {
              if (stryMutAct_9fa48("90")) {
                {}
              } else {
                stryCov_9fa48("90");
                stryMutAct_9fa48("91") ? j -= 2 : (stryCov_9fa48("91"), j += 2);
                continue;
              }
            }
            if (stryMutAct_9fa48("94") ? cj !== '(' : stryMutAct_9fa48("93") ? false : stryMutAct_9fa48("92") ? true : (stryCov_9fa48("92", "93", "94"), cj === (stryMutAct_9fa48("95") ? "" : (stryCov_9fa48("95"), '(')))) stryMutAct_9fa48("96") ? depth-- : (stryCov_9fa48("96"), depth++);else if (stryMutAct_9fa48("99") ? cj !== ')' : stryMutAct_9fa48("98") ? false : stryMutAct_9fa48("97") ? true : (stryCov_9fa48("97", "98", "99"), cj === (stryMutAct_9fa48("100") ? "" : (stryCov_9fa48("100"), ')')))) stryMutAct_9fa48("101") ? depth++ : (stryCov_9fa48("101"), depth--);
            if (stryMutAct_9fa48("104") ? depth !== 0 : stryMutAct_9fa48("103") ? false : stryMutAct_9fa48("102") ? true : (stryCov_9fa48("102", "103", "104"), depth === 0)) break;
            stryMutAct_9fa48("105") ? j-- : (stryCov_9fa48("105"), j++);
          }
        }
        if (stryMutAct_9fa48("108") ? depth === 0 : stryMutAct_9fa48("107") ? false : stryMutAct_9fa48("106") ? true : (stryCov_9fa48("106", "107", "108"), depth !== 0)) continue;
        const body = stryMutAct_9fa48("109") ? pattern : (stryCov_9fa48("109"), pattern.slice(bodyStart, j));
        const bodyStripped = body.replace(/\\./g, stryMutAct_9fa48("110") ? "Stryker was here!" : (stryCov_9fa48("110"), ''));
        if (stryMutAct_9fa48("113") ? /[+*]/.test(bodyStripped) && /\{\d+,?\d*\}/.test(bodyStripped) : stryMutAct_9fa48("112") ? false : stryMutAct_9fa48("111") ? true : (stryCov_9fa48("111", "112", "113"), (stryMutAct_9fa48("114") ? /[^+*]/ : (stryCov_9fa48("114"), /[+*]/)).test(bodyStripped) || (stryMutAct_9fa48("119") ? /\{\d+,?\D*\}/ : stryMutAct_9fa48("118") ? /\{\d+,?\d\}/ : stryMutAct_9fa48("117") ? /\{\d+,\d*\}/ : stryMutAct_9fa48("116") ? /\{\D+,?\d*\}/ : stryMutAct_9fa48("115") ? /\{\d,?\d*\}/ : (stryCov_9fa48("115", "116", "117", "118", "119"), /\{\d+,?\d*\}/)).test(bodyStripped))) {
          if (stryMutAct_9fa48("120")) {
            {}
          } else {
            stryCov_9fa48("120");
            return stryMutAct_9fa48("121") ? {} : (stryCov_9fa48("121"), {
              safe: stryMutAct_9fa48("122") ? true : (stryCov_9fa48("122"), false),
              reason: stryMutAct_9fa48("123") ? "" : (stryCov_9fa48("123"), 'lookaround-with-quantifier')
            });
          }
        }
        i = j;
      }
    }

    // Bounded `{n,m}` with a very large upper bound, or `{n,}` with a very
    // large lower bound. Lone repetitions like `a{5}` are fine; only the
    // comma-form is a range.
    {
      if (stryMutAct_9fa48("124")) {
        {}
      } else {
        stryCov_9fa48("124");
        const re = stryMutAct_9fa48("130") ? /(?<!\\)\{(\d+)(?:,(\D*))?\}/g : stryMutAct_9fa48("129") ? /(?<!\\)\{(\d+)(?:,(\d))?\}/g : stryMutAct_9fa48("128") ? /(?<!\\)\{(\d+)(?:,(\d*))\}/g : stryMutAct_9fa48("127") ? /(?<!\\)\{(\D+)(?:,(\d*))?\}/g : stryMutAct_9fa48("126") ? /(?<!\\)\{(\d)(?:,(\d*))?\}/g : stryMutAct_9fa48("125") ? /(?<=\\)\{(\d+)(?:,(\d*))?\}/g : (stryCov_9fa48("125", "126", "127", "128", "129", "130"), /(?<!\\)\{(\d+)(?:,(\d*))?\}/g);
        let m: RegExpExecArray | null;
        // biome-ignore lint/suspicious/noAssignInExpressions: classic regex iteration
        while (stryMutAct_9fa48("132") ? (m = re.exec(pattern)) === null : stryMutAct_9fa48("131") ? false : (stryCov_9fa48("131", "132"), (m = re.exec(pattern)) !== null)) {
          if (stryMutAct_9fa48("133")) {
            {}
          } else {
            stryCov_9fa48("133");
            const low = Number(m[1]);
            const upperStr = m[2];
            if (stryMutAct_9fa48("136") ? upperStr !== undefined : stryMutAct_9fa48("135") ? false : stryMutAct_9fa48("134") ? true : (stryCov_9fa48("134", "135", "136"), upperStr === undefined)) continue; // `{n}` exact count — not a range.
            if (stryMutAct_9fa48("139") ? upperStr !== '' : stryMutAct_9fa48("138") ? false : stryMutAct_9fa48("137") ? true : (stryCov_9fa48("137", "138", "139"), upperStr === (stryMutAct_9fa48("140") ? "Stryker was here!" : (stryCov_9fa48("140"), '')))) {
              if (stryMutAct_9fa48("141")) {
                {}
              } else {
                stryCov_9fa48("141");
                if (stryMutAct_9fa48("145") ? low <= MAX_BOUNDED_QUANTIFIER : stryMutAct_9fa48("144") ? low >= MAX_BOUNDED_QUANTIFIER : stryMutAct_9fa48("143") ? false : stryMutAct_9fa48("142") ? true : (stryCov_9fa48("142", "143", "144", "145"), low > MAX_BOUNDED_QUANTIFIER)) {
                  if (stryMutAct_9fa48("146")) {
                    {}
                  } else {
                    stryCov_9fa48("146");
                    return stryMutAct_9fa48("147") ? {} : (stryCov_9fa48("147"), {
                      safe: stryMutAct_9fa48("148") ? true : (stryCov_9fa48("148"), false),
                      reason: stryMutAct_9fa48("149") ? "" : (stryCov_9fa48("149"), 'bounded-large-quantifier')
                    });
                  }
                }
                continue;
              }
            }
            const high = Number(upperStr);
            if (stryMutAct_9fa48("152") ? Number.isFinite(high) || high > MAX_BOUNDED_QUANTIFIER : stryMutAct_9fa48("151") ? false : stryMutAct_9fa48("150") ? true : (stryCov_9fa48("150", "151", "152"), Number.isFinite(high) && (stryMutAct_9fa48("155") ? high <= MAX_BOUNDED_QUANTIFIER : stryMutAct_9fa48("154") ? high >= MAX_BOUNDED_QUANTIFIER : stryMutAct_9fa48("153") ? true : (stryCov_9fa48("153", "154", "155"), high > MAX_BOUNDED_QUANTIFIER)))) {
              if (stryMutAct_9fa48("156")) {
                {}
              } else {
                stryCov_9fa48("156");
                return stryMutAct_9fa48("157") ? {} : (stryCov_9fa48("157"), {
                  safe: stryMutAct_9fa48("158") ? true : (stryCov_9fa48("158"), false),
                  reason: stryMutAct_9fa48("159") ? "" : (stryCov_9fa48("159"), 'bounded-large-quantifier')
                });
              }
            }
          }
        }
      }
    } // Nested quantifiers: a group whose closing `)` is immediately followed by
    // `+`, `*`, or `{n,}` AND whose body itself contains an unbounded quantifier.
    // We walk parens with a depth counter so nested groups are inspected too.
    const stack: number[] = stryMutAct_9fa48("160") ? ["Stryker was here"] : (stryCov_9fa48("160"), []);
    for (let i = 0; stryMutAct_9fa48("163") ? i >= pattern.length : stryMutAct_9fa48("162") ? i <= pattern.length : stryMutAct_9fa48("161") ? false : (stryCov_9fa48("161", "162", "163"), i < pattern.length); stryMutAct_9fa48("164") ? i-- : (stryCov_9fa48("164"), i++)) {
      if (stryMutAct_9fa48("165")) {
        {}
      } else {
        stryCov_9fa48("165");
        const ch = pattern[i];
        if (stryMutAct_9fa48("168") ? ch !== '\\' : stryMutAct_9fa48("167") ? false : stryMutAct_9fa48("166") ? true : (stryCov_9fa48("166", "167", "168"), ch === (stryMutAct_9fa48("169") ? "" : (stryCov_9fa48("169"), '\\')))) {
          if (stryMutAct_9fa48("170")) {
            {}
          } else {
            stryCov_9fa48("170");
            stryMutAct_9fa48("171") ? i-- : (stryCov_9fa48("171"), i++);
            continue;
          }
        }
        if (stryMutAct_9fa48("174") ? ch !== '(' : stryMutAct_9fa48("173") ? false : stryMutAct_9fa48("172") ? true : (stryCov_9fa48("172", "173", "174"), ch === (stryMutAct_9fa48("175") ? "" : (stryCov_9fa48("175"), '(')))) {
          if (stryMutAct_9fa48("176")) {
            {}
          } else {
            stryCov_9fa48("176");
            stack.push(i);
            continue;
          }
        }
        if (stryMutAct_9fa48("179") ? ch !== ')' : stryMutAct_9fa48("178") ? false : stryMutAct_9fa48("177") ? true : (stryCov_9fa48("177", "178", "179"), ch === (stryMutAct_9fa48("180") ? "" : (stryCov_9fa48("180"), ')')))) {
          if (stryMutAct_9fa48("181")) {
            {}
          } else {
            stryCov_9fa48("181");
            const openIdx = stack.pop();
            if (stryMutAct_9fa48("184") ? openIdx !== undefined : stryMutAct_9fa48("183") ? false : stryMutAct_9fa48("182") ? true : (stryCov_9fa48("182", "183", "184"), openIdx === undefined)) continue;
            const next = pattern[stryMutAct_9fa48("185") ? i - 1 : (stryCov_9fa48("185"), i + 1)];
            const isUnboundedQuant = stryMutAct_9fa48("188") ? (next === '+' || next === '*') && next === '{' && /^\{\d+,\}?/.test(pattern.slice(i + 1)) : stryMutAct_9fa48("187") ? false : stryMutAct_9fa48("186") ? true : (stryCov_9fa48("186", "187", "188"), (stryMutAct_9fa48("190") ? next === '+' && next === '*' : stryMutAct_9fa48("189") ? false : (stryCov_9fa48("189", "190"), (stryMutAct_9fa48("192") ? next !== '+' : stryMutAct_9fa48("191") ? false : (stryCov_9fa48("191", "192"), next === (stryMutAct_9fa48("193") ? "" : (stryCov_9fa48("193"), '+')))) || (stryMutAct_9fa48("195") ? next !== '*' : stryMutAct_9fa48("194") ? false : (stryCov_9fa48("194", "195"), next === (stryMutAct_9fa48("196") ? "" : (stryCov_9fa48("196"), '*')))))) || (stryMutAct_9fa48("198") ? next === '{' || /^\{\d+,\}?/.test(pattern.slice(i + 1)) : stryMutAct_9fa48("197") ? false : (stryCov_9fa48("197", "198"), (stryMutAct_9fa48("200") ? next !== '{' : stryMutAct_9fa48("199") ? true : (stryCov_9fa48("199", "200"), next === (stryMutAct_9fa48("201") ? "" : (stryCov_9fa48("201"), '{')))) && (stryMutAct_9fa48("205") ? /^\{\d+,\}/ : stryMutAct_9fa48("204") ? /^\{\D+,\}?/ : stryMutAct_9fa48("203") ? /^\{\d,\}?/ : stryMutAct_9fa48("202") ? /\{\d+,\}?/ : (stryCov_9fa48("202", "203", "204", "205"), /^\{\d+,\}?/)).test(stryMutAct_9fa48("206") ? pattern : (stryCov_9fa48("206"), pattern.slice(stryMutAct_9fa48("207") ? i - 1 : (stryCov_9fa48("207"), i + 1)))))));
            if (stryMutAct_9fa48("210") ? false : stryMutAct_9fa48("209") ? true : stryMutAct_9fa48("208") ? isUnboundedQuant : (stryCov_9fa48("208", "209", "210"), !isUnboundedQuant)) continue;
            const body = stryMutAct_9fa48("211") ? pattern : (stryCov_9fa48("211"), pattern.slice(stryMutAct_9fa48("212") ? openIdx - 1 : (stryCov_9fa48("212"), openIdx + 1), i));
            // Strip escapes from body before scanning so `\+` doesn't trigger.
            const bodyStripped = body.replace(/\\./g, stryMutAct_9fa48("213") ? "Stryker was here!" : (stryCov_9fa48("213"), ''));
            if (stryMutAct_9fa48("216") ? /[+*]/.test(bodyStripped) && /\{\d+,\d*\}/.test(bodyStripped) : stryMutAct_9fa48("215") ? false : stryMutAct_9fa48("214") ? true : (stryCov_9fa48("214", "215", "216"), (stryMutAct_9fa48("217") ? /[^+*]/ : (stryCov_9fa48("217"), /[+*]/)).test(bodyStripped) || (stryMutAct_9fa48("221") ? /\{\d+,\D*\}/ : stryMutAct_9fa48("220") ? /\{\d+,\d\}/ : stryMutAct_9fa48("219") ? /\{\D+,\d*\}/ : stryMutAct_9fa48("218") ? /\{\d,\d*\}/ : (stryCov_9fa48("218", "219", "220", "221"), /\{\d+,\d*\}/)).test(bodyStripped))) {
              if (stryMutAct_9fa48("222")) {
                {}
              } else {
                stryCov_9fa48("222");
                return stryMutAct_9fa48("223") ? {} : (stryCov_9fa48("223"), {
                  safe: stryMutAct_9fa48("224") ? true : (stryCov_9fa48("224"), false),
                  reason: stryMutAct_9fa48("225") ? "" : (stryCov_9fa48("225"), 'nested quantifier (e.g. `(a+)+`) — catastrophic backtracking risk')
                });
              }
            }
            if (stryMutAct_9fa48("227") ? false : stryMutAct_9fa48("226") ? true : (stryCov_9fa48("226", "227"), bodyStripped.includes(stryMutAct_9fa48("228") ? "" : (stryCov_9fa48("228"), '|')))) {
              if (stryMutAct_9fa48("229")) {
                {}
              } else {
                stryCov_9fa48("229");
                return stryMutAct_9fa48("230") ? {} : (stryCov_9fa48("230"), {
                  safe: stryMutAct_9fa48("231") ? true : (stryCov_9fa48("231"), false),
                  reason: stryMutAct_9fa48("232") ? "" : (stryCov_9fa48("232"), 'alternation inside a quantified group — catastrophic backtracking risk')
                });
              }
            }
          }
        }
      }
    }

    // Count unbounded quantifiers outside of escapes. `+`, `*`, and `{n,}`
    // each count once.
    let unbounded = 0;
    for (let i = 0; stryMutAct_9fa48("235") ? i >= pattern.length : stryMutAct_9fa48("234") ? i <= pattern.length : stryMutAct_9fa48("233") ? false : (stryCov_9fa48("233", "234", "235"), i < pattern.length); stryMutAct_9fa48("236") ? i-- : (stryCov_9fa48("236"), i++)) {
      if (stryMutAct_9fa48("237")) {
        {}
      } else {
        stryCov_9fa48("237");
        const ch = pattern[i];
        if (stryMutAct_9fa48("240") ? ch !== '\\' : stryMutAct_9fa48("239") ? false : stryMutAct_9fa48("238") ? true : (stryCov_9fa48("238", "239", "240"), ch === (stryMutAct_9fa48("241") ? "" : (stryCov_9fa48("241"), '\\')))) {
          if (stryMutAct_9fa48("242")) {
            {}
          } else {
            stryCov_9fa48("242");
            stryMutAct_9fa48("243") ? i-- : (stryCov_9fa48("243"), i++);
            continue;
          }
        }
        if (stryMutAct_9fa48("246") ? ch === '+' && ch === '*' : stryMutAct_9fa48("245") ? false : stryMutAct_9fa48("244") ? true : (stryCov_9fa48("244", "245", "246"), (stryMutAct_9fa48("248") ? ch !== '+' : stryMutAct_9fa48("247") ? false : (stryCov_9fa48("247", "248"), ch === (stryMutAct_9fa48("249") ? "" : (stryCov_9fa48("249"), '+')))) || (stryMutAct_9fa48("251") ? ch !== '*' : stryMutAct_9fa48("250") ? false : (stryCov_9fa48("250", "251"), ch === (stryMutAct_9fa48("252") ? "" : (stryCov_9fa48("252"), '*')))))) {
          if (stryMutAct_9fa48("253")) {
            {}
          } else {
            stryCov_9fa48("253");
            stryMutAct_9fa48("254") ? unbounded-- : (stryCov_9fa48("254"), unbounded++);
            continue;
          }
        }
        if (stryMutAct_9fa48("257") ? ch !== '{' : stryMutAct_9fa48("256") ? false : stryMutAct_9fa48("255") ? true : (stryCov_9fa48("255", "256", "257"), ch === (stryMutAct_9fa48("258") ? "" : (stryCov_9fa48("258"), '{')))) {
          if (stryMutAct_9fa48("259")) {
            {}
          } else {
            stryCov_9fa48("259");
            // `{n,}` or `{n,m}` — only `{n,}` (no upper bound) is unbounded.
            const close = pattern.indexOf(stryMutAct_9fa48("260") ? "" : (stryCov_9fa48("260"), '}'), i);
            if (stryMutAct_9fa48("263") ? close !== -1 : stryMutAct_9fa48("262") ? false : stryMutAct_9fa48("261") ? true : (stryCov_9fa48("261", "262", "263"), close === (stryMutAct_9fa48("264") ? +1 : (stryCov_9fa48("264"), -1)))) continue;
            const inner = stryMutAct_9fa48("265") ? pattern : (stryCov_9fa48("265"), pattern.slice(stryMutAct_9fa48("266") ? i - 1 : (stryCov_9fa48("266"), i + 1), close));
            if (stryMutAct_9fa48("268") ? false : stryMutAct_9fa48("267") ? true : (stryCov_9fa48("267", "268"), (stryMutAct_9fa48("274") ? /^\d+,\S*$/ : stryMutAct_9fa48("273") ? /^\d+,\s$/ : stryMutAct_9fa48("272") ? /^\D+,\s*$/ : stryMutAct_9fa48("271") ? /^\d,\s*$/ : stryMutAct_9fa48("270") ? /^\d+,\s*/ : stryMutAct_9fa48("269") ? /\d+,\s*$/ : (stryCov_9fa48("269", "270", "271", "272", "273", "274"), /^\d+,\s*$/)).test(inner))) stryMutAct_9fa48("275") ? unbounded-- : (stryCov_9fa48("275"), unbounded++);
            i = close;
          }
        }
      }
    }
    if (stryMutAct_9fa48("279") ? unbounded <= MAX_UNBOUNDED_QUANTIFIERS : stryMutAct_9fa48("278") ? unbounded >= MAX_UNBOUNDED_QUANTIFIERS : stryMutAct_9fa48("277") ? false : stryMutAct_9fa48("276") ? true : (stryCov_9fa48("276", "277", "278", "279"), unbounded > MAX_UNBOUNDED_QUANTIFIERS)) {
      if (stryMutAct_9fa48("280")) {
        {}
      } else {
        stryCov_9fa48("280");
        return stryMutAct_9fa48("281") ? {} : (stryCov_9fa48("281"), {
          safe: stryMutAct_9fa48("282") ? true : (stryCov_9fa48("282"), false),
          reason: stryMutAct_9fa48("283") ? `` : (stryCov_9fa48("283"), `${unbounded} unbounded quantifiers exceed limit of ${MAX_UNBOUNDED_QUANTIFIERS}`)
        });
      }
    }
    return stryMutAct_9fa48("284") ? {} : (stryCov_9fa48("284"), {
      safe: stryMutAct_9fa48("285") ? false : (stryCov_9fa48("285"), true)
    });
  }
}

/**
 * Field paths longer than this are refused. The runtime DotPath resolver
 * splits on dots, so an enormous field string would cost O(length) work
 * per evaluation with no upside.
 */
export const MAX_FIELD_LENGTH = 256;
/**
 * Valid combining algorithm names.
 */
export const VALID_ALGORITHMS = new Set(stryMutAct_9fa48("286") ? [] : (stryCov_9fa48("286"), [stryMutAct_9fa48("287") ? "" : (stryCov_9fa48("287"), 'deny-overrides'), stryMutAct_9fa48("288") ? "" : (stryCov_9fa48("288"), 'allow-overrides'), stryMutAct_9fa48("289") ? "" : (stryCov_9fa48("289"), 'first-match'), stryMutAct_9fa48("290") ? "" : (stryCov_9fa48("290"), 'highest-priority')]));

/**
 * Valid rule effect values.
 */
export const VALID_EFFECTS = new Set(stryMutAct_9fa48("291") ? [] : (stryCov_9fa48("291"), [stryMutAct_9fa48("292") ? "" : (stryCov_9fa48("292"), 'allow'), stryMutAct_9fa48("293") ? "" : (stryCov_9fa48("293"), 'deny')]));

/**
 * Validate-time policy size caps.
 *
 * `indexPolicy()` builds an `actions x resources` cartesian per rule, so an
 * unbounded policy can stall the event loop. Limits also cap memory growth
 * in {@link Engine}'s LRU caches.
 */
export const POLICY_LIMITS = {
  rulesPerPolicy: 1_000,
  actionsPerRule: 100,
  resourcesPerRule: 100,
  /** Worst-case cartesian product per rule. */
  cartesianPerRule: 1_000
} as const;

/** Whole-path shorthands accepted alongside the dotted roots. */
const RESOLVABLE_SHORTHANDS = new Set(stryMutAct_9fa48("294") ? [] : (stryCov_9fa48("294"), [stryMutAct_9fa48("295") ? "" : (stryCov_9fa48("295"), 'action'), stryMutAct_9fa48("296") ? "" : (stryCov_9fa48("296"), 'scope')]));

/**
 * True when `path` would resolve to a real attribute at evaluation time.
 * Shares {@link ALLOWED_ROOTS} with the resolver so the two stay in lock-step.
 *
 * @param path - Dot-path string to check.
 * @returns `true` when the path's root is a known resolvable root.
 */
export function isResolvablePath(path: string): boolean {
  if (stryMutAct_9fa48("297")) {
    {}
  } else {
    stryCov_9fa48("297");
    if (stryMutAct_9fa48("299") ? false : stryMutAct_9fa48("298") ? true : (stryCov_9fa48("298", "299"), RESOLVABLE_SHORTHANDS.has(path))) return stryMutAct_9fa48("300") ? false : (stryCov_9fa48("300"), true);
    const root = path.split(stryMutAct_9fa48("301") ? "" : (stryCov_9fa48("301"), '.'), 1)[0];
    return stryMutAct_9fa48("304") ? !!root || ALLOWED_ROOTS.has(root) : stryMutAct_9fa48("303") ? false : stryMutAct_9fa48("302") ? true : (stryCov_9fa48("302", "303", "304"), (stryMutAct_9fa48("305") ? !root : (stryCov_9fa48("305"), !(stryMutAct_9fa48("306") ? root : (stryCov_9fa48("306"), !root)))) && ALLOWED_ROOTS.has(root));
  }
}

/**
 * Set of valid condition operator names supported by the condition evaluator.
 */
export const VALID_OPERATORS = new Set(stryMutAct_9fa48("307") ? [] : (stryCov_9fa48("307"), [stryMutAct_9fa48("308") ? "" : (stryCov_9fa48("308"), 'eq'), stryMutAct_9fa48("309") ? "" : (stryCov_9fa48("309"), 'neq'), stryMutAct_9fa48("310") ? "" : (stryCov_9fa48("310"), 'gt'), stryMutAct_9fa48("311") ? "" : (stryCov_9fa48("311"), 'gte'), stryMutAct_9fa48("312") ? "" : (stryCov_9fa48("312"), 'lt'), stryMutAct_9fa48("313") ? "" : (stryCov_9fa48("313"), 'lte'), stryMutAct_9fa48("314") ? "" : (stryCov_9fa48("314"), 'in'), stryMutAct_9fa48("315") ? "" : (stryCov_9fa48("315"), 'nin'), stryMutAct_9fa48("316") ? "" : (stryCov_9fa48("316"), 'contains'), stryMutAct_9fa48("317") ? "" : (stryCov_9fa48("317"), 'not_contains'), stryMutAct_9fa48("318") ? "" : (stryCov_9fa48("318"), 'starts_with'), stryMutAct_9fa48("319") ? "" : (stryCov_9fa48("319"), 'ends_with'), stryMutAct_9fa48("320") ? "" : (stryCov_9fa48("320"), 'matches'), stryMutAct_9fa48("321") ? "" : (stryCov_9fa48("321"), 'exists'), stryMutAct_9fa48("322") ? "" : (stryCov_9fa48("322"), 'not_exists'), stryMutAct_9fa48("323") ? "" : (stryCov_9fa48("323"), 'subset_of'), stryMutAct_9fa48("324") ? "" : (stryCov_9fa48("324"), 'superset_of')]));

/**
 * Validate a single condition item (leaf or group).
 *
 * A leaf condition must have a non-empty `field` string and a valid `operator`.
 * If the item does not contain a `field` key it is treated as a condition group
 * and delegated to {@link validateConditionGroup}.
 *
 * @param input  - The condition item to validate.
 * @param path   - Dot-path prefix used in reported issues.
 * @param issues - Array to push validation issues into.
 * @param depth  - Current nesting depth (defaults to `0`; bounded by `MAX_CONDITION_DEPTH`).
 */
export function validateConditionItem(input: unknown, path: string, issues: Validate.IIssue[], depth = 0): void {
  if (stryMutAct_9fa48("325")) {
    {}
  } else {
    stryCov_9fa48("325");
    if (stryMutAct_9fa48("328") ? typeof input !== 'object' && input === null : stryMutAct_9fa48("327") ? false : stryMutAct_9fa48("326") ? true : (stryCov_9fa48("326", "327", "328"), (stryMutAct_9fa48("330") ? typeof input === 'object' : stryMutAct_9fa48("329") ? false : (stryCov_9fa48("329", "330"), typeof input !== (stryMutAct_9fa48("331") ? "" : (stryCov_9fa48("331"), 'object')))) || (stryMutAct_9fa48("333") ? input !== null : stryMutAct_9fa48("332") ? false : (stryCov_9fa48("332", "333"), input === null)))) {
      if (stryMutAct_9fa48("334")) {
        {}
      } else {
        stryCov_9fa48("334");
        issues.push(stryMutAct_9fa48("335") ? {} : (stryCov_9fa48("335"), {
          type: stryMutAct_9fa48("336") ? "" : (stryCov_9fa48("336"), 'error'),
          code: stryMutAct_9fa48("337") ? "" : (stryCov_9fa48("337"), 'INVALID_CONDITION'),
          message: stryMutAct_9fa48("338") ? "" : (stryCov_9fa48("338"), 'Condition must be an object'),
          path
        }));
        return;
      }
    }
    const obj = input as Record<string, unknown>;
    if (stryMutAct_9fa48("340") ? false : stryMutAct_9fa48("339") ? true : (stryCov_9fa48("339", "340"), (stryMutAct_9fa48("341") ? "" : (stryCov_9fa48("341"), 'field')) in obj)) {
      if (stryMutAct_9fa48("342")) {
        {}
      } else {
        stryCov_9fa48("342");
        if (stryMutAct_9fa48("345") ? typeof obj.field !== 'string' && !obj.field : stryMutAct_9fa48("344") ? false : stryMutAct_9fa48("343") ? true : (stryCov_9fa48("343", "344", "345"), (stryMutAct_9fa48("347") ? typeof obj.field === 'string' : stryMutAct_9fa48("346") ? false : (stryCov_9fa48("346", "347"), typeof obj.field !== (stryMutAct_9fa48("348") ? "" : (stryCov_9fa48("348"), 'string')))) || (stryMutAct_9fa48("349") ? obj.field : (stryCov_9fa48("349"), !obj.field)))) {
          if (stryMutAct_9fa48("350")) {
            {}
          } else {
            stryCov_9fa48("350");
            issues.push(stryMutAct_9fa48("351") ? {} : (stryCov_9fa48("351"), {
              type: stryMutAct_9fa48("352") ? "" : (stryCov_9fa48("352"), 'error'),
              code: stryMutAct_9fa48("353") ? "" : (stryCov_9fa48("353"), 'MISSING_FIELD'),
              message: stryMutAct_9fa48("354") ? "" : (stryCov_9fa48("354"), 'Condition must have a non-empty string "field"'),
              path: stryMutAct_9fa48("355") ? `` : (stryCov_9fa48("355"), `${path}.field`)
            }));
          }
        } else if (stryMutAct_9fa48("359") ? obj.field.length <= MAX_FIELD_LENGTH : stryMutAct_9fa48("358") ? obj.field.length >= MAX_FIELD_LENGTH : stryMutAct_9fa48("357") ? false : stryMutAct_9fa48("356") ? true : (stryCov_9fa48("356", "357", "358", "359"), obj.field.length > MAX_FIELD_LENGTH)) {
          if (stryMutAct_9fa48("360")) {
            {}
          } else {
            stryCov_9fa48("360");
            issues.push(stryMutAct_9fa48("361") ? {} : (stryCov_9fa48("361"), {
              type: stryMutAct_9fa48("362") ? "" : (stryCov_9fa48("362"), 'error'),
              code: stryMutAct_9fa48("363") ? "" : (stryCov_9fa48("363"), 'LIMIT_EXCEEDED'),
              message: stryMutAct_9fa48("364") ? `` : (stryCov_9fa48("364"), `Condition field is ${obj.field.length} chars; limit is ${MAX_FIELD_LENGTH}`),
              path: stryMutAct_9fa48("365") ? `` : (stryCov_9fa48("365"), `${path}.field`)
            }));
          }
        } else if (stryMutAct_9fa48("368") ? false : stryMutAct_9fa48("367") ? true : stryMutAct_9fa48("366") ? isResolvablePath(obj.field) : (stryCov_9fa48("366", "367", "368"), !isResolvablePath(obj.field))) {
          if (stryMutAct_9fa48("369")) {
            {}
          } else {
            stryCov_9fa48("369");
            issues.push(stryMutAct_9fa48("370") ? {} : (stryCov_9fa48("370"), {
              type: stryMutAct_9fa48("371") ? "" : (stryCov_9fa48("371"), 'warning'),
              code: stryMutAct_9fa48("372") ? "" : (stryCov_9fa48("372"), 'UNRESOLVABLE_FIELD'),
              message: stryMutAct_9fa48("373") ? `` : (stryCov_9fa48("373"), `Condition field "${obj.field}" has no resolvable root (expected subject/resource/environment, or shorthand action/scope)`),
              path: stryMutAct_9fa48("374") ? `` : (stryCov_9fa48("374"), `${path}.field`)
            }));
          }
        }
        if (stryMutAct_9fa48("377") ? false : stryMutAct_9fa48("376") ? true : stryMutAct_9fa48("375") ? VALID_OPERATORS.has(obj.operator as string) : (stryCov_9fa48("375", "376", "377"), !VALID_OPERATORS.has(obj.operator as string))) {
          if (stryMutAct_9fa48("378")) {
            {}
          } else {
            stryCov_9fa48("378");
            issues.push(stryMutAct_9fa48("379") ? {} : (stryCov_9fa48("379"), {
              type: stryMutAct_9fa48("380") ? "" : (stryCov_9fa48("380"), 'error'),
              code: stryMutAct_9fa48("381") ? "" : (stryCov_9fa48("381"), 'INVALID_OPERATOR'),
              message: stryMutAct_9fa48("382") ? `` : (stryCov_9fa48("382"), `Invalid operator "${String(obj.operator)}"`),
              path: stryMutAct_9fa48("383") ? `` : (stryCov_9fa48("383"), `${path}.operator`)
            }));
          }
        }
        if (stryMutAct_9fa48("386") ? typeof obj.value === 'string' && obj.value.startsWith('$') || !isResolvablePath(obj.value.slice(1)) : stryMutAct_9fa48("385") ? false : stryMutAct_9fa48("384") ? true : (stryCov_9fa48("384", "385", "386"), (stryMutAct_9fa48("388") ? typeof obj.value === 'string' || obj.value.startsWith('$') : stryMutAct_9fa48("387") ? true : (stryCov_9fa48("387", "388"), (stryMutAct_9fa48("390") ? typeof obj.value !== 'string' : stryMutAct_9fa48("389") ? true : (stryCov_9fa48("389", "390"), typeof obj.value === (stryMutAct_9fa48("391") ? "" : (stryCov_9fa48("391"), 'string')))) && (stryMutAct_9fa48("392") ? obj.value.endsWith('$') : (stryCov_9fa48("392"), obj.value.startsWith(stryMutAct_9fa48("393") ? "" : (stryCov_9fa48("393"), '$')))))) && (stryMutAct_9fa48("394") ? isResolvablePath(obj.value.slice(1)) : (stryCov_9fa48("394"), !isResolvablePath(stryMutAct_9fa48("395") ? obj.value : (stryCov_9fa48("395"), obj.value.slice(1))))))) {
          if (stryMutAct_9fa48("396")) {
            {}
          } else {
            stryCov_9fa48("396");
            issues.push(stryMutAct_9fa48("397") ? {} : (stryCov_9fa48("397"), {
              type: stryMutAct_9fa48("398") ? "" : (stryCov_9fa48("398"), 'warning'),
              code: stryMutAct_9fa48("399") ? "" : (stryCov_9fa48("399"), 'UNRESOLVABLE_VALUE'),
              message: stryMutAct_9fa48("400") ? `` : (stryCov_9fa48("400"), `Condition value "${obj.value}" references an unresolvable path`),
              path: stryMutAct_9fa48("401") ? `` : (stryCov_9fa48("401"), `${path}.value`)
            }));
          }
        }
        // `matches` is the only operator that compiles its value into a regex.
        // Refuse catastrophic patterns at validate-time so they never reach the
        // policy store. Non-string / $-resolved values are caught elsewhere.
        if (stryMutAct_9fa48("404") ? obj.operator === 'matches' && typeof obj.value === 'string' || !obj.value.startsWith('$') : stryMutAct_9fa48("403") ? false : stryMutAct_9fa48("402") ? true : (stryCov_9fa48("402", "403", "404"), (stryMutAct_9fa48("406") ? obj.operator === 'matches' || typeof obj.value === 'string' : stryMutAct_9fa48("405") ? true : (stryCov_9fa48("405", "406"), (stryMutAct_9fa48("408") ? obj.operator !== 'matches' : stryMutAct_9fa48("407") ? true : (stryCov_9fa48("407", "408"), obj.operator === (stryMutAct_9fa48("409") ? "" : (stryCov_9fa48("409"), 'matches')))) && (stryMutAct_9fa48("411") ? typeof obj.value !== 'string' : stryMutAct_9fa48("410") ? true : (stryCov_9fa48("410", "411"), typeof obj.value === (stryMutAct_9fa48("412") ? "" : (stryCov_9fa48("412"), 'string')))))) && (stryMutAct_9fa48("413") ? obj.value.startsWith('$') : (stryCov_9fa48("413"), !(stryMutAct_9fa48("414") ? obj.value.endsWith('$') : (stryCov_9fa48("414"), obj.value.startsWith(stryMutAct_9fa48("415") ? "" : (stryCov_9fa48("415"), '$')))))))) {
          if (stryMutAct_9fa48("416")) {
            {}
          } else {
            stryCov_9fa48("416");
            const result = detectCatastrophicRegex(obj.value);
            if (stryMutAct_9fa48("419") ? false : stryMutAct_9fa48("418") ? true : stryMutAct_9fa48("417") ? result.safe : (stryCov_9fa48("417", "418", "419"), !result.safe)) {
              if (stryMutAct_9fa48("420")) {
                {}
              } else {
                stryCov_9fa48("420");
                issues.push(stryMutAct_9fa48("421") ? {} : (stryCov_9fa48("421"), {
                  type: stryMutAct_9fa48("422") ? "" : (stryCov_9fa48("422"), 'error'),
                  code: stryMutAct_9fa48("423") ? "" : (stryCov_9fa48("423"), 'ERR_REGEX_CATASTROPHIC'),
                  message: stryMutAct_9fa48("424") ? `` : (stryCov_9fa48("424"), `Condition "matches" pattern rejected: ${result.reason}`),
                  path: stryMutAct_9fa48("425") ? `` : (stryCov_9fa48("425"), `${path}.value`)
                }));
              }
            }
          }
        }
      }
    } else {
      if (stryMutAct_9fa48("426")) {
        {}
      } else {
        stryCov_9fa48("426");
        validateConditionGroup(input, path, issues, depth);
      }
    }
  }
}

/**
 * Validate a condition group (`all`, `any`, or `none`).
 *
 * The group must be an object containing exactly one of the keys `all`, `any`,
 * or `none`, whose value must be an array of condition items.
 *
 * @param input  - The condition group to validate.
 * @param path   - Dot-path prefix used in reported issues.
 * @param issues - Array to push validation issues into.
 * @param depth  - Current nesting depth (defaults to `0`; bounded by `MAX_CONDITION_DEPTH`).
 */
export function validateConditionGroup(input: unknown, path: string, issues: Validate.IIssue[], depth = 0): void {
  if (stryMutAct_9fa48("427")) {
    {}
  } else {
    stryCov_9fa48("427");
    if (stryMutAct_9fa48("431") ? depth <= MAX_CONDITION_DEPTH : stryMutAct_9fa48("430") ? depth >= MAX_CONDITION_DEPTH : stryMutAct_9fa48("429") ? false : stryMutAct_9fa48("428") ? true : (stryCov_9fa48("428", "429", "430", "431"), depth > MAX_CONDITION_DEPTH)) {
      if (stryMutAct_9fa48("432")) {
        {}
      } else {
        stryCov_9fa48("432");
        issues.push(stryMutAct_9fa48("433") ? {} : (stryCov_9fa48("433"), {
          type: stryMutAct_9fa48("434") ? "" : (stryCov_9fa48("434"), 'error'),
          code: stryMutAct_9fa48("435") ? "" : (stryCov_9fa48("435"), 'LIMIT_EXCEEDED'),
          message: stryMutAct_9fa48("436") ? `` : (stryCov_9fa48("436"), `Condition nesting exceeds MAX_CONDITION_DEPTH (${MAX_CONDITION_DEPTH})`),
          path
        }));
        return;
      }
    }
    if (stryMutAct_9fa48("439") ? typeof input !== 'object' && input === null : stryMutAct_9fa48("438") ? false : stryMutAct_9fa48("437") ? true : (stryCov_9fa48("437", "438", "439"), (stryMutAct_9fa48("441") ? typeof input === 'object' : stryMutAct_9fa48("440") ? false : (stryCov_9fa48("440", "441"), typeof input !== (stryMutAct_9fa48("442") ? "" : (stryCov_9fa48("442"), 'object')))) || (stryMutAct_9fa48("444") ? input !== null : stryMutAct_9fa48("443") ? false : (stryCov_9fa48("443", "444"), input === null)))) {
      if (stryMutAct_9fa48("445")) {
        {}
      } else {
        stryCov_9fa48("445");
        issues.push(stryMutAct_9fa48("446") ? {} : (stryCov_9fa48("446"), {
          type: stryMutAct_9fa48("447") ? "" : (stryCov_9fa48("447"), 'error'),
          code: stryMutAct_9fa48("448") ? "" : (stryCov_9fa48("448"), 'INVALID_CONDITION'),
          message: stryMutAct_9fa48("449") ? "" : (stryCov_9fa48("449"), 'Condition group must be an object'),
          path
        }));
        return;
      }
    }
    const obj = input as Record<string, unknown>;
    const groupKey = (stryMutAct_9fa48("450") ? [] : (stryCov_9fa48("450"), [stryMutAct_9fa48("451") ? "" : (stryCov_9fa48("451"), 'all'), stryMutAct_9fa48("452") ? "" : (stryCov_9fa48("452"), 'any'), stryMutAct_9fa48("453") ? "" : (stryCov_9fa48("453"), 'none')])).find(stryMutAct_9fa48("454") ? () => undefined : (stryCov_9fa48("454"), k => k in obj));
    if (stryMutAct_9fa48("457") ? false : stryMutAct_9fa48("456") ? true : stryMutAct_9fa48("455") ? groupKey : (stryCov_9fa48("455", "456", "457"), !groupKey)) {
      if (stryMutAct_9fa48("458")) {
        {}
      } else {
        stryCov_9fa48("458");
        issues.push(stryMutAct_9fa48("459") ? {} : (stryCov_9fa48("459"), {
          type: stryMutAct_9fa48("460") ? "" : (stryCov_9fa48("460"), 'error'),
          code: stryMutAct_9fa48("461") ? "" : (stryCov_9fa48("461"), 'INVALID_CONDITION'),
          message: stryMutAct_9fa48("462") ? "" : (stryCov_9fa48("462"), 'Condition group must have "all", "any", or "none" key'),
          path
        }));
        return;
      }
    }
    const items = obj[groupKey];
    if (stryMutAct_9fa48("465") ? false : stryMutAct_9fa48("464") ? true : stryMutAct_9fa48("463") ? Array.isArray(items) : (stryCov_9fa48("463", "464", "465"), !Array.isArray(items))) {
      if (stryMutAct_9fa48("466")) {
        {}
      } else {
        stryCov_9fa48("466");
        issues.push(stryMutAct_9fa48("467") ? {} : (stryCov_9fa48("467"), {
          type: stryMutAct_9fa48("468") ? "" : (stryCov_9fa48("468"), 'error'),
          code: stryMutAct_9fa48("469") ? "" : (stryCov_9fa48("469"), 'INVALID_CONDITION'),
          message: stryMutAct_9fa48("470") ? `` : (stryCov_9fa48("470"), `"${groupKey}" must be an array`),
          path: stryMutAct_9fa48("471") ? `` : (stryCov_9fa48("471"), `${path}.${groupKey}`)
        }));
        return;
      }
    }
    for (const [i, item] of items.entries()) {
      if (stryMutAct_9fa48("472")) {
        {}
      } else {
        stryCov_9fa48("472");
        validateConditionItem(item, stryMutAct_9fa48("473") ? `` : (stryCov_9fa48("473"), `${path}.${groupKey}[${i}]`), issues, stryMutAct_9fa48("474") ? depth - 1 : (stryCov_9fa48("474"), depth + 1));
      }
    }
  }
}

/**
 * Validate the shape of a single rule object.
 *
 * Checks that all required fields (`id`, `effect`, `priority`, `actions`,
 * `resources`) are present and have the correct types. Optionally validates
 * nested `conditions` via {@link validateConditionGroup}.
 *
 * @param input - The rule object to validate.
 * @param path - Dot-path prefix used in reported issues.
 * @param issues - Array to push validation issues into.
 */
export function validateRuleShape(input: unknown, path: string, issues: Validate.IIssue[]): void {
  if (stryMutAct_9fa48("475")) {
    {}
  } else {
    stryCov_9fa48("475");
    if (stryMutAct_9fa48("478") ? typeof input !== 'object' && input === null : stryMutAct_9fa48("477") ? false : stryMutAct_9fa48("476") ? true : (stryCov_9fa48("476", "477", "478"), (stryMutAct_9fa48("480") ? typeof input === 'object' : stryMutAct_9fa48("479") ? false : (stryCov_9fa48("479", "480"), typeof input !== (stryMutAct_9fa48("481") ? "" : (stryCov_9fa48("481"), 'object')))) || (stryMutAct_9fa48("483") ? input !== null : stryMutAct_9fa48("482") ? false : (stryCov_9fa48("482", "483"), input === null)))) {
      if (stryMutAct_9fa48("484")) {
        {}
      } else {
        stryCov_9fa48("484");
        issues.push(stryMutAct_9fa48("485") ? {} : (stryCov_9fa48("485"), {
          type: stryMutAct_9fa48("486") ? "" : (stryCov_9fa48("486"), 'error'),
          code: stryMutAct_9fa48("487") ? "" : (stryCov_9fa48("487"), 'INVALID_RULE'),
          message: stryMutAct_9fa48("488") ? "" : (stryCov_9fa48("488"), 'Rule must be an object'),
          path
        }));
        return;
      }
    }
    const rule = input as Record<string, unknown>;
    if (stryMutAct_9fa48("491") ? typeof rule.id !== 'string' && !rule.id : stryMutAct_9fa48("490") ? false : stryMutAct_9fa48("489") ? true : (stryCov_9fa48("489", "490", "491"), (stryMutAct_9fa48("493") ? typeof rule.id === 'string' : stryMutAct_9fa48("492") ? false : (stryCov_9fa48("492", "493"), typeof rule.id !== (stryMutAct_9fa48("494") ? "" : (stryCov_9fa48("494"), 'string')))) || (stryMutAct_9fa48("495") ? rule.id : (stryCov_9fa48("495"), !rule.id)))) {
      if (stryMutAct_9fa48("496")) {
        {}
      } else {
        stryCov_9fa48("496");
        issues.push(stryMutAct_9fa48("497") ? {} : (stryCov_9fa48("497"), {
          type: stryMutAct_9fa48("498") ? "" : (stryCov_9fa48("498"), 'error'),
          code: stryMutAct_9fa48("499") ? "" : (stryCov_9fa48("499"), 'MISSING_FIELD'),
          message: stryMutAct_9fa48("500") ? "" : (stryCov_9fa48("500"), 'Rule must have a non-empty string "id"'),
          path: stryMutAct_9fa48("501") ? `` : (stryCov_9fa48("501"), `${path}.id`)
        }));
      }
    }
    if (stryMutAct_9fa48("504") ? false : stryMutAct_9fa48("503") ? true : stryMutAct_9fa48("502") ? VALID_EFFECTS.has(rule.effect as string) : (stryCov_9fa48("502", "503", "504"), !VALID_EFFECTS.has(rule.effect as string))) {
      if (stryMutAct_9fa48("505")) {
        {}
      } else {
        stryCov_9fa48("505");
        issues.push(stryMutAct_9fa48("506") ? {} : (stryCov_9fa48("506"), {
          type: stryMutAct_9fa48("507") ? "" : (stryCov_9fa48("507"), 'error'),
          code: stryMutAct_9fa48("508") ? "" : (stryCov_9fa48("508"), 'INVALID_EFFECT'),
          message: stryMutAct_9fa48("509") ? `` : (stryCov_9fa48("509"), `Invalid effect "${String(rule.effect)}". Must be "allow" or "deny"`),
          path: stryMutAct_9fa48("510") ? `` : (stryCov_9fa48("510"), `${path}.effect`)
        }));
      }
    }
    if (stryMutAct_9fa48("513") ? typeof rule.priority !== 'number' && !Number.isFinite(rule.priority) : stryMutAct_9fa48("512") ? false : stryMutAct_9fa48("511") ? true : (stryCov_9fa48("511", "512", "513"), (stryMutAct_9fa48("515") ? typeof rule.priority === 'number' : stryMutAct_9fa48("514") ? false : (stryCov_9fa48("514", "515"), typeof rule.priority !== (stryMutAct_9fa48("516") ? "" : (stryCov_9fa48("516"), 'number')))) || (stryMutAct_9fa48("517") ? Number.isFinite(rule.priority) : (stryCov_9fa48("517"), !Number.isFinite(rule.priority))))) {
      if (stryMutAct_9fa48("518")) {
        {}
      } else {
        stryCov_9fa48("518");
        issues.push(stryMutAct_9fa48("519") ? {} : (stryCov_9fa48("519"), {
          type: stryMutAct_9fa48("520") ? "" : (stryCov_9fa48("520"), 'error'),
          code: stryMutAct_9fa48("521") ? "" : (stryCov_9fa48("521"), 'INVALID_TYPE'),
          message: stryMutAct_9fa48("522") ? "" : (stryCov_9fa48("522"), 'Rule "priority" must be a finite number (NaN/Infinity break highest-priority ranking)'),
          path: stryMutAct_9fa48("523") ? `` : (stryCov_9fa48("523"), `${path}.priority`)
        }));
      }
    }
    if (stryMutAct_9fa48("526") ? !Array.isArray(rule.actions) && rule.actions.length === 0 : stryMutAct_9fa48("525") ? false : stryMutAct_9fa48("524") ? true : (stryCov_9fa48("524", "525", "526"), (stryMutAct_9fa48("527") ? Array.isArray(rule.actions) : (stryCov_9fa48("527"), !Array.isArray(rule.actions))) || (stryMutAct_9fa48("529") ? rule.actions.length !== 0 : stryMutAct_9fa48("528") ? false : (stryCov_9fa48("528", "529"), rule.actions.length === 0)))) {
      if (stryMutAct_9fa48("530")) {
        {}
      } else {
        stryCov_9fa48("530");
        issues.push(stryMutAct_9fa48("531") ? {} : (stryCov_9fa48("531"), {
          type: stryMutAct_9fa48("532") ? "" : (stryCov_9fa48("532"), 'error'),
          code: stryMutAct_9fa48("533") ? "" : (stryCov_9fa48("533"), 'MISSING_FIELD'),
          message: stryMutAct_9fa48("534") ? "" : (stryCov_9fa48("534"), 'Rule must have a non-empty "actions" array'),
          path: stryMutAct_9fa48("535") ? `` : (stryCov_9fa48("535"), `${path}.actions`)
        }));
      }
    } else {
      if (stryMutAct_9fa48("536")) {
        {}
      } else {
        stryCov_9fa48("536");
        if (stryMutAct_9fa48("540") ? rule.actions.length <= POLICY_LIMITS.actionsPerRule : stryMutAct_9fa48("539") ? rule.actions.length >= POLICY_LIMITS.actionsPerRule : stryMutAct_9fa48("538") ? false : stryMutAct_9fa48("537") ? true : (stryCov_9fa48("537", "538", "539", "540"), rule.actions.length > POLICY_LIMITS.actionsPerRule)) {
          if (stryMutAct_9fa48("541")) {
            {}
          } else {
            stryCov_9fa48("541");
            issues.push(stryMutAct_9fa48("542") ? {} : (stryCov_9fa48("542"), {
              type: stryMutAct_9fa48("543") ? "" : (stryCov_9fa48("543"), 'error'),
              code: stryMutAct_9fa48("544") ? "" : (stryCov_9fa48("544"), 'LIMIT_EXCEEDED'),
              message: stryMutAct_9fa48("545") ? `` : (stryCov_9fa48("545"), `Rule has ${rule.actions.length} actions; limit is ${POLICY_LIMITS.actionsPerRule}`),
              path: stryMutAct_9fa48("546") ? `` : (stryCov_9fa48("546"), `${path}.actions`)
            }));
          }
        }
        for (const [i, action] of (rule.actions as unknown[]).entries()) {
          if (stryMutAct_9fa48("547")) {
            {}
          } else {
            stryCov_9fa48("547");
            if (stryMutAct_9fa48("550") ? typeof action === 'string' : stryMutAct_9fa48("549") ? false : stryMutAct_9fa48("548") ? true : (stryCov_9fa48("548", "549", "550"), typeof action !== (stryMutAct_9fa48("551") ? "" : (stryCov_9fa48("551"), 'string')))) {
              if (stryMutAct_9fa48("552")) {
                {}
              } else {
                stryCov_9fa48("552");
                issues.push(stryMutAct_9fa48("553") ? {} : (stryCov_9fa48("553"), {
                  type: stryMutAct_9fa48("554") ? "" : (stryCov_9fa48("554"), 'error'),
                  code: stryMutAct_9fa48("555") ? "" : (stryCov_9fa48("555"), 'INVALID_TYPE'),
                  message: stryMutAct_9fa48("556") ? "" : (stryCov_9fa48("556"), 'Action must be a string'),
                  path: stryMutAct_9fa48("557") ? `` : (stryCov_9fa48("557"), `${path}.actions[${i}]`)
                }));
              }
            }
          }
        }
      }
    }
    if (stryMutAct_9fa48("560") ? !Array.isArray(rule.resources) && rule.resources.length === 0 : stryMutAct_9fa48("559") ? false : stryMutAct_9fa48("558") ? true : (stryCov_9fa48("558", "559", "560"), (stryMutAct_9fa48("561") ? Array.isArray(rule.resources) : (stryCov_9fa48("561"), !Array.isArray(rule.resources))) || (stryMutAct_9fa48("563") ? rule.resources.length !== 0 : stryMutAct_9fa48("562") ? false : (stryCov_9fa48("562", "563"), rule.resources.length === 0)))) {
      if (stryMutAct_9fa48("564")) {
        {}
      } else {
        stryCov_9fa48("564");
        issues.push(stryMutAct_9fa48("565") ? {} : (stryCov_9fa48("565"), {
          type: stryMutAct_9fa48("566") ? "" : (stryCov_9fa48("566"), 'error'),
          code: stryMutAct_9fa48("567") ? "" : (stryCov_9fa48("567"), 'MISSING_FIELD'),
          message: stryMutAct_9fa48("568") ? "" : (stryCov_9fa48("568"), 'Rule must have a non-empty "resources" array'),
          path: stryMutAct_9fa48("569") ? `` : (stryCov_9fa48("569"), `${path}.resources`)
        }));
      }
    } else {
      if (stryMutAct_9fa48("570")) {
        {}
      } else {
        stryCov_9fa48("570");
        if (stryMutAct_9fa48("574") ? rule.resources.length <= POLICY_LIMITS.resourcesPerRule : stryMutAct_9fa48("573") ? rule.resources.length >= POLICY_LIMITS.resourcesPerRule : stryMutAct_9fa48("572") ? false : stryMutAct_9fa48("571") ? true : (stryCov_9fa48("571", "572", "573", "574"), rule.resources.length > POLICY_LIMITS.resourcesPerRule)) {
          if (stryMutAct_9fa48("575")) {
            {}
          } else {
            stryCov_9fa48("575");
            issues.push(stryMutAct_9fa48("576") ? {} : (stryCov_9fa48("576"), {
              type: stryMutAct_9fa48("577") ? "" : (stryCov_9fa48("577"), 'error'),
              code: stryMutAct_9fa48("578") ? "" : (stryCov_9fa48("578"), 'LIMIT_EXCEEDED'),
              message: stryMutAct_9fa48("579") ? `` : (stryCov_9fa48("579"), `Rule has ${rule.resources.length} resources; limit is ${POLICY_LIMITS.resourcesPerRule}`),
              path: stryMutAct_9fa48("580") ? `` : (stryCov_9fa48("580"), `${path}.resources`)
            }));
          }
        }
        for (const [i, resource] of (rule.resources as unknown[]).entries()) {
          if (stryMutAct_9fa48("581")) {
            {}
          } else {
            stryCov_9fa48("581");
            if (stryMutAct_9fa48("584") ? typeof resource === 'string' : stryMutAct_9fa48("583") ? false : stryMutAct_9fa48("582") ? true : (stryCov_9fa48("582", "583", "584"), typeof resource !== (stryMutAct_9fa48("585") ? "" : (stryCov_9fa48("585"), 'string')))) {
              if (stryMutAct_9fa48("586")) {
                {}
              } else {
                stryCov_9fa48("586");
                issues.push(stryMutAct_9fa48("587") ? {} : (stryCov_9fa48("587"), {
                  type: stryMutAct_9fa48("588") ? "" : (stryCov_9fa48("588"), 'error'),
                  code: stryMutAct_9fa48("589") ? "" : (stryCov_9fa48("589"), 'INVALID_TYPE'),
                  message: stryMutAct_9fa48("590") ? "" : (stryCov_9fa48("590"), 'Resource must be a string'),
                  path: stryMutAct_9fa48("591") ? `` : (stryCov_9fa48("591"), `${path}.resources[${i}]`)
                }));
              }
            }
          }
        }
      }
    }

    // Broad-allow warning: `effect: 'allow'` + `actions: ['*']` + `resources: ['*']`
    // + zero conditions grants every operation to every subject the policy applies to.
    // Intent is ambiguous from the policy alone (super-admin vs. mistake) - surface
    // for review so the operator confirms once.
    if (stryMutAct_9fa48("594") ? rule.effect === 'allow' && Array.isArray(rule.actions) || Array.isArray(rule.resources) : stryMutAct_9fa48("593") ? false : stryMutAct_9fa48("592") ? true : (stryCov_9fa48("592", "593", "594"), (stryMutAct_9fa48("596") ? rule.effect === 'allow' || Array.isArray(rule.actions) : stryMutAct_9fa48("595") ? true : (stryCov_9fa48("595", "596"), (stryMutAct_9fa48("598") ? rule.effect !== 'allow' : stryMutAct_9fa48("597") ? true : (stryCov_9fa48("597", "598"), rule.effect === (stryMutAct_9fa48("599") ? "" : (stryCov_9fa48("599"), 'allow')))) && Array.isArray(rule.actions))) && Array.isArray(rule.resources))) {
      if (stryMutAct_9fa48("600")) {
        {}
      } else {
        stryCov_9fa48("600");
        const allActions = stryMutAct_9fa48("603") ? rule.actions.length === 1 || rule.actions[0] === '*' : stryMutAct_9fa48("602") ? false : stryMutAct_9fa48("601") ? true : (stryCov_9fa48("601", "602", "603"), (stryMutAct_9fa48("605") ? rule.actions.length !== 1 : stryMutAct_9fa48("604") ? true : (stryCov_9fa48("604", "605"), rule.actions.length === 1)) && (stryMutAct_9fa48("607") ? rule.actions[0] !== '*' : stryMutAct_9fa48("606") ? true : (stryCov_9fa48("606", "607"), rule.actions[0] === (stryMutAct_9fa48("608") ? "" : (stryCov_9fa48("608"), '*')))));
        const allResources = stryMutAct_9fa48("611") ? rule.resources.length === 1 || rule.resources[0] === '*' : stryMutAct_9fa48("610") ? false : stryMutAct_9fa48("609") ? true : (stryCov_9fa48("609", "610", "611"), (stryMutAct_9fa48("613") ? rule.resources.length !== 1 : stryMutAct_9fa48("612") ? true : (stryCov_9fa48("612", "613"), rule.resources.length === 1)) && (stryMutAct_9fa48("615") ? rule.resources[0] !== '*' : stryMutAct_9fa48("614") ? true : (stryCov_9fa48("614", "615"), rule.resources[0] === (stryMutAct_9fa48("616") ? "" : (stryCov_9fa48("616"), '*')))));
        const cond = rule.conditions as {
          all?: unknown[];
          any?: unknown[];
          none?: unknown[];
        } | undefined;
        const hasConditions = stryMutAct_9fa48("619") ? !!cond || (cond.all?.length ?? 0) > 0 || (cond.any?.length ?? 0) > 0 || (cond.none?.length ?? 0) > 0 : stryMutAct_9fa48("618") ? false : stryMutAct_9fa48("617") ? true : (stryCov_9fa48("617", "618", "619"), (stryMutAct_9fa48("620") ? !cond : (stryCov_9fa48("620"), !(stryMutAct_9fa48("621") ? cond : (stryCov_9fa48("621"), !cond)))) && (stryMutAct_9fa48("623") ? ((cond.all?.length ?? 0) > 0 || (cond.any?.length ?? 0) > 0) && (cond.none?.length ?? 0) > 0 : stryMutAct_9fa48("622") ? true : (stryCov_9fa48("622", "623"), (stryMutAct_9fa48("625") ? (cond.all?.length ?? 0) > 0 && (cond.any?.length ?? 0) > 0 : stryMutAct_9fa48("624") ? false : (stryCov_9fa48("624", "625"), (stryMutAct_9fa48("628") ? (cond.all?.length ?? 0) <= 0 : stryMutAct_9fa48("627") ? (cond.all?.length ?? 0) >= 0 : stryMutAct_9fa48("626") ? false : (stryCov_9fa48("626", "627", "628"), (stryMutAct_9fa48("629") ? cond.all?.length && 0 : (stryCov_9fa48("629"), (stryMutAct_9fa48("630") ? cond.all.length : (stryCov_9fa48("630"), cond.all?.length)) ?? 0)) > 0)) || (stryMutAct_9fa48("633") ? (cond.any?.length ?? 0) <= 0 : stryMutAct_9fa48("632") ? (cond.any?.length ?? 0) >= 0 : stryMutAct_9fa48("631") ? false : (stryCov_9fa48("631", "632", "633"), (stryMutAct_9fa48("634") ? cond.any?.length && 0 : (stryCov_9fa48("634"), (stryMutAct_9fa48("635") ? cond.any.length : (stryCov_9fa48("635"), cond.any?.length)) ?? 0)) > 0)))) || (stryMutAct_9fa48("638") ? (cond.none?.length ?? 0) <= 0 : stryMutAct_9fa48("637") ? (cond.none?.length ?? 0) >= 0 : stryMutAct_9fa48("636") ? false : (stryCov_9fa48("636", "637", "638"), (stryMutAct_9fa48("639") ? cond.none?.length && 0 : (stryCov_9fa48("639"), (stryMutAct_9fa48("640") ? cond.none.length : (stryCov_9fa48("640"), cond.none?.length)) ?? 0)) > 0)))));
        if (stryMutAct_9fa48("643") ? allActions && allResources || !hasConditions : stryMutAct_9fa48("642") ? false : stryMutAct_9fa48("641") ? true : (stryCov_9fa48("641", "642", "643"), (stryMutAct_9fa48("645") ? allActions || allResources : stryMutAct_9fa48("644") ? true : (stryCov_9fa48("644", "645"), allActions && allResources)) && (stryMutAct_9fa48("646") ? hasConditions : (stryCov_9fa48("646"), !hasConditions)))) {
          if (stryMutAct_9fa48("647")) {
            {}
          } else {
            stryCov_9fa48("647");
            issues.push(stryMutAct_9fa48("648") ? {} : (stryCov_9fa48("648"), {
              type: stryMutAct_9fa48("649") ? "" : (stryCov_9fa48("649"), 'warning'),
              code: stryMutAct_9fa48("650") ? "" : (stryCov_9fa48("650"), 'BROAD_ALLOW'),
              message: stryMutAct_9fa48("651") ? "" : (stryCov_9fa48("651"), 'Rule allows every action on every resource with no conditions. This is the broadest possible grant - confirm it is intentional.'),
              path
            }));
          }
        }
      }
    }

    // Indexer cost is actions x resources per rule. Bound the cartesian even when
    // each list passes its own cap, so a 99x99 rule doesn't slip through.
    if (stryMutAct_9fa48("654") ? Array.isArray(rule.actions) || Array.isArray(rule.resources) : stryMutAct_9fa48("653") ? false : stryMutAct_9fa48("652") ? true : (stryCov_9fa48("652", "653", "654"), Array.isArray(rule.actions) && Array.isArray(rule.resources))) {
      if (stryMutAct_9fa48("655")) {
        {}
      } else {
        stryCov_9fa48("655");
        const cartesian = stryMutAct_9fa48("656") ? rule.actions.length / rule.resources.length : (stryCov_9fa48("656"), rule.actions.length * rule.resources.length);
        if (stryMutAct_9fa48("660") ? cartesian <= POLICY_LIMITS.cartesianPerRule : stryMutAct_9fa48("659") ? cartesian >= POLICY_LIMITS.cartesianPerRule : stryMutAct_9fa48("658") ? false : stryMutAct_9fa48("657") ? true : (stryCov_9fa48("657", "658", "659", "660"), cartesian > POLICY_LIMITS.cartesianPerRule)) {
          if (stryMutAct_9fa48("661")) {
            {}
          } else {
            stryCov_9fa48("661");
            issues.push(stryMutAct_9fa48("662") ? {} : (stryCov_9fa48("662"), {
              type: stryMutAct_9fa48("663") ? "" : (stryCov_9fa48("663"), 'error'),
              code: stryMutAct_9fa48("664") ? "" : (stryCov_9fa48("664"), 'LIMIT_EXCEEDED'),
              message: stryMutAct_9fa48("665") ? `` : (stryCov_9fa48("665"), `Rule actionxresource cartesian is ${cartesian}; limit is ${POLICY_LIMITS.cartesianPerRule}`),
              path
            }));
          }
        }
      }
    }
    if (stryMutAct_9fa48("668") ? rule.conditions === undefined : stryMutAct_9fa48("667") ? false : stryMutAct_9fa48("666") ? true : (stryCov_9fa48("666", "667", "668"), rule.conditions !== undefined)) {
      if (stryMutAct_9fa48("669")) {
        {}
      } else {
        stryCov_9fa48("669");
        validateConditionGroup(rule.conditions, stryMutAct_9fa48("670") ? `` : (stryCov_9fa48("670"), `${path}.conditions`), issues);
      }
    }
  }
}