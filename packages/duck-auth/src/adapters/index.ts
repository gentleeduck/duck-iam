/** The contract every adapter meets, under the public `@gentleduck/auth/adapters` entry. A store written
 *  outside this package needs both: the shape to declare itself as, and the base class that answers in it. */

export type { Adapter } from './adapter'
export { AdapterStore } from './adapter'
