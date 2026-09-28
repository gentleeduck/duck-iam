'use client'

import { useEffect, useState } from 'react'
import { Can, useAccess } from '@/access'
import { api, type Company, type Order, type Product, type UserRow } from './api'

const ROLE_OPTIONS = ['viewer', 'staff', 'manager', 'admin']
// Duplicated from `shared/src/schema.ts`'s `ORDER_STATUSES` rather than imported — that module
// pulls in `drizzle-orm/pg-core`, which must never reach a client bundle (same reasoning as
// `ROLE_OPTIONS` above and `@/access`'s `import type` boundary).
const ORDER_STATUS_OPTIONS = ['pending', 'shipped', 'delivered', 'cancelled']

export function DuckMarket({
  userId,
  companyId,
  onSignOut,
}: {
  userId: string
  companyId: string
  onSignOut: () => void
}) {
  const { permissions } = useAccess()
  const [company, setCompany] = useState<Company | null>(null)
  const [users, setUsers] = useState<UserRow[]>([])
  const [products, setProducts] = useState<Product[]>([])
  const [orders, setOrders] = useState<Order[]>([])
  const [notice, setNotice] = useState<string | null>(null)

  const reload = () => {
    const onError = (label: string) => (err: unknown) =>
      setNotice(`Couldn't load ${label}: ${err instanceof Error ? err.message : 'request failed'}`)
    api.company(companyId).then(setCompany, (err) => {
      setCompany(null)
      onError('company')(err)
    })
    api.users().then(setUsers, (err) => {
      setUsers([])
      onError('users')(err)
    })
    api.products().then(setProducts, (err) => {
      setProducts([])
      onError('products')(err)
    })
    api.orders().then(setOrders, (err) => {
      setOrders([])
      onError('orders')(err)
    })
  }

  useEffect(reload, [companyId])

  const run = async (action: () => Promise<unknown>, successMessage: string) => {
    try {
      await action()
      setNotice(successMessage)
      reload()
    } catch (err) {
      setNotice(err instanceof Error ? err.message : 'request failed')
    }
  }

  return (
    <main>
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <div>
          <strong>{userId}</strong> <span className="muted">@ {companyId}</span>
        </div>
        <button type="button" onClick={onSignOut}>
          Sign out
        </button>
      </div>

      {notice && (
        <p className="muted" role="status">
          {notice}
        </p>
      )}

      <section>
        <h2>Your permissions</h2>
        <p className="muted">
          Fetched once via <code>GET /api/me/permissions</code> (one <code>engine.permissions()</code> batch call), then
          gates every control below through <code>&lt;Can&gt;</code> — never a client-side guess.
        </p>
        <table>
          <thead>
            <tr>
              <th>key</th>
              <th>allowed</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(permissions)
              .filter(([, allowed]) => allowed)
              .map(([key]) => (
                <tr key={key}>
                  <td>{key}</td>
                  <td>true</td>
                </tr>
              ))}
          </tbody>
        </table>
      </section>

      <section>
        <h2>Company</h2>
        {company ? (
          <div className="row">
            <span>{company.name}</span>
            <Can action="update" resource="companies">
              <button
                type="button"
                onClick={() => {
                  const name = prompt('New company name', company.name)
                  if (name) run(() => api.renameCompany(companyId, name), 'Company renamed.')
                }}>
                Rename
              </button>
            </Can>
          </div>
        ) : (
          <p className="muted">not visible</p>
        )}
      </section>

      <section>
        <h2>Products</h2>
        <Can action="create" resource="products">
          <form
            className="row"
            onSubmit={(e) => {
              e.preventDefault()
              const form = e.currentTarget
              const name = (form.elements.namedItem('name') as HTMLInputElement).value
              const price = Number((form.elements.namedItem('price') as HTMLInputElement).value)
              if (name && price > 0) {
                run(() => api.createProduct(name, Math.round(price * 100)), `Created product "${name}".`)
                form.reset()
              }
            }}>
            <input name="name" placeholder="Product name" />
            <input name="price" type="number" step="0.01" min="0" placeholder="Price (USD)" />
            <button type="submit">Add product</button>
          </form>
        </Can>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>name</th>
                <th>price</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {products.map((p) => (
                <tr key={p.id}>
                  <td>{p.name}</td>
                  <td>${(p.priceCents / 100).toFixed(2)}</td>
                  <td>
                    <Can action="delete" resource="products">
                      <button
                        className="danger"
                        type="button"
                        aria-label={`Delete ${p.name}`}
                        onClick={() => run(() => api.deleteProduct(p.id), `Deleted "${p.name}".`)}>
                        Delete
                      </button>
                    </Can>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <h2>Orders</h2>
        <Can action="create" resource="orders">
          <form
            className="row"
            onSubmit={(e) => {
              e.preventDefault()
              const form = e.currentTarget
              const productId = (form.elements.namedItem('productId') as HTMLSelectElement).value
              const quantity = Number((form.elements.namedItem('quantity') as HTMLInputElement).value)
              if (productId && quantity > 0) {
                run(() => api.createOrder(productId, quantity), 'Order placed.')
                form.reset()
              }
            }}>
            <select name="productId" defaultValue="">
              <option value="" disabled>
                Choose product
              </option>
              {products.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
            <input name="quantity" type="number" min="1" defaultValue="1" />
            <button type="submit">Place order</button>
          </form>
        </Can>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>product</th>
                <th>qty</th>
                <th>status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {orders.map((o) => {
                const productName = products.find((p) => p.id === o.productId)?.name ?? o.productId
                return (
                  <tr key={o.id}>
                    <td>{productName}</td>
                    <td>{o.quantity}</td>
                    <td>{o.status}</td>
                    <td>
                      <Can action="update" resource="orders">
                        <select
                          value={o.status}
                          aria-label={`Update status for order of ${productName}`}
                          onChange={(e) =>
                            run(
                              () => api.updateOrderStatus(o.id, e.target.value),
                              `Order ${o.id} -> ${e.target.value}.`,
                            )
                          }>
                          {ORDER_STATUS_OPTIONS.map((s) => (
                            <option key={s} value={s}>
                              {s}
                            </option>
                          ))}
                        </select>
                      </Can>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <h2>Users</h2>
        <p className="muted">
          Deleting your own row is denied server-side by the <code>deny-self-account-delete</code> policy even though
          the batch permission map (resource-level, not per-row) still shows <code>delete:users</code> as allowed for an
          admin — a real instance of coarse client gating vs. fine-grained server enforcement. Try it as{' '}
          <code>admin@acme.test</code> against your own row.
        </p>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>email</th>
                <th>role assign</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td>{u.email}</td>
                  <td>
                    <Can action="manageRoles" resource="users">
                      <select
                        defaultValue=""
                        aria-label={`Assign role for ${u.email}`}
                        onChange={(e) => {
                          const roleId = e.target.value
                          if (roleId) run(() => api.assignRole(u.id, roleId), `${u.email} -> ${roleId}.`)
                        }}>
                        <option value="" disabled>
                          set role...
                        </option>
                        {ROLE_OPTIONS.map((r) => (
                          <option key={r} value={r}>
                            {r}
                          </option>
                        ))}
                      </select>
                    </Can>
                  </td>
                  <td>
                    <Can action="delete" resource="users">
                      <button
                        className="danger"
                        type="button"
                        aria-label={`Delete ${u.email}`}
                        onClick={() => run(() => api.deleteUser(u.id), `Deleted ${u.email}.`)}>
                        Delete
                      </button>
                    </Can>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  )
}
