# Tenants (draft)

Status 2026-10-19: a design, nothing of it is built. It describes tenants as
areas of administration inside **one** network, not as separate networks.

## The model

* There is one network: one control plane, one admin signer chain, one
  overlay pool, one set of hubs. Every node keeps being made a member by the
  same thing as today: a binding signed with a global administrator's
  hardware key (BINDINGS.md).
* Every node belongs to exactly one **tenant**. The default is `global`.
* **Global administrators** approve and sign nodes, choose their tenant, and
  manage everything: the signer chain, settings, hubs, tenants and their
  administrators.
* **Tenant administrators** manage what concerns the nodes of their tenant:
  logs, mesh, policies. They cannot approve, sign, move or revoke a node,
  and see nothing of other tenants beyond what touches their own nodes.

Because it stays one network, what crosses tenants costs nothing extra: a
hub is shared by being a node of tenant `global`, a route from tenant A to a
server of tenant B is an ordinary route with a policy, and all logs go to
one place.

What this is not: isolation from the global administrators. They sign
every node and see everything. Tenants that must not trust them need
separate networks (separate installations, or a federation of signer
chains; neither is planned).

## The tenant is part of the signed binding

`tenant` is a field of the binding, like `tags`
(`internal/binding`): left out when it is `global`, so every binding signed
before the field existed stays valid and means `global`. The control plane
keeps a copy in `nodes.tenant` for its queries; nodes take it from the
binding only.

A tenant held only in the database could be changed by whoever reaches the
database or finds a hole in the admin API, and a tenant administrator could
take another tenant's nodes. In the binding, changing a node's tenant means
signing it again, which only a global administrator can do.

A node may ask for a tenant at enrollment (like `roles_requested`); the
global administrator decides when confirming, and the sign dialog shows it.
Tenant names: `[a-z0-9-]{1,32}`, `global` reserved.

## Policies: a permit is given by whoever owns the resource

Policies are global (ACL.md). A tenant administrator writes them too, under
one rule, the one BoundGate already follows (the receiving side decides):

| A tenant administrator of tenant `a` may write | when |
|---|---|
| `permit` | the **resource** belongs to `a`: the node that is the destination or announces it is a node of `a` |
| `forbid` | the **resource or the principal** belongs to `a`. Forbidding things to one's own nodes and users is always safe: it only restricts |

So access from tenant A to a server of tenant B is given by B's
administrator. Access to a global resource (the exit node, the networks
behind global hubs) is given by a global administrator. And A can restrict
its own people anywhere, including towards other tenants.

The rule is enforced by the control plane, not by the editor. When a tenant
administrator saves a policy, the control plane narrows it:

```cedar
// a permit written by an administrator of tenant "a" is stored as
permit (...) when { <their condition> } when { resource.tenant == "a" };
// a forbid as
forbid (...) when { <their condition> } when { principal.tenant == "a" || resource.tenant == "a" };
```

Whatever the policy says, it acts only inside its area. Policies keep their
author's tenant (`policies.tenant`); a tenant administrator sees and edits
only their tenant's policies, global administrators all of them. The
dry run (validate/evaluate) shows the narrowed form.

New attributes for this:

* `principal.tenant`: the tenant from the principal node's binding.
* `resource.tenant`: the tenant of the node that owns the destination,
  known to the enforcing node from the bindings in its snapshot: the node
  whose overlay address it is, or the node announcing the prefix it lies in
  (the most specific one). An address no node owns, the internet behind an
  exit node, belongs to the exit node's tenant.

Policies are state of the control plane today, not signed. The narrowing is
therefore **delegation, not protection against a compromised control
plane**: such a control plane can serve any policy, as now (R138).

## Logs and mesh

| | Global administrator | Tenant administrator of `a` |
|---|---|---|
| Flows | all | those whose principal **or** resource is in `a` |
| Tunnels, mesh | all | `a`'s nodes in full; global hubs as nodes with only `a`'s edges; no other tenant's nodes |
| Nodes | all, all states | `a`'s approved nodes; pending ones only once confirmed for `a` |
| User sessions | all | sessions on `a`'s nodes |
| System, enrollment, signer chain, settings, admin auth | all | none |

A flow from A to B is in both tenants' view, and each sees the other
side's node name and user (R139).

Every log line carries `tenant` (of the node it is about; both tenants for a
flow: `tenant` and `resource_tenant`), also in the files the SIEM reads.

Per tenant, the global administrator sets the log retention and a quota
for the flow records the control plane stores. A single misbehaving client
filled 5.8 GB in four weeks on pVPN; with a quota one tenant cannot fill the
database for all (R140).

## Tenant administrators

Like global administrators (ADMIN-AUTH.md): OIDC and a passkey, with the
tenant coming from an IdP group:

```yaml
admin:
  group: admins                    # global administrators, as today
  tenant_groups:
    kunde-a: boundgate-admin-kunde-a
    kunde-b: boundgate-admin-kunde-b
```

An admin session carries its scope (`global` or `tenant:<name>`), fixed at
login. Someone in several groups chooses one at login; global wins over a
tenant. Every admin endpoint checks the scope on the server: the API
answers 404, not 403, for an object of another tenant, so ids of other
tenants cannot be probed. The first passkey of a tenant administrator is
approved by a global administrator (like a pending passkey today); tenant
administrators approve further passkeys of their own tenant (R141).

## Risks

| ID | Risk | Handling |
|---|---|---|
| R138 | Policy narrowing is control-plane state: a compromised control plane, or a bug in the narrowing, lets a tenant's policy act outside its tenant | Same trust as policies today; the narrowing is one function applied on save and again when the snapshot is built, with tests per policy shape; the evaluate endpoint shows the stored form |
| R139 | Cross-tenant flows show each side the other's node and user names | Documented; tenants are areas of one organization. Hiding the other side would make a deny impossible to explain |
| R140 | One tenant's log volume slows the control plane for all (single SQLite connection) | Retention and quota per tenant; prune by index in batches (since cd25309) |
| R141 | Admin endpoints that forget the scope check leak or change another tenant's objects | Scope is a parameter of every database query that lists or loads tenant objects (no unscoped variant for tenant sessions); a test calls every admin route with a tenant session against another tenant's ids |

## Steps

1. **Binding and nodes:** `tenant` in the binding (omitted for `global`),
   `nodes.tenant`, choice at confirm, shown in the sign dialog and in
   `boundgatectl admin sign`. Small.
2. **Admin scope:** `admin.tenant_groups`, scope in the admin session, scope
   checks in every admin endpoint and query, the test of R141. The largest
   step: it touches every page of the admin UI.
3. **Cedar:** `principal.tenant`, `resource.tenant` on the enforcing nodes,
   `policies.tenant`, narrowing on save and at snapshot build, the editor
   showing the narrowed form. Medium.
4. **Logs and mesh:** `tenant` on log lines, filters per scope, retention and
   quota per tenant. Medium.

About a week of work in all, most of it step 2. Steps 1 and 3 change what
nodes verify and evaluate, so they need a release of the nodes before a
tenant other than `global` is used; until then every node is `global` and
nothing changes.
