---
title: Kubernetes
---

The operator puts dvarapala in front of a Service without touching the
application, its Service or the route's manifest
([RFC 0019](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0019-operator.md)).
Label an `Ingress`, `HTTPRoute` or `GRPCRoute` (or its namespace), and a
mutating webhook points the route's backends at a dvarapala gateway the
operator runs for each backend Service.

## Install

Kubernetes 1.33 or later. Gateway API routes are handled when their CRDs
are installed.

```sh
kubectl apply --server-side -f \
  https://github.com/franzramadhan/dvarapala/releases/download/v<version>/operator.yaml
```

The manifest holds the `DvarapalaPolicy` CRD, RBAC, the operator
Deployment (2 replicas and a PodDisruptionBudget, namespace `dvarapala`)
and the `MutatingWebhookConfiguration`. The operator generates its own
webhook certificate: no cert-manager needed.

## Protect a route

A policy holds the protection config as dvarapala TOML, the same keys as
the [configuration](configuration.html), minus the ones the operator sets
(`mode`, `listen`, `upstream`, `upstream_protocol`, `[pool]`,
`config_watch`, `metrics.listen`, `[admin]`, `[xdp]`, `[quic]`, `[tls]`):

```yaml
apiVersion: dvarapala.franzramadhan.dev/v1alpha1
kind: DvarapalaPolicy
metadata: {name: default, namespace: shop}
spec:
  config: |
    trusted_proxies = ["10.0.0.0/8"]
    [rate_limit]
    rate = 20
    burst = 40
  secretRef: {name: dvarapala-secrets}  # optional, DVARAPALA__* env
  gateway:
    replicas: 2
    # autoscaling: {maxReplicas: 10, targetCpu: 70}
```

Then label the route, or the namespace for every route in it:

```sh
kubectl -n shop label httproute web dvarapala.franzramadhan.dev/policy=default
```

A route label overrides the namespace's; `none` opts a route out. The
full example, with network policies, is
[`kubernetes.yaml`](https://github.com/franzramadhan/dvarapala/blob/main/examples/kubernetes.yaml).

## What happens

- The webhook replaces each backend Service with a gateway Service
  (`<service>-dvp-<hash>`, same port) and records the originals in the
  annotation `dvarapala.franzramadhan.dev/backends`. Removing the label
  restores them.
- A new gateway Service starts as a **passthrough** to the application's
  pods, so labeling a route never drops a request. Once a gateway pod is
  ready, the Service switches to the gateway pods and never goes back: no
  ready gateway pod means `503` at the route (fail closed).
- Gateway pods run the dvarapala image non-root with a read-only root
  file system (the `restricted` Pod Security Standard), with a readiness
  probe, a PodDisruptionBudget and a topology spread.
- Edits to the policy reach the gateways through their ConfigMap and the
  `config_watch` key: reloadable keys apply in place within the kubelet
  sync (about a minute), other keys roll the gateway pods.
- The rewrite happens in admission, so GitOps tools that diff server
  side (Flux, Argo CD with `ServerSideDiff=true`) see no drift.

The policy's status shows `ready`, the rendered config hash, each
gateway's phase (`Passthrough` or `Protecting`), the routes and any
skipped backends (`ExternalName` Services, Services without a selector,
`https` backends, non-Service backends).

## Things to know

- Each gateway pod has its own buckets: without a `[store]` (see
  [Clusters](clusters.html)), a client's limit is `rate` times the ready
  gateway pods.
- The gateway's peer is the ingress controller's pod: `trusted_proxies`
  must cover those pods, and the controller must set `X-Forwarded-For`.
- Traffic reaches the application through the gateway's ClusterIP, so
  ingress features that pick a pod (sticky sessions, per-pod balancing
  and retries) do not apply. Service-to-service traffic does not pass a
  gateway.
- The webhook uses `failurePolicy: Fail`: while it is down, labeled
  routes cannot be updated (unlabeled routes are never sent to it).
- With default-deny NetworkPolicies, the gateway pods
  (`app.kubernetes.io/name: dvarapala-gateway`) need ingress from the
  ingress controller and egress to the application, DNS and the store.

## Operator flags and metrics

| Flag | Default |
|---|---|
| `--gateway-image` | `ghcr.io/franzramadhan/dvarapala:<operator version>` |
| `--webhook-listen` | `0.0.0.0:9443` |
| `--metrics-listen` | `0.0.0.0:9090` |

| Metric | Labels |
|---|---|
| `dvarapala_operator_admissions_total` | `kind`, `result`: `rewritten`, `unchanged`, `refused` |
| `dvarapala_operator_reconciles_total` | `result`: `ok`, `invalid` |
| `dvarapala_operator_gateways` | `namespace`, `phase`: `passthrough`, `protecting` |

## Remove it

Remove the labels first: the webhook restores the original backends and
the controller deletes gateways no route uses. Then delete the operator.
If it is already gone and labeled routes are stuck, delete the
`MutatingWebhookConfiguration` and re-apply the routes from their
manifests.
