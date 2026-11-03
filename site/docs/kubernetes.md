---
title: Kubernetes
---

The operator puts dvarapala in front of a Service. It does not change the
application, its Service or the manifest of the route
([RFC 0019](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0019-operator.md)).
If you label an `Ingress`, `HTTPRoute` or `GRPCRoute` (or its namespace),
a mutating webhook (a hook that changes objects at admission) points the
backends of the route at a dvarapala gateway. The operator runs one
gateway for each backend Service.

## Install

You need Kubernetes 1.33 or later. The operator handles Gateway API routes
when their CRDs are installed.

```sh
kubectl apply --server-side -f \
  https://github.com/franzramadhan/dvarapala/releases/download/v<version>/operator.yaml
```

The manifest holds the `DvarapalaPolicy` CRD, RBAC, the operator
Deployment (2 replicas and a PodDisruptionBudget, namespace `dvarapala`)
and the `MutatingWebhookConfiguration`. The operator makes its own webhook
certificate, so you do not need cert-manager.

## Protect a route

A policy holds the protection configuration as dvarapala TOML. It uses the
same keys as the [configuration](configuration.html), except the keys that
the operator sets (`mode`, `listen`, `upstream`, `upstream_protocol`,
`[pool]`, `config_watch`, `metrics.listen`, `admin.listen`, `[xdp]`,
`[quic]`, `[tls]`, and `waf.endpoint` with `gateway.waf`):

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

Then label the route. To protect every route in a namespace, label the
namespace:

```sh
kubectl -n shop label httproute web dvarapala.franzramadhan.dev/policy=default
```

A route label overrides the label of its namespace. The value `none`
takes a route out of protection. The full example, with network policies,
is [`kubernetes.yaml`](https://github.com/franzramadhan/dvarapala/blob/main/examples/kubernetes.yaml).

To protect only some rules of a route, list them in the annotation
`dvarapala.franzramadhan.dev/rules`, comma separated. For an `HTTPRoute`
or `GRPCRoute`, list rule `name`s. For an `Ingress`, list path values
(`/api/,/login`). The other rules keep their backends. If a listed rule is
not in the route, it shows in the `status.warnings` of the policy and
changes nothing.

## Console, WAF and mounts

The gateway pods can run what a hand-written dvarapala Deployment has
(RFC 0025). Each item is off unless the `gateway` field of the policy asks
for it:

```yaml
  gateway:
    admin: {enabled: true}
    waf:
      image: ghcr.io/corazawaf/coraza-spoa:<version>@sha256:<digest>
      configMap: shop-coraza          # the agent's config.yaml
      resources: {requests: {cpu: 100m, memory: 96Mi}}
    mounts:
      - {name: pg-ca, configMap: lab-root-ca}   # or secret: <name>
      - {name: geoip, persistentVolumeClaim: {claimName: geoip}}
      - {name: lists, image: {reference: "<registry>/<lists>@sha256:<digest>"}}
    podLabels: {team: shop}
    podAnnotations: {}
```

- `admin`: the operator sets `admin.listen` to `0.0.0.0:9091`. It also
  adds a Service `<backend>-dvp-admin-<port>` (ClientIP affinity) for the
  console and the admin API. `status.gateways[].adminService` names this
  Service. The policy needs a `secretRef` with `DVARAPALA__ADMIN__TOKEN`.
  Its `[admin]` table holds the other admin keys. The operator refuses an
  `[admin]` table without `gateway.admin`.
- `waf`: a `coraza-spoa` sidecar (a second container in the pod) with uid
  10001 and `-autoreload`. The ConfigMap is at
  `/etc/coraza-spoa/config.yaml` in the sidecar. The gateway also mounts
  it at `/etc/dvarapala-waf/` for `waf.rules_files`. The operator sets
  `waf.endpoint` to the shared socket `unix:/run/waf/waf.sock`, so the
  `bind` of the agent must be `unix:///run/waf/waf.sock`. The image must
  start with a prefix in `--waf-images`. An image without a digest is a
  warning in `status.warnings`. A sidecar while `[waf]` is off is also a
  warning.
- `mounts`: up to 16 read-only mounts at `/etc/dvarapala-mounts/<name>/`
  (RFC 0033). Each mount comes from a ConfigMap, a Secret, a
  PersistentVolumeClaim or an image volume:
  - ConfigMaps and Secrets suit a store CA or rule files. They hold 1 MiB
    at most.
  - A claim (`persistentVolumeClaim: {claimName}`) carries larger files,
    for example GeoIP databases, path feeds or an `ml.model`. Something
    else fills the claim, for example a CronJob. The operator never
    creates or deletes it. If a file changes in place, `config_watch`
    sends the change to the gateways with no rollout. If replicas run on
    several nodes, they need a `ReadOnlyMany` or `ReadWriteMany` claim.
  - An image mount (`image: {reference, pullPolicy}`) mounts the files of
    an OCI image or artifact. If `pullPolicy` is unset, it is
    `IfNotPresent`. A new reference rolls the pods. The reference must
    start with a prefix in the `--mount-images` flag of the operator. This
    flag is empty by default, so the operator refuses image mounts until
    the cluster admin names a registry. A reference without a digest is a
    warning.
  - Image volumes need the Kubernetes `ImageVolume` feature gate and a
    runtime that supports it. The gate is beta and off by default in 1.33,
    so make sure that the gate is on in your version. The operator does
    not detect the gate. If a pod cannot start, its events give the
    reason.
- `podLabels` and `podAnnotations`: for network policies and scrapers.
  The operator refuses its own labels and its restart annotation.

If the operator refuses a policy, the policy is `Ready=False` with the
reason. The full examples are
[`kubernetes-console-waf.yaml`](https://github.com/franzramadhan/dvarapala/blob/main/examples/kubernetes-console-waf.yaml)
and, for GeoIP from a claim,
[`kubernetes-geoip.yaml`](https://github.com/franzramadhan/dvarapala/blob/main/examples/kubernetes-geoip.yaml).

## What happens

- The webhook replaces each backend Service with a gateway Service
  (`<service>-dvp-<hash>`, same port). It records the original Services
  in the annotation `dvarapala.franzramadhan.dev/backends`. If you remove
  the label, the webhook restores them.
- A new gateway Service starts as a passthrough to the pods of the
  application, so a new route label never drops a request. When a gateway
  pod is ready, the Service switches to the gateway pods and never goes
  back. If no gateway pod is ready, the route returns `503` (fail closed).
- Gateway pods run the dvarapala image as non-root with a read-only root
  file system (the `restricted` Pod Security Standard). They also have a
  readiness probe, a PodDisruptionBudget and a topology spread.
- Edits to the policy reach the gateways through their ConfigMap and the
  `config_watch` key. Reloadable keys apply in place within the kubelet
  sync (about a minute). Other keys roll the gateway pods.
- The rewrite happens in admission. Thus GitOps tools that diff on the
  server side (Flux, Argo CD with `ServerSideDiff=true`) see no drift.

The status of the policy shows `ready`, the hash of the rendered
configuration, the phase of each gateway (`Passthrough` or `Protecting`),
the routes and any skipped backends (`ExternalName` Services, Services
without a selector, `https` backends, non-Service backends).

## Things to know

- Each gateway pod has its own buckets. Without a `[store]` (see
  [Clusters](clusters.html)), the limit of a client is `rate` times the
  number of ready gateway pods.
- The peer of the gateway is the pod of the ingress controller. Thus
  `trusted_proxies` must cover those pods, and the controller must set
  `X-Forwarded-For`.
- Traffic reaches the application through the ClusterIP of the gateway.
  Thus ingress features that pick a pod (sticky sessions, per-pod
  balancing and retries) do not apply. Service-to-service traffic does not
  go through a gateway.
- The webhook uses `failurePolicy: Fail`. While the webhook is down, you
  cannot update labeled routes. Unlabeled routes never go to the webhook.
- The gateways run the container image. This image has every feature,
  `ml` included.
- The operator owns `[tls]`, so the gateway listener is cleartext behind
  the ingress controller. Thus `[fingerprint]` rules and
  `routes.key = "ja4"` never see a JA4.
- Without `gateway.waf`, `[waf]` needs an agent that the pod can reach
  over TCP (`endpoint = "<host>:<port>"`). An example is a `coraza-spoa`
  Deployment and Service (see [WAF](waf.html)).
- If `[challenge]` runs on more than one gateway pod, every pod needs the
  same `challenge.secret` (through `secretRef`). If not, a pass from one
  pod fails on the other pods.
- With default-deny NetworkPolicies, the gateway pods
  (`app.kubernetes.io/name: dvarapala-gateway`) need ingress from the
  ingress controller. They also need egress to the application, DNS and
  the store.

## Operator flags and metrics

| Flag | Default |
|---|---|
| `--gateway-image` | `ghcr.io/franzramadhan/dvarapala:<operator version>` |
| `--webhook-listen` | `0.0.0.0:9443` |
| `--metrics-listen` | `0.0.0.0:9090` |
| `--waf-images` | `ghcr.io/corazawaf/coraza-spoa` (comma separated prefixes. If empty, the operator refuses every sidecar.) |

| Metric | Labels |
|---|---|
| `dvarapala_operator_admissions_total` | `kind`, `result`: `rewritten`, `partial`, `unchanged`, `refused` |
| `dvarapala_operator_reconciles_total` | `result`: `ok`, `invalid` |
| `dvarapala_operator_gateways` | `namespace`, `phase`: `passthrough`, `protecting`; `admin`, `waf`: `true`, `false` |

## Remove it

Remove the labels first. The webhook then restores the original backends,
and the controller deletes the gateways that no route uses. Then delete
the operator. If the operator is already gone and labeled routes are
stuck, delete the `MutatingWebhookConfiguration`. Then apply the routes
again from their manifests.
