# 0019: Kubernetes operator with route rewrite to a gateway

| Status | Date | PR | Release |
|---|---|---|---|
| implemented | 2026-10-29 | #140 | v0.13.0 |

> A Kubernetes operator that puts dvarapala in front of a Service when
> the Ingress, HTTPRoute or GRPCRoute that reaches it, or its namespace,
> carries a label: the operator runs a dvarapala gateway for that Service
> and a mutating webhook points the route's backend at it, with no change
> to the application, its Service or the route's manifest.

## Problem

Running dvarapala in Kubernetes today means hand-written manifests:

- A gateway Deployment in front of a Service means a second Service, a
  config, and an edit of every Ingress or HTTPRoute backend, repeated per
  service and kept in step on each dvarapala upgrade and each route
  change.
- A sidecar means editing every Deployment: a container, its config, a
  new port and a Service `targetPort` change, plus exceptions in every
  namespace's admission (Kyverno, Pod Security) and runtime (Tetragon)
  policies.
- Policy changes (a lower `rate_limit.rate` during an attack) mean
  editing a ConfigMap and then sending `SIGHUP` or calling `POST /reload`
  (RFC 0014) on every pod by hand.

Most of the traffic a DDoS gateway protects against enters the cluster
through an Ingress or a Gateway API route. Putting dvarapala on that path
needs no change to the application pods, and the route is already the
place where operators decide what traffic goes where.

## Proposal

- A new binary, `dvarapala-operator`, shipped as its own image
  (`ghcr.io/franzramadhan/dvarapala-operator`) with one manifest,
  `deploy/operator.yaml` (CRD, RBAC, Deployment with 2 replicas and a
  PodDisruptionBudget, the `MutatingWebhookConfiguration`). One process
  runs the admission webhook and a controller (leader elected).
- **Policy**: a namespaced `DvarapalaPolicy` holds the protection config
  as TOML, the same keys as `CONFIG.md`, and the gateway's shape:

  ```yaml
  apiVersion: dvarapala.franzramadhan.dev/v1alpha1
  kind: DvarapalaPolicy
  metadata: { name: default, namespace: shop }
  spec:
    config: |
      trusted_proxies = ["10.0.0.0/8"]
      [rate_limit]
      rate = 50
      burst = 100
      [detection]
      mode = "enforce"
    secretRef: { name: dvarapala-secrets }  # optional, DVARAPALA__* env
    gateway:
      replicas: 2
      autoscaling: { maxReplicas: 10, targetCPU: 70 }  # optional, an HPA
      resources: { requests: { cpu: 50m, memory: 16Mi }, limits: { memory: 64Mi } }
  ```

- **Opt in** with the label `dvarapala.franzramadhan.dev/policy=<name>`
  on a route (`Ingress`, `HTTPRoute`, `GRPCRoute`) or on a namespace (then
  every such route in it). A route label overrides the namespace's; the
  value `none` opts a route out (`none` is not a valid policy name).
  Labels, not annotations, so the webhook's `objectSelector` and
  `namespaceSelector` send it only opted-in routes.
- **Gateways**: one per (backend Service, port, policy) that an opted-in
  route references. A gateway is a Deployment of the dvarapala image, a
  ConfigMap with the policy's TOML, and a Service named
  `<service>-dvp-<hash>` (truncated to 63 characters) in the backend's
  namespace, with one port of the same number as the backend's. The
  gateway's own keys come as environment variables, so one ConfigMap per
  policy serves all its gateways:
  `DVARAPALA__LISTEN=0.0.0.0:8080`,
  `DVARAPALA__UPSTREAM=http://<service>.<namespace>.svc:<port>`
  (`https://` for a port with `appProtocol: https`),
  `DVARAPALA__UPSTREAM_PROTOCOL` (`http2` for `appProtocol:
  kubernetes.io/h2c` or a `GRPCRoute` backend), `DVARAPALA__CONFIG_WATCH=10s`.
  Gateway pods run non-root with a read-only root file system and no
  capabilities (the `restricted` Pod Security Standard), with a
  readiness probe, a PodDisruptionBudget and a topology spread over
  nodes. The operator owns these objects; nothing in the user's
  manifests refers to them.
- **Route rewrite** (the webhook, on route create and update): each
  backend Service of the route is replaced by its gateway's Service; the
  port stays the same, so only the name changes. Covered: `backendRefs`
  of `HTTPRoute` and `GRPCRoute` rules (weights and filters kept, so a
  weighted canary gets one gateway per backend), and the `Ingress`
  `spec.defaultBackend` and `rules[].http.paths[].backend.service`. The
  original names are recorded in the annotation
  `dvarapala.franzramadhan.dev/backends`. When the label goes away (the
  webhook sees it on the old object), the originals are restored.
  Backends that are not Services (`resource` backends, other `kind`s) and
  Services of type `ExternalName` or without a selector are left as they
  are and reported in the policy's status.
- **No outage on first enable**: the webhook creates the gateway Service
  in the same request (`sideEffects: NoneOnDryRun`; on a dry run it only
  patches), first as a **passthrough**: selector and `targetPort` copied
  from the backend Service, so the rewritten route reaches the
  application exactly as before. The controller then creates the gateway
  Deployment and, once it has a ready pod, switches the Service's
  selector to the gateway pods and its `targetPort` to 8080. From then on
  the Service never goes back to passthrough: no ready gateway pod means
  no endpoints and a `503` at the route (fail closed). The passthrough
  phase is the only fail open; it is bounded by the gateway's first
  rollout, and the status and a metric show it.
- **GitOps**: the rewrite happens in admission, inside the apply of the
  tool that owns the route. Tools that diff server side see the rewritten
  object in their dry run and report no drift: Flux, and Argo CD with
  `ServerSideDiff=true`. Argo CD's client-side diff needs
  `ignoreDifferences` on the backend names. Routes that existed before
  the label (or before the operator) are rewritten when the controller
  writes the `backends` annotation on them, which passes through the
  webhook like any update.
- **Reload without a restart**: the controller renders each policy to a
  ConfigMap (owner reference to the policy); kubelet updates the mounted
  file (within its sync period, about a minute), and a new dvarapala key,
  `config_watch`, polls the file's content hash and reloads as `SIGHUP`
  does (RFC 0014): reloadable keys apply in place, buckets and the
  detector baseline kept; a file that fails to validate is refused whole
  and the running config stays. A change to a key that needs a restart
  rolls the gateway Deployment instead (the operator owns it), through a
  config hash in its pod template. During an attack the admin API's
  manual blocks (RFC 0014) on the gateway pods are the immediate lever.
- **Validation**: the controller checks that `spec.config` parses as TOML
  and sets none of the keys the operator owns (`mode`, `listen`,
  `upstream`, `upstream_protocol`, `[pool]`, `config_watch`,
  `metrics.listen`, `[admin]`, `[xdp]`, `[quic]`, `[tls]`); a bad policy
  gets `Ready=False` with the reason and its ConfigMap is not updated, so
  running gateways keep the last good config. Unknown keys and value
  errors are caught by dvarapala at start (the new pod fails readiness,
  the rollout stops) and at reload (refused, logged).
- **Status** of a `DvarapalaPolicy`: `Ready`, `observedGeneration`,
  `configHash`, `gateways` (Service, port, phase `Passthrough` or
  `Protecting`, ready replicas), `routes`, `skippedBackends`. A policy
  with gateways has a finalizer: it cannot be deleted while a route still
  points at one of them.
- **Rate limits per gateway pod**: each gateway replica has its own
  buckets, so without a `[store]` a Service's effective limit is `rate`
  times its ready gateway pods. A policy with `[store]` (RFC 0010, the URL
  from `secretRef`) shares the budget across replicas. The docs say so
  next to the first example.
- **Client address**: the gateway's peer is the ingress or Gateway API
  controller's pod. `trusted_proxies` must cover those pods and the
  controller must set `X-Forwarded-For`, as it would for the application.
- **Webhook availability**: `failurePolicy: Fail`. A labeled route is
  never stored unprotected, and an update to it is refused while the
  webhook is down; the selectors keep unlabeled routes out of it, and two
  replicas with a PodDisruptionBudget keep it up. `Ignore` is not
  offered: with it, any update during an outage would restore the
  original backend.
- **Webhook TLS**: the operator generates a self-signed CA and serving
  certificate at start, keeps them in a Secret in its namespace, and
  patches the CA into the `MutatingWebhookConfiguration`. No cert-manager
  needed.
- **Versions**: the gateway image is
  `ghcr.io/franzramadhan/dvarapala:<operator version>`, overridable with
  `--gateway-image` (a digest reference is accepted). Kubernetes 1.29 or
  later; Gateway API v1 (`HTTPRoute`, `GRPCRoute`) when installed, and
  the operator skips those kinds when their CRDs are absent.

### Policy engines and network policy

The gateway pods are new pods in the application's namespace; the
application pods are untouched.

- **Kyverno**: validate rules see the gateway pods. They pass the
  `restricted` profile and the common library policies (no `latest`
  tag, resources set, probes, non-root). A registry allowlist needs
  `ghcr.io/franzramadhan/*`, or the image mirrored and set with
  `--gateway-image`. No `PolicyException` is needed.
- **Tetragon**: policies that select the application by `podSelector`
  do not match the gateway pods (label
  `app.kubernetes.io/name: dvarapala-gateway`); a namespace-wide
  `TracingPolicyNamespaced` with a binary allowlist needs `/dvarapala`
  added.
- **NetworkPolicy**: in a namespace with default deny, the gateway pods
  need ingress from the ingress or Gateway API controller and egress to
  the application pods (and to DNS and the `[store]`); the application
  pods need ingress from the gateway pods. The operator does not write
  NetworkPolicies; `examples/kubernetes/` ships them
  (`networking.k8s.io/v1` and a `CiliumNetworkPolicy`), selecting the
  gateway pods by their labels.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/operator/src/crd.rs` | `DvarapalaPolicy` spec and status types, the CRD schema |
| `crates/operator/src/routes.rs` | pure: an `Ingress`, `HTTPRoute` or `GRPCRoute` (as JSON) and the gateway names in, a JSON patch out; the restore when the label goes; skipped backends |
| `crates/operator/src/gateway.rs` | pure: a policy, a backend Service and a port in, the Deployment, the passthrough and protecting Service, the PDB and the HPA out |
| `crates/operator/src/policy.rs` | pure: TOML parse, the owned-key check, the rendered ConfigMap, its hash, reload or restart |
| `crates/operator/src/webhook.rs` | the HTTPS admission server: `AdmissionReview` in, the passthrough Service created, `routes` out |
| `crates/operator/src/controller.rs` | reconcile policies and gateways: ConfigMaps, Deployments, the passthrough switch, garbage collection of unreferenced gateways, status |
| `crates/operator/src/cert.rs` | the self-signed CA and serving pair, the `caBundle` patch |
| `crates/operator/src/main.rs` | flags, the two loops, leader election |
| `crates/dvarapala/src/watch.rs` | `config_watch`: poll the config file's hash, trigger the `SIGHUP` reload path |
| `deploy/operator.yaml` | CRD, RBAC, Deployment, PDB, Service, webhook configuration |

New dependencies, operator only (the `dvarapala` binary gains none):
`kube` (`runtime`, `derive`, `admission`, `rustls-tls`), `k8s-openapi`,
`schemars`, `rcgen`. Routes are handled as JSON, so no Gateway API crate.
All permissive, checked with `cargo deny check`.

### Configuration

Operator flags:

| Flag | Default | |
|---|---|---|
| `--gateway-image` | `ghcr.io/franzramadhan/dvarapala:<version>` | image of the gateways |
| `--webhook-listen` | `0.0.0.0:9443` | admission server |
| `--metrics-listen` | `0.0.0.0:9090` | operator metrics |

Labels and annotations (prefix `dvarapala.franzramadhan.dev/`):

| Name | On | |
|---|---|---|
| `policy` (label) | route or namespace | the `DvarapalaPolicy` in the route's namespace; `none` opts a route out |
| `backends` (annotation) | route, set by the operator | original backend names, used to restore them |

New dvarapala key (in `CONFIG.md`, `examples/dvarapala.toml`):

| Key | Default | |
|---|---|---|
| `config_watch` | `""` | poll interval of the `--config` file, for example `"10s"`, at least `"1s"`; a changed file reloads like `SIGHUP`. Empty is off |

### Logs and metrics

| | |
|---|---|
| `msg="config changed on disk"` | `config_watch` saw a new hash, followed by the RFC 0014 reload lines |
| `dvarapala_operator_admissions_total{kind,result}` | `rewritten`, `restored`, `skipped`, `refused` |
| `dvarapala_operator_reconciles_total{result}` | `ok`, `invalid`, `error` |
| `dvarapala_operator_gateways{policy,phase}` | gateways in `passthrough` and `protecting` |
| Kubernetes Events on the route and the policy | refusals, skipped backends, invalid policies, the passthrough switch |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | an `HTTPRoute` labeled `policy=default` with two weighted `backendRefs` to `web:80` and `web-canary:80` | `routes` | both names replaced by their gateway Services, ports, weights and filters unchanged, `backends` annotation set | unit (`routes`) |
| 2 | an `Ingress` with a `defaultBackend` and two paths, one to a Service, one to a `resource` backend | `routes` | the Service backends replaced, the `resource` one kept and reported | unit (`routes`) |
| 3 | a rewritten route | the label removed | the original names back, the annotation removed | unit (`routes`) |
| 4 | a rewritten route | admitted again (an unrelated update, or a second webhook entry) | the same object: no double rewrite | unit (`routes`) |
| 5 | a route labeled `none` in a namespace labeled `policy=default` | `routes` | no patch | unit (`routes`) |
| 6 | a backend of type `ExternalName`, or without a selector | `routes` | left as it is, reported in `skippedBackends` | unit (`routes`) |
| 7 | a policy and the Service `web` port 80 with `appProtocol: kubernetes.io/h2c` | `gateway` | a Deployment with `DVARAPALA__UPSTREAM=http://web.shop.svc:80`, `UPSTREAM_PROTOCOL=http2`, restricted security context, PDB; a Service on port 80 | unit (`gateway`) |
| 8 | the same | `gateway` passthrough, then protecting | first the backend's selector and `targetPort`, then the gateway pods' labels and 8080 | unit (`gateway`) |
| 9 | a policy setting `listen`, one setting `[admin]`, one with broken TOML | render | each `Ready=False` naming the key or the parse error; no ConfigMap change | unit (`policy`) |
| 10 | two policies differing only in `rate_limit.rate`, two differing in `[l4]` | reload or restart | the first reload, the second restart; the operator's reloadable list equals the one in `crates/dvarapala/src/reload.rs` | unit (`policy`) |
| 11 | arbitrary route JSON and label values | `routes` | no panic; a patch or a refusal | fuzz (`route_rewrite`) |
| 12 | dvarapala with `config_watch = "100ms"` at `rate = 100` | the file is rewritten with `rate = 1` | within 1 s the second request from a client is `429`; no connection dropped | integration (`dvarapala/tests`) |
| 13 | dvarapala with `config_watch` | the file is rewritten with an invalid route | `config reload failed`, the running config unchanged | integration (`dvarapala/tests`) |
| 14 | dvarapala with `config_watch` | the file is replaced through a symlink swap, as kubelet does | reloaded once | integration (`dvarapala/tests`) |
| 15 | a kind cluster with Envoy Gateway, the operator, a policy at `rate = 1`, an echo Deployment, its Service and an `HTTPRoute` | label the route, keep sending requests | no request fails during the switch; after `Protecting`, the second request per client `429`; echo Deployment and Service unchanged | e2e (`kind` job) |
| 16 | the same with ingress-nginx and an `Ingress` | the same | the same | e2e (`kind` job) |
| 17 | the same, policy edited to `rate = 100` | requests after the kubelet sync | `200`; the gateway pods not restarted | e2e (`kind` job) |
| 18 | the same, the gateway Deployment scaled to zero | a request | `503`; the Service did not go back to passthrough | e2e (`kind` job) |
| 19 | a rewritten route | `kubectl apply --server-side --dry-run=server` of its manifest, then a diff | no difference on the backends | e2e (`kind` job) |
| 20 | the operator scaled to zero | update a labeled route, then an unlabeled one | the first refused, the second stored | e2e (`kind` job) |
| 21 | a kind cluster with Cilium and `kubeProxyReplacement=true`, a namespace enforcing `restricted` Pod Security | label a route | gateway pods admitted and running, case 15's result | e2e (`kind` job, Cilium) |

## Alternatives

| Option | Why not |
|---|---|
| Sidecar injection into application pods (webhook on pods, port rename or `iptables` redirect) | changes every application pod, needs Kyverno and Pod Security exceptions for `iptables`, Tetragon allowlists in every namespace, and limits per application pod. It is the only way to cover service-to-service traffic, so it stays a candidate for a follow-up RFC |
| The user edits each route's backend by hand to the gateway Service | one edit per backend per route, kept in step by hand; the label is one line and survives backend changes |
| The controller patches routes instead of the webhook | outside the GitOps tool's apply: its server-side dry run would not see the rewrite and would report drift on every sync |
| The webhook refuses the label until a gateway is ready | needs the gateway declared first (a second object per Service); the passthrough phase gives the same safety with one label |
| Annotations for opt-in | the webhook's `objectSelector` matches labels only, so every route in the cluster would go through the webhook |
| A gateway per namespace or per policy, routing by Host to many Services | one dvarapala process has one upstream (or one pool); per-Service gateways keep each one simple and each blast radius small |
| Gateways that upstream to pod IPs with a pool (RFC 0015) | keeps per-pod balancing and health but makes the operator mirror EndpointSlices into the config; the Service's ClusterIP is enough to start |
| A Gateway API extension (an `ExtensionRef` filter, ext_authz or ext_proc to dvarapala) | implementation specific; dvarapala would become an authorizer and give up proxying, buffering and challenges |
| Structured CRD fields mirroring every `CONFIG.md` key | a second schema to keep in step with every RFC; TOML keeps one reference |
| The operator calls `POST /reload` on each gateway pod | reload reads the mounted file, which kubelet updates on its own schedule anyway; `config_watch` needs no admin token or pod-to-pod call |
| cert-manager for the webhook certificate | an extra cluster dependency for one serving pair |
| Go and controller-runtime | a second toolchain; `kube` covers the CRD, the controller and admission in the workspace's language |

## Security and resource limits

- **Trade-offs to accept**: routes that go through the ingress reach the
  application through the gateway and its ClusterIP, so ingress features
  that pick an application pod are lost: sticky sessions, per-pod load
  balancing such as EWMA, per-pod retries and outlier detection. One
  extra in-cluster hop (well under a millisecond). Service-to-service
  traffic inside the cluster does not go through a gateway.
- The webhook can rewrite every opted-in route and create Services in its
  namespace, so its RBAC is the narrowest that works: read and update
  `ingresses`, `httproutes`, `grpcroutes`; read namespaces and Services;
  create, update and delete Deployments, Services, ConfigMaps,
  PodDisruptionBudgets and HPAs labeled as gateways; the policy status;
  Events; its own Secret and the one `MutatingWebhookConfiguration` by
  name. It never reads the Secrets that `secretRef` names: they reach the
  gateway as `envFrom`.
- Anyone who can label a route can already point it anywhere; the label
  only points it at a gateway the operator builds from a policy in the
  same namespace. Policy authors cannot set the owned keys, so a policy
  cannot open an admin listener, attach XDP or change the upstream.
- Admission requests are capped at 3 MiB (the API server's limit);
  `routes` is pure and covered by a fuzz target.
- Per gateway pod: default requests 50m CPU and 16 MiB, memory limit 64
  MiB (the RFC 0001 idle budget is under 10 MB), all set per policy. A
  policy enabling `[waf]` (RFC 0017) needs a higher limit, and the
  controller warns in the status when it is lower than that RFC's
  measured budget.
- `config_watch` reads one file per interval, at least `1s`.

## Rollout

- **Rollout:** v0.13.0, a minor release after acceptance. Nothing changes for
  existing users: the operator is a new image and manifest, and
  `config_watch` is off unless set. Install with
  `kubectl apply -f https://github.com/franzramadhan/dvarapala/releases/download/v<version>/operator.yaml`,
  create a policy, label a route or a namespace. The `title` check gains
  the scope `operator`; `release.yml` builds the operator image and
  attaches `operator.yaml`; a `kind` e2e job (with kube-proxy and with
  Cilium replacing it) runs when `crates/operator`, `deploy/` or
  `crates/dvarapala/src/watch.rs` changes. `examples/kubernetes/` holds a
  policy, labeled `Ingress` and `HTTPRoute` examples and the
  NetworkPolicies. A new site page, `site/docs/kubernetes.md`.
- **Off switch:** remove the label: the webhook restores the original
  backends and the controller deletes the gateways no route references.
  Removing the operator: remove the labels first; while the webhook is
  down, labeled routes cannot be updated, so a stuck uninstall is undone
  by deleting the `MutatingWebhookConfiguration` and re-applying the
  routes from their manifests.

## Implementation notes

Found while building, folded back from the PRs:

- Kubernetes 1.33 or later, not 1.29: `kube` 4.2 is built on
  `k8s-openapi` 0.28, whose oldest API is 1.33. The e2e runs on the `kind`
  default (1.37).
- `config_watch` accepts `100ms` and up, not `1s`: case 12 needs a sub
  second interval, and reading one small file ten times a second is
  cheap. It compares the file's bytes, not a hash, and skips a read error
  (a kubelet swap in progress) until the next tick.
- As proposed, the webhook creates a missing gateway Service in
  passthrough (`sideEffects: NoneOnDryRun`) and rewrites the backends in
  the user's own request. A first build had the controller patch the
  routes instead; case 19 caught it: the controller then owned
  `.spec.rules`, and the user's next `kubectl apply --server-side` of
  their manifest conflicted. The controller still patches a route when a
  policy appears after its routes, or to restore backends after a label
  removal (equal values, no conflict).
- The controller keeps an unused gateway Service for 60 s after its
  creation: the webhook creates it just before the route that uses it is
  stored.
- Two webhook entries, one on labeled routes anywhere and one on any route
  in a labeled namespace, so the API server calls the webhook only for
  opted-in routes; an unlabeled route is never refused (case 20).
- A label removed from a route in an unlabeled namespace matches neither
  entry: the controller restores the backends on its next reconcile.
- Backends with `appProtocol: https` (or a `https` port name) are skipped
  and reported in `skippedBackends`: the gateway speaks cleartext to its
  upstream, and TLS to the backend is a follow-up.
- No leader election, no finalizer and no Kubernetes Events. Every
  replica reconciles: every write is a server-side apply with the same
  field manager or a JSON patch computed from the live object, so two
  replicas converge on the same objects. Deleting a policy restores its
  routes and garbage-collects its gateways on the next reconcile instead
  of being blocked by a finalizer. Refusals, skipped backends and invalid
  policies are in the policy status and the operator's log.
- Garbage collection runs only after every route patch in the namespace
  succeeded, so a gateway is never deleted while a route may still point
  at it.
- Metrics: `dvarapala_operator_gateways{namespace,phase}` (per namespace,
  not per policy), `dvarapala_operator_admissions_total{kind,result}` with
  `rewritten`, `unchanged` and `refused`, and
  `dvarapala_operator_reconciles_total{result}` with `ok` and `invalid`
  per policy (a failed reconcile is logged and retried after 10 s).
- The e2e policy runs one gateway replica: without a shared store each
  gateway pod has its own buckets, and ingress-nginx spreads requests
  over pods, so "the second request is 429" needs one pod. The e2e waits
  for the Envoy proxy, not the Gateway's `Programmed` condition, which
  kind never sets without a load balancer.
- Case 18 scales the operator to zero first: a running operator applies
  the gateway's replica count again right away. Case 20 runs in the same
  window.
- The webhook's serving certificate is self-signed, generated by the
  first replica into the Secret `dvarapala-operator-tls`, and set as the
  `caBundle` by each replica on start. No cert-manager dependency.
- The example is one file, `examples/kubernetes.yaml`, not a directory.
- `[waf]` (RFC 0017, shipped after this RFC was accepted) is in the
  operator's reloadable list: the binary reloads the agent settings in
  place, so a change to them does not roll the gateway pods.
