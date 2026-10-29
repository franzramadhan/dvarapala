# 0019: Kubernetes operator with sidecar injection

| Status | Date | PR | Release |
|---|---|---|---|
| draft | 2026-10-29 | #140 | |

> A Kubernetes operator that puts dvarapala in front of an existing
> workload when its pod template carries an annotation: a mutating
> webhook adds dvarapala as a native sidecar and steers the Service's
> traffic through it, with no change to the application image, its
> Service or its Ingress.

## Problem

Running dvarapala in Kubernetes today means hand-written manifests:

- A gateway Deployment in front of a Service means a second Service, an
  Ingress or Gateway edit, a hop, and its own scaling. Teams that own only
  their Deployment (the platform team owns the Ingress) cannot do it.
- A hand-added sidecar means editing every Deployment: the container, its
  config, a new port and a Service `targetPort` change, repeated per
  service and kept in step on each dvarapala upgrade.
- Policy changes (a lower `rate_limit.rate` during an attack) mean
  editing a ConfigMap and then sending `SIGHUP` or calling `POST /reload`
  (RFC 0014) on every pod by hand.
- Egress shaping (RFC 0007) needs the same sidecar plus `HTTP_PROXY` in
  every container.

The service mesh pattern (Istio, Linkerd) solved the same problem for
mTLS: a namespace label or a pod annotation, an admission webhook that
injects a proxy, and traffic redirected to it. Operators already know
that pattern, so dvarapala should use it.

## Proposal

- A new binary, `dvarapala-operator`, shipped as its own image
  (`ghcr.io/franzramadhan/dvarapala-operator`) with one manifest,
  `deploy/operator.yaml` (CRD, RBAC, Deployment with 2 replicas and a
  PodDisruptionBudget, the `MutatingWebhookConfiguration`). It runs
  two loops in one process: the admission webhook and a controller.
- **Opt in** per namespace (label `dvarapala.franzramadhan.dev/inject=enabled`)
  or per pod template (annotation `dvarapala.franzramadhan.dev/inject: "true"`).
  A pod annotation `"false"` opts out inside an enabled namespace. The
  webhook only receives pods that opted in (`namespaceSelector` and
  `objectSelector`), and never pods in `kube-system` or the operator's own
  namespace.
- **Policy**: a namespaced `DvarapalaPolicy` holds the protection config
  as TOML, the same keys as `CONFIG.md`. The pod annotation
  `dvarapala.franzramadhan.dev/policy: <name>` picks one; without it the
  policy named `default` in the pod's namespace. No policy found: the pod
  is refused (fail closed) with a message naming the missing policy.

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
    sidecar:
      resources: { requests: { cpu: 10m, memory: 16Mi }, limits: { memory: 64Mi } }
  ```

- **Injection** (the webhook, on pod `CREATE`): it adds dvarapala as a
  native sidecar (an init container with `restartPolicy: Always`, so it
  starts and is ready before the application and stops after it; Jobs
  still complete). The sidecar reads the policy's TOML from a ConfigMap
  the controller renders, and gets its per-pod keys as `DVARAPALA__*`
  environment variables, so one ConfigMap serves every pod:
  `DVARAPALA__LISTEN=0.0.0.0:15080`,
  `DVARAPALA__UPSTREAM=http://127.0.0.1:<app port>`,
  `DVARAPALA__METRICS__LISTEN=0.0.0.0:15090`,
  `DVARAPALA__CONFIG_WATCH=10s`. The sidecar runs as non-root with a
  read-only root file system and no capabilities, so it passes the
  `restricted` Pod Security Standard. It has a startup probe (the
  application starts only once it passes), resource requests and limits,
  and fixed container names (`dvarapala`, `dvarapala-egress`,
  `dvarapala-init`), so policy engines can match it (see Policy engines).
- **Which port**: annotation `dvarapala.franzramadhan.dev/port: <name or number>`,
  one container port per pod. Without it: the only TCP container port of
  the pod; a pod with several is refused with a message asking for the
  annotation.
- **Traffic redirect**, annotation `dvarapala.franzramadhan.dev/redirect`:
  - `port-name` (default, no privileges): Services and EndpointSlices
    resolve a named `targetPort` per pod. The webhook removes the name
    from the application's port and gives it to the sidecar's port 15080.
    A Service with `targetPort: http` now reaches the sidecar, which
    proxies to `127.0.0.1:<app port>`. Probes that named the port are
    rewritten to its number, so kubelet probes go straight to the
    application and are never rate limited. Pods without the sidecar
    during a rollout keep the name on the application port, so mixed
    EndpointSlices route right. Not covered: a Service with a numeric
    `targetPort`, and clients that dial the pod IP and port directly.
    The controller lists those Services in the policy's status (see the
    open question on Service mutation).
    To check first (case 16): that a named `targetPort` resolves to a
    port declared on a native sidecar (a restartable init container), not
    only on a regular container. If the cluster versions we support do
    not, `port-name` mode injects a regular container instead and keeps
    the native sidecar for `iptables` mode and egress.
  - `iptables` (opt-in): an init container (the operator image, which
    carries `iptables-nft`) adds `PREROUTING` `REDIRECT` rules from the
    application port to 15080, for IPv4 and IPv6. Every inbound
    connection goes through the sidecar, numeric `targetPort` and direct
    pod IP included. The sidecar's own connection to `127.0.0.1` goes
    through `OUTPUT`, so it does not loop. Needs `NET_ADMIN` and
    `NET_RAW` on the init container, which the `baseline` and
    `restricted` Pod Security Standards refuse. Kubelet probes to that
    port go through the sidecar too. The rules live in the pod's own
    network namespace, after the Service has been resolved to a pod IP
    and port, so they work the same with kube-proxy and with a kube-proxy
    replacement (Cilium with `kubeProxyReplacement`, socket load balancing
    included): neither rewrites a packet once it is inside the pod. No
    outbound traffic is redirected (egress uses `HTTP_PROXY`), so Cilium's
    `socketLB.hostNamespaceOnly`, which Istio needs for its outbound
    redirect, is not required.
- **Egress** (opt-in), annotation `dvarapala.franzramadhan.dev/egress: <policy>`:
  a second native sidecar in `mode = "forward"` (RFC 0007) on
  `127.0.0.1:15081`, and `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`,
  `https_proxy` and `NO_PROXY` (`.svc`, `.cluster.local`, the policy's
  `spec.noProxy`) set on every application container that does not
  already set them. Only clients that honor these variables are shaped;
  the rest go direct.
- **Reload without a restart**: the controller renders each policy to a
  ConfigMap `dvarapala-<policy>` (owner reference to the policy). Kubelet
  updates the mounted file (within its sync period, about a minute); a new
  dvarapala key, `config_watch`, polls the file's content hash and, on a
  change, reloads exactly as `SIGHUP` does (RFC 0014): the reloadable keys
  apply in place, a file that fails to validate is refused whole and the
  running config stays. Keys that need a restart take effect on the next
  rollout; the pod annotation `dvarapala.franzramadhan.dev/config-hash`
  records what each pod started with, and the status counts the pods
  started from an older one.
- **Validation**: the controller checks that `spec.config` parses as TOML
  and sets none of the keys the operator owns (`mode`, `listen`,
  `upstream`, `config_watch`, `metrics.listen`, `[admin]`, `[xdp]`,
  `[quic]`, `[tls]`); a bad policy gets `Ready=False` with the reason and
  its ConfigMap is not updated, so running pods keep the last good config.
  Unknown keys and value errors are caught by the sidecar at start
  (the pod fails its startup probe) and at reload (refused, logged).
- **Status** of a `DvarapalaPolicy`: `Ready`, `observedGeneration`,
  `configHash`, `injectedPods`, `stalePods`, `bypassingServices` (Services
  selecting injected pods with a numeric `targetPort` in `port-name`
  mode).
- **Per-pod limits**: every sidecar has its own buckets, so without a
  `[store]` the effective limit of a Service is `rate` times its ready
  pods. A policy with `[store]` (RFC 0010, the URL from `secretRef`)
  shares the budget across pods. The docs say so next to the first
  example.
- **Webhook availability**: `failurePolicy: Fail`, so an opted-in pod is
  never created without its protection (fail closed). Two replicas, a
  PodDisruptionBudget and the selectors above keep that from blocking
  anything else. `deploy/operator.yaml` documents switching to `Ignore`
  for those who prefer availability; pods admitted while the webhook is
  down then run without the sidecar and are not in `injectedPods`.
- **Webhook ordering**: `reinvocationPolicy: IfNeeded`, so a later
  mutating webhook (a Kyverno mutate policy, for example) that changes the
  pod gets the sidecar re-checked; injection is idempotent (case 6).
- **Webhook TLS**: the operator generates a self-signed CA and serving
  certificate at start, keeps them in a Secret in its namespace, and
  patches the CA into the `MutatingWebhookConfiguration`. No cert-manager
  needed.
- **Versions**: the sidecar image is
  `ghcr.io/franzramadhan/dvarapala:<operator version>`, overridable with
  `--sidecar-image` (a digest reference is accepted, for policies that
  require one). Kubernetes 1.29 or later (native sidecars on by
  default).

### Policy engines

Admission policy and runtime enforcement see the injected containers like
any other, so a cluster that runs them needs the sidecar allowed. The
operator never edits those policies; `examples/kubernetes/` ships the
exceptions below and the docs page links them.

**Kyverno**

- Kyverno's validate rules run in a validating webhook, which the API
  server calls after every mutating webhook: they see the pod with the
  sidecar. In `port-name` mode the sidecar passes the `restricted` Pod
  Security profile and the common library policies (no `latest` tag,
  resources set, probes, non-root). A policy that allows only some
  registries needs `ghcr.io/franzramadhan/*` added, or the sidecar image
  mirrored and set with `--sidecar-image`. A native sidecar is in
  `spec.initContainers`; custom policies that walk only
  `spec.containers` miss it, which is harmless for the sidecar but worth
  knowing.
- `iptables` mode fails the `Capabilities` control of the `baseline`
  profile. It needs a `PolicyException`, scoped to the init container's
  image, field and values:

  ```yaml
  apiVersion: kyverno.io/v2
  kind: PolicyException
  metadata: { name: dvarapala-init, namespace: kyverno-exceptions }
  spec:
    exceptions:
      - policyName: <pod security policy>
        ruleNames: [<baseline or restricted rule>]
    match:
      any:
        - resources: { kinds: [Pod], namespaces: [<opted-in namespaces>] }
    podSecurity:
      - controlName: Capabilities
        images: ["ghcr.io/franzramadhan/dvarapala-operator*"]
        restrictedField: spec.initContainers[*].securityContext.capabilities.add
        values: [NET_ADMIN, NET_RAW]
  ```

  Prerequisites: Kyverno started with `enablePolicyException=true` and
  the exception's namespace in `exceptionNamespace` (exceptions are off
  by default). `kyverno.io/v2` exceptions are deprecated from Kyverno
  1.19; on CEL `ValidatingPolicy` (1.14 and later) the equivalent is a
  `policies.kyverno.io` `PolicyException` with `images`, which the policy
  reads as `exceptions.allowedImages`. The example ships both.
- The built-in Pod Security Admission has no per-container exception: a
  namespace enforcing `baseline` or `restricted` through PSA cannot run
  `iptables` mode at all.

**Tetragon**

- `TracingPolicy` and `TracingPolicyNamespaced` select pods by
  `podSelector`, then containers by `containerSelector` (fields `name`
  and `repo`). An enforcement policy written for the application (a
  `Sigkill` on any binary but the application's, a ban on
  `CAP_NET_ADMIN` use, a connect allowlist) also hits the sidecar
  process `/dvarapala` and, in `iptables` mode, `iptables` in the init
  container. Exclude them by container name:

  ```yaml
  containerSelector:
    matchExpressions:
      - key: name
        operator: NotIn
        values: [dvarapala, dvarapala-egress, dvarapala-init]
  ```

  or, for a binary allowlist, add `/dvarapala` to the `matchBinaries`
  values. A connect allowlist for the application must also allow the
  sidecar's connection to `127.0.0.1:<app port>`, and the egress
  sidecar's connections to the destinations the application calls.
- Prerequisites: Tetragon's policy filtering on (the agent logs
  `Enabling policy filtering`) for `podSelector` and `containerSelector`
  to apply, and the OCI runtime hooks, without which Tetragon applies
  them best effort from the API server, so a just-started container can
  run briefly before the policy covers it.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/operator/src/crd.rs` | `DvarapalaPolicy` spec and status types, the CRD schema |
| `crates/operator/src/inject.rs` | pure: a pod, its namespace labels and a policy in, a JSON patch or a refusal out. No client, no I/O |
| `crates/operator/src/redirect.rs` | pure: the `port-name` rename and probe rewrite, the `iptables` init container and its rules |
| `crates/operator/src/egress.rs` | pure: the forward sidecar and the proxy environment |
| `crates/operator/src/policy.rs` | pure: TOML parse, the owned-key check, the rendered ConfigMap and its hash |
| `crates/operator/src/webhook.rs` | the HTTPS admission server: `AdmissionReview` in, `inject` out |
| `crates/operator/src/controller.rs` | reconcile a policy: ConfigMap, status, pod and Service counts |
| `crates/operator/src/cert.rs` | the self-signed CA and serving pair, the `caBundle` patch |
| `crates/operator/src/main.rs` | flags, the two loops, leader election for the controller |
| `crates/dvarapala/src/watch.rs` | `config_watch`: poll the config file's hash, trigger the `SIGHUP` reload path |
| `deploy/operator.yaml` | CRD, RBAC, Deployment, PDB, Service, webhook configuration |

New dependencies, operator only (the `dvarapala` binary gains none):
`kube` (`runtime`, `derive`, `admission`, `rustls-tls`), `k8s-openapi`,
`schemars`, `rcgen`. All permissive, checked with `cargo deny check`.

### Configuration

The operator's own flags:

| Flag | Default | |
|---|---|---|
| `--sidecar-image` | `ghcr.io/franzramadhan/dvarapala:<version>` | image of the injected sidecars |
| `--webhook-listen` | `0.0.0.0:9443` | admission server |
| `--metrics-listen` | `0.0.0.0:9090` | operator metrics |

Pod annotations (prefix `dvarapala.franzramadhan.dev/`):

| Annotation | Default | |
|---|---|---|
| `inject` | from the namespace label | `"true"` or `"false"` |
| `policy` | `default` | the `DvarapalaPolicy` in the pod's namespace |
| `port` | the only TCP container port | name or number of the port to protect |
| `redirect` | policy's `spec.redirect`, else `port-name` | `port-name` or `iptables` |
| `egress` | unset | a policy for the forward sidecar; unset is off |
| `config-hash` | set by the webhook | the policy hash the pod started with |

New dvarapala key (in `CONFIG.md`, `examples/dvarapala.toml`):

| Key | Default | |
|---|---|---|
| `config_watch` | `""` | poll interval of the `--config` file, for example `"10s"`; a changed file reloads like `SIGHUP`. Empty is off |

### Logs and metrics

| | |
|---|---|
| `msg="config changed on disk"` | `config_watch` saw a new hash, followed by the RFC 0014 reload lines |
| `dvarapala_operator_admissions_total{result}` | `injected`, `skipped` (opted out), `refused` (no policy, ambiguous port, bad policy) |
| `dvarapala_operator_reconciles_total{result}` | `ok`, `invalid`, `error` |
| `dvarapala_operator_policy_pods{policy,state}` | `injected`, `stale` |
| Kubernetes Events on the pod owner and the policy | refusals and invalid policies, with the reason |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | a pod annotated `inject: "true"`, one port `http` 8080, policy `default` exists | `inject` | a native sidecar on 15080 named `http`, the app port unnamed, `DVARAPALA__UPSTREAM=http://127.0.0.1:8080`, the ConfigMap mounted, `config-hash` set | unit (`inject`) |
| 2 | a pod with a liveness and a readiness probe on port `http` | `inject`, `port-name` | both probes on port 8080 by number | unit (`redirect`) |
| 3 | a pod in an enabled namespace, annotated `inject: "false"` | `inject` | no patch | unit (`inject`) |
| 4 | a pod with ports `http` and `admin`, no `port` annotation | `inject` | refused, the message names `dvarapala.franzramadhan.dev/port` | unit (`inject`) |
| 5 | a pod referencing a policy that does not exist | `inject` | refused, the message names the policy | unit (`inject`) |
| 6 | a pod that already has the sidecar (a re-admitted pod) | `inject` | no second sidecar | unit (`inject`) |
| 7 | `redirect: iptables`, port 8080 | `inject` | an init container before the sidecar with `NET_ADMIN`, `NET_RAW`, and IPv4 and IPv6 `REDIRECT` rules 8080 to 15080 | unit (`redirect`) |
| 8 | `egress: shaping`, one container with `HTTPS_PROXY` already set | `inject` | the forward sidecar on 127.0.0.1:15081; that container keeps its value, the others get the five variables | unit (`egress`) |
| 9 | the injected sidecar container | inspect | non-root, read-only root file system, all capabilities dropped, `allowPrivilegeEscalation: false` | unit (`inject`) |
| 10 | a policy setting `listen`, one setting `[admin]`, one with broken TOML | render | each `Ready=False` naming the key or the parse error; no ConfigMap change | unit (`policy`) |
| 11 | two policies differing only in whitespace and comments | render | the same hash | unit (`policy`) |
| 12 | arbitrary pod JSON and annotation values | `inject` | no panic; a patch or a refusal | fuzz (`inject_pod`) |
| 13 | dvarapala with `config_watch = "100ms"` at `rate = 100` | the file is rewritten with `rate = 1` | within 1 s the second request from a client is `429`; no connection dropped | integration (`dvarapala/tests`) |
| 14 | dvarapala with `config_watch` | the file is rewritten with an invalid route | `config reload failed`, the running config unchanged | integration (`dvarapala/tests`) |
| 15 | dvarapala with `config_watch` | the file is replaced through a symlink swap, as kubelet does | reloaded once | integration (`dvarapala/tests`) |
| 16 | a kind cluster, the operator, a policy at `rate = 1`, an annotated echo Deployment and its Service with `targetPort: http` | two requests through the Service | the second `429`; the echo image and the Service unchanged | e2e (`kind` job) |
| 17 | the same, policy edited to `rate = 100` | requests after the kubelet sync | `200`; the pod not restarted | e2e (`kind` job) |
| 18 | the same, a Service with numeric `targetPort` | reconcile | listed in `bypassingServices` | e2e (`kind` job) |
| 19 | a namespace enforcing the `restricted` Pod Security Standard | an annotated pod in `port-name` mode | admitted and running | e2e (`kind` job) |
| 20 | a kind cluster with Cilium, `kubeProxyReplacement=true`, no kube-proxy | an annotated pod in `iptables` mode, requests through a Service with a numeric `targetPort` and to the pod IP | both reach the sidecar (second request `429` at `rate = 1`) | e2e (`kind` job, Cilium) |
| 21 | Kyverno enforcing the `baseline` pod security policy, the shipped `PolicyException` | an annotated pod in `port-name` mode, then one in `iptables` mode | both admitted; without the exception the second is refused naming `Capabilities` | e2e (`kind` job) |
| 22 | the operator Deployment scaled to zero, `failurePolicy: Fail` | create an opted-in pod, then a pod in another namespace | the first refused, the second created | e2e (`kind` job) |

## Alternatives

| Option | Why not |
|---|---|
| A gateway Deployment per Service (a `DvarapalaGateway` CR) | a hop, its own scaling, and a Service or Ingress change the workload team often does not own. A later RFC if asked for: it reuses the policy and the controller |
| Rewrite the Service `targetPort` instead of the port name | the operator would edit an object the user's GitOps tool owns, and the two would fight |
| `iptables` as the default | needs `NET_ADMIN`, refused by the `baseline` and `restricted` Pod Security Standards that most clusters enforce |
| A CNI plugin for the redirect (as Istio CNI) | a node-level DaemonSet and per-CNI testing for what the port rename does without privileges; reconsider if `iptables` mode gets real use |
| Annotations only, no CRD (the policy in a ConfigMap) | no status, no owned-key check, sidecar settings and secret references spread over many annotations |
| Structured CRD fields mirroring every `CONFIG.md` key | a second schema to keep in step with every RFC; TOML keeps one reference |
| The operator validates the full config with dvarapala's own types | pulls the whole proxy into the operator build; the sidecar already refuses a bad file at start and at reload |
| The operator calls `POST /reload` on each pod | needs the admin API on the pod network, a token per pod and pod-to-pod reachability; `config_watch` needs nothing |
| cert-manager for the webhook certificate | an extra cluster dependency for one serving pair |
| Go and controller-runtime | a second toolchain; `kube` covers the CRD, the controller and admission in the workspace's language |
| Classic sidecar (a regular container) | starts in parallel with the application, so early requests miss the proxy, and Jobs never complete |
| XDP in the sidecar | needs `CAP_BPF` and the node's interface; a node DaemonSet is its own RFC |

## Security and resource limits

- The webhook can change every opted-in pod, so its RBAC is the narrowest
  that works: read pods, namespaces, Services and EndpointSlices; read and
  write ConfigMaps and Events in namespaces with policies; the policy
  status; its own Secret and the one `MutatingWebhookConfiguration` by
  name. It never reads the Secrets that `secretRef` names: they reach the
  sidecar as `envFrom`.
- An attacker who can create pods in an enabled namespace can already run
  any container there; the webhook adds nothing they could not write
  themselves. Policy authors cannot set the owned keys, so a policy cannot
  open an admin listener or attach XDP.
- `iptables` mode gives `NET_ADMIN` to an init container that exits before
  the application starts; the sidecar and the application never get it.
- Admission requests are capped at 3 MiB (the API server's own limit);
  `inject` is pure and covered by a fuzz target.
- Per pod: the sidecar's default requests are 10m CPU and 16 MiB, its
  memory limit 64 MiB (the RFC 0001 idle budget is under 10 MB), all set
  per policy. A policy enabling `[waf]` (RFC 0017) needs a higher limit,
  and the controller warns in the status when it is lower than that
  RFC's measured budget.
- `config_watch` reads one file per interval, at least `1s`.

## Open questions

- **Service mutation for a numeric `targetPort`.** `port-name` mode does
  not cover a Service that targets the application port by number. The
  operator could rewrite that Service's `targetPort` to the sidecar's
  port name, opted in with a Service annotation:
  - In an admission webhook on Service create and update (not a
    controller patch), GitOps tools that diff server side (Flux, Argo CD
    with `ServerSideDiff=true`) see no drift; Argo CD's client-side diff
    needs `ignoreDifferences` on `targetPort`.
  - A named `targetPort` drops every selected pod that lacks the name
    from the EndpointSlices. Flipping the Service while pods without the
    sidecar still serve is a partial or full outage. The webhook would
    refuse the annotation until every selected pod is injected and
    ready, so the order is: annotate and roll out the pods, then
    annotate the Service.
  - Undoing it means removing the annotation before the pods lose the
    sidecar, the same order in reverse.
  - Kyverno policies on Services rarely look at `targetPort`; Tetragon
    does not see Service objects.

  To decide before acceptance: ship it in this RFC, in a follow-up, or
  not at all (numeric `targetPort` users switch to a named port or use
  `iptables` mode).

## Rollout

- **Rollout:** a minor release after acceptance. Nothing changes for
  existing users: the operator is a new image and manifest, and
  `config_watch` is off unless set. Install with
  `kubectl apply -f https://github.com/franzramadhan/dvarapala/releases/download/v<version>/operator.yaml`,
  create a policy, label a namespace or annotate a pod template, roll
  out. The `title` check gains the scope `operator`; `release.yml` builds
  the operator image and attaches `operator.yaml`; a `kind` e2e job runs
  when `crates/operator`, `deploy/` or the sidecar's config path changes,
  once with kube-proxy and once with Cilium replacing it.
  `examples/kubernetes/` holds a policy, an annotated Deployment, and the
  Kyverno and Tetragon exceptions.
- **Off switch:** remove the annotation or the namespace label and roll
  out: new pods come without the sidecar and the Service reaches the
  application port again by its name. Deleting the operator leaves
  running pods as they are; with `failurePolicy: Fail`, delete the
  `MutatingWebhookConfiguration` first so opted-in pods can still be
  created.
