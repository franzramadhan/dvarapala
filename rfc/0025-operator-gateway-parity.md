# 0025: Operator gateways with the console, a WAF sidecar and mounts

| Status | Date | PR | Release |
|---|---|---|---|
| draft | 2026-10-30 | #213 | |

> Operator-made gateways (RFC 0019) gain what hand-written dvarapala
> Deployments use today: the admin listener and console, the WAF agent
> as a sidecar over a Unix socket, read-only ConfigMap and Secret mounts
> (a CA for the store, the WAF rules), extra pod labels, and opt-in per
> route rule. A Deployment written by hand can then be replaced by a
> policy and a label.

## Problem

RFC 0019 builds a gateway from a policy's TOML, but some keys and pod
shapes are out of reach, so a deployment that uses them keeps its
hand-written manifests:

- **No console.** `[admin]` is an operator-owned key, so a gateway has
  no admin listener: no console (RFC 0018), no OIDC login, no manual
  blocks (RFC 0014), no `observe`/`enforce` switch (RFC 0021), no
  `GET /history` (RFC 0022), no `POST /llm` or `GET /llm` (RFC 0023).
  During an attack the manual blocks are the lever RFC 0019 itself
  points to.
- **No WAF agent.** `[waf]` (RFC 0017) needs `coraza-spoa` next to the
  proxy. The gateway pod has one container, so the agent would be a
  separate Deployment reached over TCP, which sends every inspected
  request in clear across the cluster (dvarapala warns at start), adds
  a hop and needs its own scaling.
- **No files.** The pod mounts only the rendered config. A PostgreSQL
  store with `sslmode=verify-full` against a private CA needs
  `store.ca_file`; `waf.rules_files` (the console's WAF page) needs the
  agent's rule files; `ml.llm.export` (RFC 0023) needs a path.
- **No pod labels of one's own.** Scrape jobs, network policies and
  admission rules select pods by label; the gateway pods carry only the
  operator's labels.
- **A route opts in whole.** A labeled `HTTPRoute` has every backend of
  every rule rewritten. A route that sends only `/api/` and `/login`
  through protection, and its static assets straight to the
  application, has to be split into two routes first.

## Proposal

All new fields are optional; a policy without them renders the same
gateway as today.

- **Admin listener: `spec.gateway.admin`.**
  ```yaml
  spec:
    secretRef: { name: shop-dvarapala }   # DVARAPALA__ADMIN__TOKEN, ...
    gateway:
      admin: { enabled: true }
  ```
  The operator sets `DVARAPALA__ADMIN__LISTEN=0.0.0.0:9091`, adds the
  container port `admin` and creates one Service per gateway, named
  `<backend service>-dvp-admin-<port>` (stable, so an Ingress or a
  Tailscale proxy written by hand can point at it), with
  `sessionAffinity: ClientIP`: console sessions, manual blocks and the
  mode switch live in one pod, as they do behind a hand-written
  Deployment. The policy's TOML may now set every `[admin]` key except
  `listen` (owned: `admin.listen` replaces `admin` in the list), so
  `ui_enabled`, `public_url`, `[admin.oidc]` and `mode_switch` come from
  the policy. The token stays in the `secretRef` Secret; a policy with
  `admin.enabled` and no `secretRef` is `Ready=False`. The admin Service
  names are in the policy status (`gateways[].adminService`).
- **WAF sidecar: `spec.gateway.waf`.**
  ```yaml
  spec:
    config: |
      [waf]
      enabled = true
      mode = "observe"
    gateway:
      waf:
        image: ghcr.io/corazawaf/coraza-spoa:<version>@sha256:<digest>
        configMap: shop-coraza      # key config.yaml, the agent's config
        resources: { limits: { memory: 256Mi } }
  ```
  The operator adds a container `waf` with that image, the ConfigMap
  mounted read-only at `/etc/coraza-spoa`, and an `emptyDir` at
  `/run/waf` shared with the proxy. It sets
  `DVARAPALA__WAF__ENDPOINT=unix:/run/waf/waf.sock` (`waf.endpoint`
  becomes an owned key while `gateway.waf` is set) and mounts the same
  ConfigMap into the proxy at `/etc/dvarapala/waf/`, so
  `waf.rules_files` can name it for the console. The agent's config must
  bind that socket; `examples/kubernetes/` ships one that does. The
  sidecar runs under the same `restricted` Pod Security settings as the
  proxy (non-root, read-only root, no capabilities). The image must
  match a prefix in the operator's `--waf-images` flag (default
  `ghcr.io/corazawaf/coraza-spoa`); anything else is `Ready=False`.
  `gateway.waf` without `[waf] enabled = true` in the config is a
  warning in the status (an idle sidecar).
- **Mounts: `spec.gateway.mounts`.**
  ```yaml
  gateway:
    mounts:
      - { name: pg-ca, configMap: lab-root-ca }
      - { name: llm-key, secret: shop-llm }
  ```
  Each is a ConfigMap or a Secret of the policy's namespace, mounted
  read-only at `/etc/dvarapala/mounts/<name>/` in the proxy container;
  the config then points at it (`store.ca_file =
  "/etc/dvarapala/mounts/pg-ca/ca.crt"`). `name` is a DNS label, unique
  in the list, at most 16 entries. The operator only names the object in
  the pod spec, as it does for `secretRef`; it never reads it. Writable
  volumes are out of scope (RFC 0024 replaces the export file with the
  PostgreSQL store).
- **Pod labels and annotations: `spec.gateway.podLabels`,
  `spec.gateway.podAnnotations`.** Added to the gateway pod template.
  The operator's own keys (`app.kubernetes.io/name`,
  `app.kubernetes.io/managed-by`, the gateway key) cannot be set; trying
  is `Ready=False` naming the key.
- **Opt in per rule.** The annotation
  `dvarapala.franzramadhan.dev/rules` on a labeled route limits the
  rewrite to some rules: rule `name`s for `HTTPRoute` and `GRPCRoute`
  (a field since Gateway API v1.2), path values for an `Ingress`
  (`/api/,/login`). Other rules keep their backends. A listed name or
  path that the route does not have is reported in the policy status
  and changes nothing. Without the annotation the whole route opts in,
  as today. Changing the annotation goes through the webhook like a
  label change: newly listed rules are rewritten, unlisted ones
  restored.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/operator/src/crd.rs` | `GatewaySpec` fields `admin`, `waf`, `mounts`, `podLabels`, `podAnnotations`; `GatewayStatus.adminService` |
| `crates/operator/src/policy.rs` | Owned keys: `admin.listen` instead of `admin`; `waf.endpoint` when `gateway.waf` is set; the new `Ready=False` reasons |
| `crates/operator/src/gateway.rs` | The pod spec: admin port and env, mounts, labels and annotations |
| `crates/operator/src/gateway/waf.rs` | Pure: the sidecar container, the shared socket volume, the image prefix check |
| `crates/operator/src/gateway/admin.rs` | Pure: the admin Service (name, affinity, selector) |
| `crates/operator/src/routes.rs` | The `rules` annotation: which rules and paths to rewrite or restore |
| `crates/operator/src/controller.rs` | Create, update and delete the admin Services with their gateways |
| `deploy/operator.yaml` | CRD schema for the new fields; the `--waf-images` flag |
| `examples/kubernetes/` | A policy with the console, the WAF sidecar and a CA mount; the agent config bound to `/run/waf/waf.sock`; network policies for the admin port |

### Configuration

The policy fields above, and one operator flag:

| Key | Default | |
|---|---|---|
| `--waf-images` | `ghcr.io/corazawaf/coraza-spoa` | Comma-separated image prefixes a policy's `gateway.waf.image` must start with. Empty refuses every WAF sidecar |

No `CONFIG.md` key changes: the gateways read the same keys, set by the
operator as environment variables.

### Logs and metrics

| | |
|---|---|
| `msg="policy refused" reason=...` | Existing; new reasons: `admin needs secretRef`, `waf image not allowed`, `reserved pod label`, `mount name` |
| `dvarapala_operator_gateways{admin,waf}` | Gateways by whether they run the admin listener and the WAF sidecar |
| `dvarapala_operator_admissions_total{kind,result}` | Existing; `result="partial"` for a route rewritten per rule |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | A policy without the new fields | render | The same Deployment and Services as before this RFC (golden) | unit (`gateway`) |
| 2 | `gateway.admin.enabled` and a `secretRef` | render | `DVARAPALA__ADMIN__LISTEN=0.0.0.0:9091`, port `admin`, a Service `<svc>-dvp-admin-<port>` with `ClientIP` affinity | unit (`gateway`) |
| 3 | `gateway.admin.enabled`, no `secretRef` | render | `Ready=False`, `admin needs secretRef` | unit (`policy`) |
| 4 | Config with `[admin] ui_enabled = true` | render | Accepted; with `[admin] listen = ...` refused naming `admin.listen` | unit (`policy`) |
| 5 | `gateway.waf` with an allowed image | render | A `waf` container, `/run/waf` shared, `DVARAPALA__WAF__ENDPOINT=unix:/run/waf/waf.sock`, restricted security context on both containers | unit (`gateway`) |
| 6 | `gateway.waf` with `docker.io/evil/agent` | render | `Ready=False`, `waf image not allowed` | unit (`policy`) |
| 7 | `gateway.waf` set and config with `waf.endpoint` | render | Refused naming `waf.endpoint` | unit (`policy`) |
| 8 | Two mounts, a ConfigMap and a Secret | render | Read-only volumes at `/etc/dvarapala/mounts/<name>/` in the proxy only | unit (`gateway`) |
| 9 | A mount named `../x`, two with the same name, 17 mounts | render | `Ready=False` naming the problem | unit (`policy`) |
| 10 | `podLabels` with `app.kubernetes.io/name` | render | `Ready=False`, `reserved pod label` | unit (`policy`) |
| 11 | An `HTTPRoute` with rules `api`, `assets` and `rules: api` | webhook | Only `api`'s backends rewritten; `result="partial"` | unit (`routes`) |
| 12 | The same route, annotation removed | webhook | `assets` rewritten too | unit (`routes`) |
| 13 | An `Ingress` with paths `/api/`, `/` and `rules: /api/` | webhook | Only the `/api/` path rewritten | unit (`routes`) |
| 14 | `rules: missing` | webhook | Nothing rewritten, the name in the policy status | unit (`routes`) |
| 15 | Arbitrary route JSON with a `rules` annotation | fuzz | No panic | fuzz (`routes`) |
| 16 | A kind cluster: a policy with the console and the WAF sidecar, a labeled route | apply | `GET /status` through the admin Service answers; a request with `<script>` logs a `waf match` | e2e (`operator-e2e`) |
| 17 | The same cluster, the policy's `[waf] mode` changed | apply | The gateway reloads (`config_watch`) without a restart; the admin Service keeps its endpoints | e2e (`operator-e2e`) |

## Alternatives

| Option | Why not |
|---|---|
| Generic `sidecars: [Container]` and `volumes: [Volume]` in the policy | Lets anyone who can write a policy run any image and mount any volume (host paths included) in a pod the operator creates, which may be more than their own RBAC allows. Typed fields plus an image allowlist keep the operator's reach as narrow as RFC 0019 made it |
| The WAF agent as its own Deployment over TCP | Requests in clear across the cluster, an extra hop, and a second thing to scale; the Unix socket in one pod is how RFC 0017 runs it |
| One admin Service per policy, routing to every gateway | Each gateway is a separate dvarapala with its own state; a console that lands on a different backend's gateway per request shows mixed data |
| Admin Service names with the gateway hash | Stable names let a hand-written Ingress or Tailscale proxy point at them; the hash changes with nothing the user controls |
| Let the operator create the Ingress for the console too | Exposure (tailnet, internal ingress, port-forward only) and its auth differ per cluster; the Service is the boundary |
| Network policies created by the operator | The egress a gateway needs (the store, the LLM endpoint, OIDC issuers) is in the TOML, not in anything the operator can resolve to selectors. Examples instead; later if a pattern settles |
| Split routes instead of the `rules` annotation | Works today, but it doubles the routes to keep in step, and a GitOps change to one rule then touches two objects |

## Security and resource limits

- The admin listener exposes the admin API to whatever reaches its
  Service. It keeps its own auth (token, session, OIDC; RFC 0018 and
  0020) and the policy cannot turn that off: the token is required. The
  operator creates no route to it; exposure is a manual step.
- `gateway.waf.image` is attacker-adjacent: a namespace user writes it.
  The `--waf-images` allowlist bounds it; images should be pinned by
  digest (the examples do), and the operator warns in the status when
  one is not.
- Mounts reference only same-namespace ConfigMaps and Secrets, read-only,
  under a fixed prefix; the operator does not read them, so its RBAC
  does not grow (no `get secrets`). Kubelet enforces that the pod's
  namespace owns them.
- The `rules` annotation is parsed from route JSON in admission: capped
  by the 3 MiB admission limit, at most 64 entries, each at most 253
  characters, and fuzzed with `routes`.
- Resources: the sidecar has its own `resources` (defaults to be
  measured on the e2e cluster with the CRS at paranoia 1, then written
  here before acceptance); the
  proxy's limit warning for `[waf]` from RFC 0019 now counts the proxy
  alone. The admin listener costs the console's footprint (RFC 0018
  budget).

## Rollout

- **Rollout:** a minor release of the operator image and
  `deploy/operator.yaml` (the CRD gains optional fields; existing
  policies render unchanged, test 1). Migrating a hand-written gateway:
  create the policy, then label the route; the webhook's passthrough
  phase (RFC 0019) keeps traffic flowing until the gateway is ready;
  then delete the hand-written Deployment and Service.
- **Off switch:** remove the fields from the policy; the gateways roll
  back to the RFC 0019 shape. The `rules` annotation removed means the
  whole route opts in again; the route label removed restores every
  backend.
