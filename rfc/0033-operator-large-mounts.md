# 0033: Operator gateway mounts from a PVC or an image volume

| Status | Date | PR | Release |
|---|---|---|---|
| accepted | 2026-11-02 | #297 | |

> `gateway.mounts` gains two read-only sources next to ConfigMaps and
> Secrets: an existing PersistentVolumeClaim and an OCI image volume. They
> carry files over the 1 MiB ConfigMap limit, such as GeoIP databases
> (RFC 0031) and large reputation lists, into operator gateways.

## Problem

Operator gateways (RFC 0019, 0025) mount files only from ConfigMaps and
Secrets of the policy's namespace. Both are capped at 1 MiB by the API
server (etcd's object size), which rules out:

- GeoIP databases for `intel.geoip`: GeoLite2-Country and GeoLite2-ASN
  are several MiB each, a City file tens of MiB. Operator gateways cannot
  use `routes[].country` or `asn` today, though the image has `geoip`.
- `path` feeds over 1 MiB (FireHOL level 2 and 3, a provider's full
  abuse list); only `url` feeds work, and each replica fetches them.
- `[ml]` models over 1 MiB (RFC 0029 allows 16 MiB).

A hand-written gateway can mount any volume. The operator should allow
the common read-only ones without becoming a general pod template.

## Proposal

- `gateway.mounts[]` takes exactly one of `configMap`, `secret` (as
  today), `persistentVolumeClaim` or `image`. Every mount stays
  read-only at `/etc/dvarapala-mounts/<name>/`, and the 16-mount limit
  stays.
- `persistentVolumeClaim: {claimName: <pvc>}`: an existing claim in the
  policy's namespace, mounted `readOnly`. The operator never creates,
  resizes or deletes it. Something else fills it, for example a
  `geoipupdate` CronJob (`examples/`). Files change in place, so
  `config_watch` (on for operator gateways) picks up new bytes with no
  rollout: the GeoIP database and the `ml.model` swap by hash, and
  `path` feeds reread.
- `image: {reference: <ref>, pullPolicy: <p>}`: a Kubernetes image
  volume (`volumes[].image`), an OCI image or artifact whose files are
  mounted read-only. The reference must start with a prefix in a new
  operator flag `--mount-images` (empty by default: image mounts are
  refused until the cluster admin allows a registry), as `--waf-images`
  does for the WAF sidecar. A reference without a digest is a warning in
  `status.warnings`. Image volumes need a cluster with the `ImageVolume`
  feature; the operator does not detect it, so a pod that cannot start
  shows the kubelet's event, and the RFC's docs say which versions have
  it on by default.
- A new image reference changes the pod template, so the gateway rolls
  as for any template change; a PVC's content never rolls pods.
- The policy is refused (`Ready=False`) for: more than one source in a
  mount, a claim or image name that is not a valid Kubernetes name, an
  image outside `--mount-images`.
- Nothing about GeoIP or feeds is built into the operator: which file
  goes where is the user's config (`intel.geoip =
  "/etc/dvarapala-mounts/geoip/GeoLite2-Country.mmdb"`). Generic first.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/operator/src/crd.rs` | `Mount` gains `persistent_volume_claim` and `image`; the CRD schema regenerates |
| `crates/operator/src/gateway.rs` | renders the volume and its read-only mount for each source |
| `crates/operator/src/policy.rs` | validation: one source, names, `--mount-images` prefixes, the digest warning |
| `crates/operator/src/app.rs` | the `--mount-images` flag |
| `deploy/operator.yaml` | the CRD and the flag in the operator Deployment (empty) |
| `deploy/e2e/` | a PVC mount on `kind` holding a test GeoIP database, a route on `country` |
| `examples/kubernetes-geoip.yaml` | a PVC, a `geoipupdate` CronJob with a license Secret placeholder, and a policy using both GeoLite2 files |
| `site/docs/kubernetes.md`, `site/docs/protection.md` | the new sources; the GeoIP section drops "operator gateways cannot mount it yet" |

### Configuration

Policy CRD:

| Field | Default | |
|---|---|---|
| `gateway.mounts[].persistentVolumeClaim.claimName` | unset | An existing claim in the namespace, mounted read-only |
| `gateway.mounts[].image.reference` | unset | An OCI image or artifact, under a `--mount-images` prefix |
| `gateway.mounts[].image.pullPolicy` | `IfNotPresent` | `Always`, `IfNotPresent` or `Never` |

Operator flag:

| Flag | Default | |
|---|---|---|
| `--mount-images` | empty | Comma-separated reference prefixes allowed in image mounts; empty refuses them |

No dvarapala config key changes.

### Logs and metrics

| | |
|---|---|
| `status.conditions[Ready]` reason `InvalidMount` | a refused mount, with the field and the reason |
| `status.warnings` | an image mount without a digest |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | a mount `{name: geoip, persistentVolumeClaim: {claimName: geo}}` | the gateway renders | a volume with claim `geo`, `readOnly: true`, mounted read-only at `/etc/dvarapala-mounts/geoip/` | unit (golden) |
| 2 | a mount with `image.reference` under a `--mount-images` prefix, with a digest | the gateway renders | an image volume with that reference and pull policy, mounted read-only; no warning | unit (golden) |
| 3 | the same without a digest | the policy reconciles | ready, with a warning naming the mount | unit |
| 4 | an image outside `--mount-images`, or `--mount-images` empty | the policy reconciles | `Ready=False`, `InvalidMount`, no gateway change | unit |
| 5 | a mount with both `configMap` and `persistentVolumeClaim`, or none | the policy reconciles | `Ready=False`, `InvalidMount` | unit |
| 6 | 17 mounts of mixed sources | the policy reconciles | refused, as today | unit |
| 7 | a policy with an existing ConfigMap mount | the operator upgrades | the rendered gateway is byte-identical (no rollout) | unit (golden) |
| 8 | a PVC mount | the policy changes only `claimName` content (files in the claim) | the pod template hash is unchanged | unit |
| 9 | an image mount | its reference changes | the pod template changes (rollout) | unit |
| 10 | `kind`, a PVC holding a generated test GeoIP database, a policy with `intel.geoip` on it and a `country` route | a request from the database's test range | the route applies through the operator gateway | e2e (`operator-e2e`) |
| 11 | the same | the file in the claim is replaced by one mapping another country | after `config_watch`, the route follows the new file without a pod restart | e2e |
| 12 | `examples/kubernetes-geoip.yaml` | the e2e manifest check | parses and validates against the CRD | integration |

The test database is generated in the test from RFC 5737 ranges and a
private ASN; no third-party database is checked in.

## Alternatives

| Option | Why not |
|---|---|
| A `geoipupdate` sidecar built into the gateway | GeoIP specific in a generic operator; needs a license key and egress from every gateway pod. A CronJob into a PVC does the same once per cluster |
| Split a database over several ConfigMaps | brittle, and the reader needs one file |
| An init container that downloads at start | every pod start hits the network; no update without a restart |
| `emptyDir` plus an arbitrary sidecar | becomes a general pod template; the user can already write a Deployment for that |
| Any volume type (`volumes` passthrough) | hostPath and others need a security review per type; the two read-only sources cover the files a gateway reads |

## Security and resource limits

- Every new mount is read-only; the gateway's security context
  (non-root, read-only root filesystem) does not change.
- A PVC can only be one in the policy's own namespace, as ConfigMaps and
  Secrets: a policy author cannot read another namespace's claim.
- Image mounts pull code-free data, but an image is still remote
  content: `--mount-images` keeps them off until the cluster admin names
  trusted registries, and a missing digest is surfaced.
- dvarapala reads the files with its existing caps (`intel.max_bytes`
  for feeds, 16 MiB for a model; a GeoIP file is read whole, so a City
  database costs its size in RSS per gateway pod). The docs state that
  cost.
- A PVC shared by replicas on several nodes needs `ReadOnlyMany` or
  `ReadWriteMany`; the docs say so, the operator does not check.

## Rollout

- **Rollout:** a minor release. The CRD gains optional fields only;
  existing policies render the same gateways (case 7). `--mount-images`
  is empty by default, so image mounts stay refused until enabled.
- **Off switch:** remove the mount from the policy; the gateway rolls
  back to ConfigMap and Secret mounts only.

## Implementation notes

- The policy status has no conditions: a refused mount shows as
  `ready: false` with a `message` that starts with `mount name "<name>":`
  and names the field, as the RFC 0025 mount errors do, in place of a
  `Ready` condition with reason `InvalidMount`.
- Also refused: a `claimName` that is not a DNS subdomain, an empty image
  reference or one with blanks, and a `pullPolicy` other than `Always`,
  `IfNotPresent` or `Never`.
- The validation moved to `crates/operator/src/policy/mounts.rs` (the
  file-size limit); `policy::check` takes the `--mount-images` prefixes
  as a third argument.
- Case 7 compares the rendered ConfigMap volume and mount with the JSON
  the RFC 0025 code wrote, next to the unchanged gateway golden file,
  rather than a second golden file.
- Image mounts are unit-tested only (cases 2 to 4, 9). The `kind` node
  image in CI does not turn the `ImageVolume` gate on, so the e2e covers
  the PVC (cases 10 to 12).
- The e2e database comes from `deploy/e2e/geoip-db.py`, a Python port of
  the l7 `test_db` writer: `192.0.2.0/24` maps to the user-assigned
  country codes `XA`, then `XB`, and ASN 64512. Case 12 is a server-side
  dry run of the example with strict field validation.
