#!/usr/bin/env bash
# RFC 0019 cases 15 to 21 on a kind cluster. Needs kind, kubectl, helm and
# the images dvarapala:e2e and dvarapala-operator:e2e in the local Docker
# (ci.yml job operator-e2e builds them).
#   deploy/e2e/run.sh default   # Envoy Gateway and ingress-nginx: 15 to 20
#   deploy/e2e/run.sh cilium    # Cilium, kubeProxyReplacement: 21
set -euo pipefail

flavor=${1:-default}
cluster=dvarapala-e2e-$flavor
here=$(cd "$(dirname "$0")" && pwd)
envoy_gateway=v1.9.3
ingress_nginx=controller-v1.15.1
cilium=1.20.4

# helm without the caller's repositories
HELM_REPOSITORY_CONFIG=$(mktemp -d)/repositories.yaml
HELM_REPOSITORY_CACHE=$(dirname "$HELM_REPOSITORY_CONFIG")/cache
export HELM_REPOSITORY_CONFIG HELM_REPOSITORY_CACHE

fail() { echo "FAIL: $*" >&2; exit 1; }
k() { kubectl --context "kind-$cluster" "$@"; }

up() {
  if [ "$flavor" = cilium ]; then
    kind create cluster --name "$cluster" --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  kubeProxyMode: none
EOF
    helm --kube-context "kind-$cluster" install cilium cilium --repo https://helm.cilium.io \
      --version "$cilium" --namespace kube-system \
      --set kubeProxyReplacement=true \
      --set k8sServiceHost="$cluster-control-plane" --set k8sServicePort=6443 \
      --set ipam.mode=kubernetes --set operator.replicas=1 --wait --timeout 10m
  else
    kind create cluster --name "$cluster"
  fi
  kind load docker-image --name "$cluster" dvarapala:e2e dvarapala-operator:e2e
  helm --kube-context "kind-$cluster" install eg oci://docker.io/envoyproxy/gateway-helm \
    --version "$envoy_gateway" -n envoy-gateway-system --create-namespace --wait --timeout 10m
  if [ "$flavor" = default ]; then
    k apply -f "https://raw.githubusercontent.com/kubernetes/ingress-nginx/$ingress_nginx/deploy/static/provider/kind/deploy.yaml"
    k -n ingress-nginx rollout status deploy/ingress-nginx-controller --timeout=180s
  fi
  sed -e 's#ghcr.io/franzramadhan/dvarapala-operator:__VERSION__#dvarapala-operator:e2e#' \
      -e 's#ghcr.io/franzramadhan/dvarapala:__VERSION__#dvarapala:e2e#' \
      "$here/../operator.yaml" | k apply --server-side -f -
  k -n dvarapala rollout status deploy/dvarapala-operator --timeout=120s
  k apply --server-side -f "$here/app.yaml" -f "$here/gateway.yaml"
  [ "$flavor" = default ] && k apply --server-side -f "$here/ingress.yaml"
  k -n shop rollout status deploy/echo --timeout=120s
  k -n shop wait pod/curl --for=condition=Ready --timeout=120s
  # kind has no load balancer, so the Gateway is never Programmed: wait for
  # its proxy instead
  for _ in $(seq 60); do
    k -n envoy-gateway-system get pods -l gateway.envoyproxy.io/owning-gateway-name=eg -o name | grep -q . && break
    sleep 3
  done
  k -n envoy-gateway-system wait pod -l gateway.envoyproxy.io/owning-gateway-name=eg --for=condition=Ready --timeout=180s
}

# The status code of one request through `$1` (an in-cluster URL).
code() {
  k -n shop exec curl -- curl -s -o /dev/null -w '%{http_code}' -m 5 -H 'Host: echo.example' "$1" || true
}

# Requests through `$1` every 100ms into `$2` until `stop`. Killing the
# exec would leave the loop running in the pod.
load() {
  k -n shop exec curl -- rm -f /tmp/stop
  k -n shop exec curl -- sh -c "while [ ! -f /tmp/stop ]; do curl -s -o /dev/null -w '%{http_code}\n' -m 5 -H 'Host: echo.example' '$1'; sleep 0.1; done" >"$2" 2>/dev/null
}

# An HTTPRoute `$1` to echo:80 as in gateway.yaml, labeled with policy `$2`
# unless empty.
route() {
  cat <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: $1
  namespace: shop
  labels: {${2:+dvarapala.franzramadhan.dev/policy: $2}}
spec:
  parentRefs: [{name: eg}]
  hostnames: [echo.example]
  rules:
    - backendRefs: [{name: echo, port: 80}]
EOF
}

phase() {
  k -n shop get dvarapalapolicy default -o jsonpath="{.status.gateways[?(@.backend==\"echo\")].phase}"
}

# Cases 15 and 16 (21 on Cilium): label the route `$1/$2` under load
# through `$3`. No request fails, then the second request per client is 429.
protect() {
  local kind=$1 name=$2 url=$3 log
  log=$(mktemp)
  # the proxy serves the route before the switch starts
  for _ in $(seq 60); do [ "$(code "$url")" = 200 ] && break; sleep 2; done
  [ "$(code "$url")" = 200 ] || fail "$kind: no 200 before labeling"
  load "$url" "$log" &
  local loader=$!
  sleep 3
  k -n shop label "$kind" "$name" dvarapala.franzramadhan.dev/policy=default
  for _ in $(seq 60); do [ "$(phase)" = Protecting ] && break; sleep 2; done
  [ "$(phase)" = Protecting ] || fail "$kind: gateway not Protecting: $(k -n shop get dvarapalapolicy default -o yaml)"
  # the proxy picks up the gateway pods' endpoints
  sleep 10
  k -n shop exec curl -- touch /tmp/stop
  wait "$loader" 2>/dev/null || true
  local bad
  bad=$(grep -cvE '^(200|429)$' "$log" || true)
  [ "$bad" = 0 ] || fail "$kind: $bad requests failed during the switch: $(sort "$log" | uniq -c)"
  grep -q '^429$' "$log" || fail "$kind: no 429 after Protecting: $(sort "$log" | uniq -c)"
  sleep 2
  local first second
  first=$(code "$url"); second=$(code "$url")
  [ "$first $second" = "200 429" ] || fail "$kind: got $first $second, want 200 429"
  [ "$(k -n shop get svc echo -o jsonpath='{.spec.selector.app}')" = echo ] || fail "echo Service changed"
  echo "ok: $kind protected"
}

# Case 17: a reloadable change reaches the pods without a restart.
reload() {
  local url=$1 before after
  before=$(k -n shop get pods -l app.kubernetes.io/name=dvarapala-gateway -o jsonpath='{.items[*].metadata.uid}')
  k -n shop patch dvarapalapolicy default --type merge \
    -p '{"spec":{"config":"trusted_proxies = [\"10.0.0.0/8\"]\n[rate_limit]\nrate = 100\nburst = 100\n"}}'
  local ok=
  # the kubelet syncs a ConfigMap volume within about a minute, the gateway
  # rereads it every 10s
  for _ in $(seq 60); do
    if [ "$(code "$url") $(code "$url") $(code "$url")" = "200 200 200" ]; then ok=1; break; fi
    sleep 3
  done
  [ -n "$ok" ] || fail "rate 100 not applied"
  after=$(k -n shop get pods -l app.kubernetes.io/name=dvarapala-gateway -o jsonpath='{.items[*].metadata.uid}')
  [ "$before" = "$after" ] || fail "gateway pods restarted: $before / $after"
  echo "ok: reload without restart"
}

# Case 19: a server-side dry run of the original manifest leaves the
# backends as stored.
dry_run() {
  local live dry
  live=$(k -n shop get httproute echo -o jsonpath='{.spec.rules[0].backendRefs[0].name}')
  dry=$(route echo default | k apply --server-side --dry-run=server -f - \
    -o jsonpath='{.spec.rules[0].backendRefs[0].name}')
  [ "$live" = "$dry" ] && [ "$live" != echo ] || fail "dry run backends $dry, live $live"
  echo "ok: dry run has no diff"
}

# Cases 18 and 20, with the operator down so it does not scale back.
operator_down() {
  local url=$1 gw
  k -n dvarapala scale deploy/dvarapala-operator --replicas=0
  k -n dvarapala wait pod -l app.kubernetes.io/name=dvarapala-operator --for=delete --timeout=60s
  gw=$(k -n shop get deploy -l app.kubernetes.io/name=dvarapala-gateway -o name)
  k -n shop scale "$gw" --replicas=0
  k -n shop wait pod -l app.kubernetes.io/name=dvarapala-gateway --for=delete --timeout=60s
  sleep 5
  [ "$(code "$url")" = 503 ] || fail "no gateway pod: want 503"
  [ "$(k -n shop get svc -l app.kubernetes.io/name=dvarapala-gateway -o jsonpath='{.items[0].spec.ports[0].targetPort}')" = 8080 ] \
    || fail "gateway Service went back to passthrough"
  echo "ok: fail closed"
  if k -n shop annotate httproute echo e2e=1 --overwrite 2>/dev/null; then fail "labeled route stored with the webhook down"; fi
  route other "" | k apply --server-side -f - >/dev/null || fail "unlabeled route refused with the webhook down"
  echo "ok: webhook down refuses labeled routes only"
  k -n dvarapala scale deploy/dvarapala-operator --replicas=2
  k -n dvarapala rollout status deploy/dvarapala-operator --timeout=120s
}

# REUSE=1 skips the cluster setup, to rerun the cases
[ -n "${REUSE:-}" ] || up
envoy=$(k -n envoy-gateway-system get svc -l gateway.envoyproxy.io/owning-gateway-name=eg -o jsonpath='{.items[0].metadata.name}')
gateway_url=http://$envoy.envoy-gateway-system.svc/
protect httproute echo "$gateway_url"
if [ "$flavor" = default ]; then
  protect ingress echo http://ingress-nginx-controller.ingress-nginx.svc/
  dry_run
  reload "$gateway_url"
  operator_down "$gateway_url"
fi
echo "PASS: $flavor"
