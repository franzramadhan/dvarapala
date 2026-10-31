#!/usr/bin/env bash
# What CI prints when run.sh fails: the objects, the operator's, the
# gateways' and ingress-nginx's logs (its access log shows which upstream
# answered a stray 503).
c=kind-dvarapala-e2e-${1:-default}
kubectl --context "$c" get all,dvarapalapolicy,httproute,ingress,endpointslice -A -o wide
kubectl --context "$c" -n shop get dvarapalapolicy,svc,httproute,ingress -o yaml
kubectl --context "$c" -n dvarapala logs -l app.kubernetes.io/name=dvarapala-operator --tail=300 --prefix
kubectl --context "$c" -n shop logs -l app.kubernetes.io/name=dvarapala-gateway --tail=100 --prefix
kubectl --context "$c" -n ingress-nginx logs -l app.kubernetes.io/component=controller --tail=300 --prefix
