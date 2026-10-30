//! The controller, one reconcile per namespace: render the policies, run
//! a gateway per labeled backend, point the routes at them, switch each
//! gateway Service from passthrough to protecting once its pods are ready,
//! remove the gateways no route uses, and report in the policy status.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Service};
use k8s_openapi::api::networking::v1::Ingress;
use k8s_openapi::api::policy::v1::PodDisruptionBudget;
use kube::api::{
    Api, ApiResource, DeleteParams, DynamicObject, ListParams, ObjectMeta, Patch, PatchParams,
};
use kube::core::GroupVersionKind;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher;
use kube::{Client, Resource, ResourceExt};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::crd::{DvarapalaPolicy, GatewayStatus, PolicyStatus};
use crate::gateway::{self, Gateway, MANAGED_BY, PHASE, POLICY};
use crate::policy::{self, Rendered};
use crate::routes::{self, Kind, LABEL};

/// The field manager of everything the operator writes.
pub const MANAGER: &str = "dvarapala-operator";
/// How long an unused gateway Service is kept after its creation.
const GRACE_SECS: i64 = 60;

pub struct Ctx {
    pub client: Client,
    pub image: String,
    pub kinds: Vec<(Kind, ApiResource)>,
}

#[derive(Debug)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<kube::Error> for Error {
    fn from(e: kube::Error) -> Self {
        Self(e.to_string())
    }
}

/// The route kinds this cluster serves: `Ingress`, and the Gateway API
/// routes when their CRDs are installed.
pub async fn kinds(client: &Client) -> Vec<(Kind, ApiResource)> {
    let mut out = vec![(Kind::Ingress, ApiResource::erase::<Ingress>(&()))];
    for (kind, name) in [
        (Kind::HttpRoute, "HTTPRoute"),
        (Kind::GrpcRoute, "GRPCRoute"),
    ] {
        let gvk = GroupVersionKind::gvk("gateway.networking.k8s.io", "v1", name);
        match kube::discovery::pinned_kind(client, &gvk).await {
            Ok((ar, _)) => out.push((kind, ar)),
            Err(e) => tracing::info!(kind = name, error = %e, "route kind not served, skipped"),
        }
    }
    out
}

pub async fn run(ctx: Arc<Ctx>) {
    let c = &ctx.client;
    let wc = watcher::Config::default;
    let managed = format!("{}={}", MANAGED_BY.0, MANAGED_BY.1);
    let mut controller = Controller::new(Api::<Namespace>::all(c.clone()), wc())
        .watches(Api::<DvarapalaPolicy>::all(c.clone()), wc(), ns_of)
        .watches(
            Api::<Deployment>::all(c.clone()),
            wc().labels(&managed),
            ns_of,
        );
    for (_, ar) in &ctx.kinds {
        controller = controller.watches_with(
            Api::<DynamicObject>::all_with(c.clone(), ar),
            ar.clone(),
            wc(),
            ns_of,
        );
    }
    controller
        .run(
            reconcile,
            |_, e, _| {
                tracing::warn!(error = %e, "reconcile failed");
                Action::requeue(Duration::from_secs(10))
            },
            ctx,
        )
        .for_each(|_| async {})
        .await;
}

fn ns_of<K: Resource>(o: K) -> Option<ObjectRef<Namespace>> {
    o.meta().namespace.as_deref().map(ObjectRef::new)
}

async fn apply<K>(api: &Api<K>, name: &str, obj: &K) -> Result<K, Error>
where
    K: Resource + Clone + Serialize + DeserializeOwned + std::fmt::Debug,
{
    Ok(api
        .patch(
            name,
            &PatchParams::apply(MANAGER).force(),
            &Patch::Apply(obj),
        )
        .await?)
}

async fn delete<K>(api: &Api<K>, name: &str) -> Result<(), Error>
where
    K: Resource + Clone + DeserializeOwned + std::fmt::Debug,
{
    match api.delete(name, &DeleteParams::default()).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
        Err(e) => Err(e.into()),
    }
}

struct Plan {
    /// policy name to its rendering, or why it is invalid
    policies: BTreeMap<String, (DvarapalaPolicy, Result<Rendered, String>)>,
    gateways: BTreeMap<String, Gateway>,
    skipped: BTreeMap<String, Vec<String>>,
    routes: BTreeMap<String, i32>,
}

async fn reconcile(ns: Arc<Namespace>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let name = ns.name_any();
    let c = &ctx.client;
    let lp = ListParams::default();
    let managed = ListParams::default().labels(&format!("{}={}", MANAGED_BY.0, MANAGED_BY.1));
    let ns_policy = ns.labels().get(LABEL).cloned();
    let policies = Api::<DvarapalaPolicy>::namespaced(c.clone(), &name)
        .list(&lp)
        .await?
        .items;
    let services_api = Api::<Service>::namespaced(c.clone(), &name);
    let existing: BTreeMap<String, Service> = services_api
        .list(&managed)
        .await?
        .items
        .into_iter()
        .map(|s| (s.name_any(), s))
        .collect();
    if policies.is_empty() && existing.is_empty() && ns_policy.is_none() {
        return Ok(Action::await_change());
    }
    let services: BTreeMap<String, Service> = services_api
        .list(&lp)
        .await?
        .items
        .into_iter()
        .map(|s| (s.name_any(), s))
        .collect();
    let mut routes_found = Vec::new();
    for (kind, ar) in &ctx.kinds {
        let api: Api<DynamicObject> = Api::namespaced_with(c.clone(), &name, ar);
        for r in api.list(&lp).await?.items {
            routes_found.push((*kind, api.clone(), r));
        }
    }
    let mut plan = Plan {
        policies: policies
            .into_iter()
            .map(|p| (p.name_any(), (p.clone(), policy::render(&p.spec.config))))
            .collect(),
        gateways: BTreeMap::new(),
        skipped: BTreeMap::new(),
        routes: BTreeMap::new(),
    };
    for (kind, _, r) in &routes_found {
        let Some(p) = routes::policy(
            r.labels().get(LABEL).map(String::as_str),
            ns_policy.as_deref(),
        ) else {
            continue;
        };
        if !plan.policies.contains_key(p) {
            continue;
        }
        *plan.routes.entry(p.into()).or_default() += 1;
        let json = serde_json::to_value(r).map_err(|e| Error(e.to_string()))?;
        for b in routes::backends(*kind, &json, &name) {
            let planned = match services.get(&b.service) {
                None => Err(format!("{}:{}: no such Service", b.service, b.port)),
                Some(s) => gateway::plan(s, &b.port, p, *kind == Kind::GrpcRoute),
            };
            match planned {
                Ok(g) => drop(plan.gateways.insert(g.name.clone(), g)),
                Err(e) => plan.skipped.entry(p.into()).or_default().push(e),
            }
        }
    }
    let ready = gateways(c, &name, &ctx.image, &plan, &services, &existing).await?;
    // routes point at gateways whose Service is there, never at a missing one
    let present: BTreeSet<&String> = plan
        .gateways
        .keys()
        .filter(|g| ready.contains_key(*g) || existing.contains_key(*g))
        .collect();
    for (kind, api, r) in &routes_found {
        let json = serde_json::to_value(r).map_err(|e| Error(e.to_string()))?;
        let p = routes::policy(
            r.labels().get(LABEL).map(String::as_str),
            ns_policy.as_deref(),
        );
        let out = routes::rewrite(*kind, &json, &name, p, &|g| present.contains(&g.to_owned()));
        let diff = json_patch::diff(&json, &out);
        if !diff.0.is_empty() {
            api.patch(
                &r.name_any(),
                &PatchParams::default(),
                &Patch::<()>::Json(diff),
            )
            .await?;
            tracing::info!(namespace = %name, route = %r.name_any(), "route backends updated");
        }
    }
    collect(c, &name, &plan).await?;
    status(c, &name, &plan, &ready).await?;
    let passthrough = ready.values().any(|(protecting, _)| !protecting);
    Ok(Action::requeue(Duration::from_secs(if passthrough {
        3
    } else {
        300
    })))
}

/// Applies the ConfigMaps and every planned gateway of a valid policy.
/// Returns, per gateway, whether it protects and its ready pods.
async fn gateways(
    c: &Client,
    ns: &str,
    image: &str,
    plan: &Plan,
    services: &BTreeMap<String, Service>,
    existing: &BTreeMap<String, Service>,
) -> Result<BTreeMap<String, (bool, i32)>, Error> {
    let cms = Api::<ConfigMap>::namespaced(c.clone(), ns);
    for (p, (_, r)) in &plan.policies {
        // an invalid policy keeps its last good file
        let Ok(r) = r else { continue };
        let name = policy::config_map_name(p);
        let cm = ConfigMap {
            metadata: ObjectMeta {
                name: Some(name.clone()),
                labels: Some(BTreeMap::from([
                    (MANAGED_BY.0.into(), MANAGED_BY.1.into()),
                    (POLICY.into(), p.clone()),
                ])),
                ..ObjectMeta::default()
            },
            data: Some(BTreeMap::from([(policy::FILE.into(), r.toml.clone())])),
            ..ConfigMap::default()
        };
        apply(&cms, &name, &cm).await?;
    }
    let deployments = Api::<Deployment>::namespaced(c.clone(), ns);
    let svcs = Api::<Service>::namespaced(c.clone(), ns);
    let pdbs = Api::<PodDisruptionBudget>::namespaced(c.clone(), ns);
    let hpas = Api::<HorizontalPodAutoscaler>::namespaced(c.clone(), ns);
    let mut out = BTreeMap::new();
    for (name, g) in &plan.gateways {
        let (p, r) = &plan.policies[&g.policy];
        let Ok(r) = r else { continue };
        let backend = &services[&g.backend];
        let d = apply(
            &deployments,
            name,
            &gateway::deployment(g, &p.spec, image, &r.restart_hash),
        )
        .await?;
        let ready = d.status.and_then(|s| s.ready_replicas).unwrap_or(0);
        // never back to passthrough once protecting: no ready pod is a 503
        let was = existing
            .get(name)
            .and_then(|s| s.annotations().get(PHASE))
            .is_some_and(|ph| ph == "protecting");
        let protecting = was || ready > 0;
        if protecting && !was {
            tracing::info!(namespace = %ns, gateway = %name, "gateway protecting");
        }
        apply(&svcs, name, &gateway::service(g, backend, protecting)).await?;
        apply(&pdbs, name, &gateway::pdb(g)).await?;
        match &p.spec.gateway.autoscaling {
            Some(a) => drop(apply(&hpas, name, &gateway::hpa(g, &p.spec, a)).await?),
            None => delete(&hpas, name).await?,
        }
        out.insert(name.clone(), (protecting, ready));
    }
    ::metrics::gauge!("dvarapala_operator_gateways", "namespace" => ns.to_owned(), "phase" => "passthrough")
        .set(out.values().filter(|(p, _)| !p).count() as f64);
    ::metrics::gauge!("dvarapala_operator_gateways", "namespace" => ns.to_owned(), "phase" => "protecting")
        .set(out.values().filter(|(p, _)| *p).count() as f64);
    Ok(out)
}

/// Deletes gateways no route uses and ConfigMaps of removed policies.
async fn collect(c: &Client, ns: &str, plan: &Plan) -> Result<(), Error> {
    let managed = ListParams::default().labels(&format!("{}={}", MANAGED_BY.0, MANAGED_BY.1));
    let deployments = Api::<Deployment>::namespaced(c.clone(), ns);
    let mut names: BTreeSet<String> = deployments
        .list(&managed)
        .await?
        .items
        .iter()
        .map(ResourceExt::name_any)
        .collect();
    let svcs = Api::<Service>::namespaced(c.clone(), ns);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    // the webhook creates a gateway Service just before its route is
    // stored: keep a young one until the route is there to plan it
    let mut young = BTreeSet::new();
    for s in svcs.list(&managed).await?.items {
        let born = s
            .metadata
            .creation_timestamp
            .as_ref()
            .map_or(now, |t| t.0.as_second());
        if now - born < GRACE_SECS {
            young.insert(s.name_any());
        }
        names.insert(s.name_any());
    }
    for n in names
        .iter()
        .filter(|n| !plan.gateways.contains_key(*n) && !young.contains(*n))
    {
        delete(&svcs, n).await?;
        delete(&deployments, n).await?;
        delete(&Api::<PodDisruptionBudget>::namespaced(c.clone(), ns), n).await?;
        delete(
            &Api::<HorizontalPodAutoscaler>::namespaced(c.clone(), ns),
            n,
        )
        .await?;
        tracing::info!(namespace = %ns, gateway = %n, "gateway removed");
    }
    let cms = Api::<ConfigMap>::namespaced(c.clone(), ns);
    for cm in cms.list(&managed).await?.items {
        let keep = cm
            .labels()
            .get(POLICY)
            .is_some_and(|p| plan.policies.contains_key(p));
        if !keep {
            delete(&cms, &cm.name_any()).await?;
        }
    }
    Ok(())
}

async fn status(
    c: &Client,
    ns: &str,
    plan: &Plan,
    ready: &BTreeMap<String, (bool, i32)>,
) -> Result<(), Error> {
    let api = Api::<DvarapalaPolicy>::namespaced(c.clone(), ns);
    for (name, (p, r)) in &plan.policies {
        let gateways: Vec<GatewayStatus> = plan
            .gateways
            .values()
            .filter(|g| &g.policy == name)
            .map(|g| {
                let (protecting, n) = ready.get(&g.name).copied().unwrap_or_default();
                GatewayStatus {
                    service: g.name.clone(),
                    backend: g.backend.clone(),
                    port: g.port,
                    phase: if protecting {
                        "Protecting"
                    } else {
                        "Passthrough"
                    }
                    .into(),
                    ready_replicas: n,
                    admin_service: None,
                }
            })
            .collect();
        let s = PolicyStatus {
            ready: r.is_ok(),
            message: r.as_ref().err().cloned(),
            observed_generation: p.metadata.generation,
            config_hash: r.as_ref().ok().map(|r| r.hash.clone()),
            gateway_count: gateways.len() as i32,
            gateways,
            routes: plan.routes.get(name).copied().unwrap_or(0),
            skipped_backends: plan.skipped.get(name).cloned().unwrap_or_default(),
            warnings: Vec::new(),
        };
        if p.status.as_ref() != Some(&s) {
            let body = serde_json::json!({ "status": s });
            api.patch_status(name, &PatchParams::default(), &Patch::Merge(&body))
                .await?;
        }
        ::metrics::counter!("dvarapala_operator_reconciles_total", "result" => if r.is_ok() { "ok" } else { "invalid" }).increment(1);
    }
    Ok(())
}
