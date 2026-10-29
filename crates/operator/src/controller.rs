//! The controller, one reconcile per namespace: render the policies, run
//! a gateway per labeled backend, point the routes at them, switch each
//! gateway Service from passthrough to protecting once its pods are ready,
//! remove the gateways no route uses, and report in the policy status.
#![allow(unused_variables, unused_imports, dead_code)]

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
        todo!("rfc 0019")
    }
}

impl std::error::Error for Error {}

impl From<kube::Error> for Error {
    fn from(e: kube::Error) -> Self {
        todo!("rfc 0019")
    }
}

/// The route kinds this cluster serves: `Ingress`, and the Gateway API
/// routes when their CRDs are installed.
pub async fn kinds(client: &Client) -> Vec<(Kind, ApiResource)> {
    todo!("rfc 0019")
}

pub async fn run(ctx: Arc<Ctx>) {
    todo!("rfc 0019")
}

fn ns_of<K: Resource>(o: K) -> Option<ObjectRef<Namespace>> {
    todo!("rfc 0019")
}

async fn apply<K>(api: &Api<K>, name: &str, obj: &K) -> Result<K, Error>
where
    K: Resource + Clone + Serialize + DeserializeOwned + std::fmt::Debug,
{
    todo!("rfc 0019")
}

async fn delete<K>(api: &Api<K>, name: &str) -> Result<(), Error>
where
    K: Resource + Clone + DeserializeOwned + std::fmt::Debug,
{
    todo!("rfc 0019")
}

struct Plan {
    /// policy name to its rendering, or why it is invalid
    policies: BTreeMap<String, (DvarapalaPolicy, Result<Rendered, String>)>,
    gateways: BTreeMap<String, Gateway>,
    skipped: BTreeMap<String, Vec<String>>,
    routes: BTreeMap<String, i32>,
}

async fn reconcile(ns: Arc<Namespace>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    todo!("rfc 0019")
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
    todo!("rfc 0019")
}

/// Deletes gateways no route uses and ConfigMaps of removed policies.
async fn collect(c: &Client, ns: &str, plan: &Plan) -> Result<(), Error> {
    todo!("rfc 0019")
}

async fn status(
    c: &Client,
    ns: &str,
    plan: &Plan,
    ready: &BTreeMap<String, (bool, i32)>,
) -> Result<(), Error> {
    todo!("rfc 0019")
}
