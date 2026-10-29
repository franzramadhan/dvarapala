//! The mutating webhook: a labeled route's backends point at their
//! gateways, or back at the originals when the label is gone. A gateway
//! Service that does not exist yet is created here in passthrough, so the
//! rewrite is part of the user's own request and their field manager keeps
//! owning the backends (a later server-side apply of their manifest does
//! not conflict). Nothing is created on a dry run.
#![allow(unused_variables, unused_imports, dead_code)]

use std::collections::HashSet;

use k8s_openapi::api::core::v1::{Namespace, Service};
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::core::DynamicObject;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use kube::{Client, ResourceExt};

use crate::controller::MANAGER;
use crate::crd::DvarapalaPolicy;
use crate::gateway::{self, MANAGED_BY};
use crate::routes::{self, Kind, LABEL};

/// The `AdmissionReview` answer to `body`. Refuses when a lookup fails,
/// so a labeled route is never stored without its rewrite.
pub async fn review(client: &Client, body: &[u8]) -> Vec<u8> {
    todo!("rfc 0019")
}

async fn mutate(
    client: &Client,
    req: &AdmissionRequest<DynamicObject>,
) -> Result<Option<json_patch::Patch>, String> {
    todo!("rfc 0019")
}
