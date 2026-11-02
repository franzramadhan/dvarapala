//! RFC 0019: the Kubernetes operator. Routes labeled with a policy go
//! through a dvarapala gateway the operator runs.

pub mod app;
pub mod cert;
pub mod controller;
pub mod crd;
#[cfg(test)]
mod fake;
pub mod gateway;
pub mod policy;
pub mod routes;
pub mod server;
pub mod webhook;
