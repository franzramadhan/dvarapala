//! RFC 0025: the admin Service of a gateway, with a stable name so a
//! hand-written Ingress or tailnet proxy can point at it, and `ClientIP`
//! affinity so a console session stays on one pod.
#![allow(unused_variables, unused_imports, dead_code)]

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

use super::{BACKEND, Gateway, MANAGED_BY, POLICY, selector};

pub const PORT: i32 = 9091;
/// On an admin Service: the gateway it belongs to. It has no `APP` label,
/// so it is never taken for a gateway Service.
pub const ADMIN_OF: &str = "dvarapala.franzramadhan.dev/admin-of";

/// `<backend>-dvp-admin-<port>`, at most 63 characters.
pub fn name(g: &Gateway) -> String {
    todo!("rfc 0025")
}

pub fn service(g: &Gateway) -> Service {
    todo!("rfc 0025")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "rfc 0025"]
    fn names_fit_and_keep_the_port() {
        let mut g = Gateway {
            name: "web-dvp-0".into(),
            namespace: "shop".into(),
            backend: "web".into(),
            port: 80,
            port_name: None,
            app_protocol: None,
            policy: "default".into(),
            http2: false,
        };
        assert_eq!(name(&g), "web-dvp-admin-80");
        g.backend = "a".repeat(51) + "-" + &"b".repeat(11);
        g.port = 65535;
        let n = name(&g);
        assert!(
            n.len() <= 63 && n.ends_with("-dvp-admin-65535") && !n.contains("--"),
            "{n}"
        );
    }
}
