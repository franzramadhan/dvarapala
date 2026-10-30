//! RFC 0025: the admin Service of a gateway, with a stable name so a
//! hand-written Ingress or tailnet proxy can point at it, and `ClientIP`
//! affinity so a console session stays on one pod.

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
    let suffix = format!("-dvp-admin-{}", g.port);
    let mut s: String = g.backend.chars().take(63 - suffix.len()).collect();
    while s.ends_with('-') {
        s.pop();
    }
    s + &suffix
}

pub fn service(g: &Gateway) -> Service {
    let labels = [
        MANAGED_BY,
        (ADMIN_OF, &g.name),
        (BACKEND, &g.backend),
        (POLICY, &g.policy),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect::<BTreeMap<_, _>>();
    Service {
        metadata: ObjectMeta {
            name: Some(name(g)),
            namespace: Some(g.namespace.clone()),
            labels: Some(labels),
            ..ObjectMeta::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(selector(g)),
            session_affinity: Some("ClientIP".into()),
            ports: Some(vec![ServicePort {
                name: Some("admin".into()),
                port: PORT,
                target_port: Some(IntOrString::String("admin".into())),
                protocol: Some("TCP".into()),
                ..ServicePort::default()
            }]),
            ..ServiceSpec::default()
        }),
        status: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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
