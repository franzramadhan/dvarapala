# Credits

## Research

The learned scoring in detection ([RFC 0002](rfc/0002-adaptive-detection.md))
started from this paper. It compares classifiers on the CICDDoS2019 dataset
and finds Random Forest, AdaBoost and XGBoost the most accurate and fast
enough for real-time detection. That result made a small XGBoost model in
the request path worth a try.

- Debashis Kar Suvra, "An Efficient Real Time DDoS Detection Model Using
  Machine Learning Algorithms", arXiv:2501.14311, 2025.
  <https://arxiv.org/abs/2501.14311>

dvarapala does not use code or data from the paper. It computes its own
features per client and loads standard XGBoost JSON models (see
[Learned scoring](site/docs/ml.md)).

## WAF

dvarapala's WAF ([RFC 0017](rfc/0017-waf.md)) stands on the work of these
projects. dvarapala does not bundle or link them: it speaks SPOP to an
agent you run next to it, and each project's license applies to the copy
you run.

| Project | What dvarapala uses it for | License |
|---|---|---|
| [OWASP Coraza](https://github.com/corazawaf/coraza) | The WAF engine that evaluates the rules | Apache-2.0 |
| [coraza-spoa](https://github.com/corazawaf/coraza-spoa) | The SPOP agent around Coraza, with the CRS built in; the sidecar in `examples/waf/` | Apache-2.0 |
| [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset) | The rules: SQL injection, XSS, path traversal, remote code execution and more | Apache-2.0 |
| [HAProxy](https://www.haproxy.org/) | The Stream Processing Offload Protocol, implemented from its [`doc/SPOE.txt`](https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt) | GPL-2.0 (spec only, no code) |

Thank you to the Coraza and CRS maintainers and contributors, and to the
OWASP Foundation, for keeping an open WAF and an open rule set alive.

The Rust crates dvarapala builds on are listed in `Cargo.lock`; `deny.toml`
holds them to permissive licenses.
