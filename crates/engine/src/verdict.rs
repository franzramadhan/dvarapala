use std::time::Duration;

/// What to do with a request or connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// Over the limit; the client may retry after this long.
    Throttle {
        retry_after: Duration,
    },
    Challenge,
    Drop,
}
