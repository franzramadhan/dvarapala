use std::io::Read;
use std::path::Path;

use dvarapala_engine::{FeedError, PrefixSet, parse_feed};
use dvarapala_l7::{FeedList, unix_now};

/// Why a feed body did not arrive.
#[derive(Debug)]
pub enum Failed {
    Fetch(String),
    TooLarge,
}

/// A `path` feed's body, at most `max` bytes.
pub fn read(path: &Path, max: usize) -> Result<Vec<u8>, Failed> {
    let f = std::fs::File::open(path).map_err(|e| Failed::Fetch(e.to_string()))?;
    let mut body = Vec::new();
    f.take(max as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|e| Failed::Fetch(e.to_string()))?;
    if body.len() > max {
        return Err(Failed::TooLarge);
    }
    Ok(body)
}

/// Puts the list in `body` in force, or keeps the one in force on any
/// failure. Counts the result in `dvarapala_intel_feed_refresh_total`,
/// logs a failure, and returns the result label or the error.
pub fn apply(
    name: &str,
    list: &FeedList,
    body: Result<Vec<u8>, Failed>,
    max_entries: usize,
) -> Result<&'static str, String> {
    let result = parse(body, max_entries).map(|set| {
        if *list.get() == set {
            return "unchanged";
        }
        list.set(set);
        "ok"
    });
    let label = match &result {
        Ok(l) => l,
        Err((l, _)) => l,
    };
    metrics::counter!(
        "dvarapala_intel_feed_refresh_total",
        "feed" => name.to_owned(),
        "result" => *label
    )
    .increment(1);
    match result {
        Ok(l) => {
            let entries = list.get().len();
            metrics::gauge!("dvarapala_intel_feed_entries", "feed" => name.to_owned())
                .set(entries as f64);
            metrics::gauge!(
                "dvarapala_intel_feed_last_success_timestamp_seconds",
                "feed" => name.to_owned()
            )
            .set(unix_now() as f64);
            Ok(l)
        }
        Err((_, e)) => {
            tracing::warn!(msg = "intel feed refresh failed", feed = name, error = %e);
            Err(e)
        }
    }
}

fn parse(
    body: Result<Vec<u8>, Failed>,
    max_entries: usize,
) -> Result<PrefixSet, (&'static str, String)> {
    let body = body.map_err(|e| match e {
        Failed::Fetch(e) => ("fetch_error", e),
        Failed::TooLarge => ("too_large", "larger than intel.max_bytes".into()),
    })?;
    let text = std::str::from_utf8(&body).map_err(|_| ("invalid", "not UTF-8".to_owned()))?;
    let nets = parse_feed(text, max_entries).map_err(|e| match e {
        FeedError::TooMany => ("too_large", e.to_string()),
        FeedError::Line(..) => ("invalid", e.to_string()),
    })?;
    Ok(PrefixSet::new(nets))
}

#[cfg(test)]
mod tests {
    use metrics_exporter_prometheus::PrometheusBuilder;

    use super::*;

    // RFC 0031 case 8, on the refresh step the fetch task runs
    #[test]
    fn failed_refreshes_keep_the_list_in_force_and_count() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let list = FeedList::default();
        let ok = |s: &str| Ok(s.as_bytes().to_vec());
        let results = metrics::with_local_recorder(&recorder, || {
            [
                apply("drop", &list, ok("192.0.2.0/24\n"), 2),
                apply("drop", &list, Err(Failed::Fetch("status 500".into())), 2),
                apply("drop", &list, ok("192.0.2.1\n192.0.2.2\n192.0.2.3\n"), 2),
                apply("drop", &list, Err(Failed::TooLarge), 2),
                apply("drop", &list, ok("example.com\n"), 2),
                apply("drop", &list, ok("192.0.2.0/24 ; again\n"), 2),
            ]
        });
        let labels: Vec<_> = results.iter().map(|r| r.as_deref().ok()).collect();
        assert_eq!(
            labels,
            [Some("ok"), None, None, None, None, Some("unchanged")]
        );
        assert!(list.get().contains("192.0.2.9".parse().unwrap()));
        let text = handle.render();
        let count = |result: &str| {
            let series =
                format!("dvarapala_intel_feed_refresh_total{{feed=\"drop\",result=\"{result}\"}}");
            text.lines()
                .find(|l| l.starts_with(&series))
                .and_then(|l| l.rsplit(' ').next())
                .map_or(0, |v| v.parse::<u64>().unwrap())
        };
        assert_eq!(
            ["ok", "fetch_error", "too_large", "invalid", "unchanged"].map(count),
            [1, 1, 2, 1, 1]
        );
        assert!(text.contains("dvarapala_intel_feed_entries{feed=\"drop\"} "));
    }

    #[test]
    fn a_file_over_max_bytes_is_too_large() {
        let dir = std::env::temp_dir().join(format!("dvarapala-intel-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("feed.txt");
        std::fs::write(&p, "192.0.2.0/24\n").unwrap();
        assert_eq!(read(&p, 13).unwrap().len(), 13);
        assert!(matches!(read(&p, 12), Err(Failed::TooLarge)));
        assert!(matches!(read(&dir.join("none"), 12), Err(Failed::Fetch(_))));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
