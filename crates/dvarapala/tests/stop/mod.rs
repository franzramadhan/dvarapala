//! Stops a spawned binary with SIGTERM, so it exits through `main` and an
//! instrumented build writes its coverage profile (SIGKILL loses it).

use std::process::{Child, Command};
use std::time::{Duration, Instant};

pub fn stop(child: &mut Child) {
    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
}
