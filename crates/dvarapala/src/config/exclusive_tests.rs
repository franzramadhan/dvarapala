use crate::config::{jail, load};

/// Issue 358: `load` outside a jail must not see a jail's environment.
#[test]
#[allow(clippy::result_large_err)]
fn unjailed_load_ignores_a_jails_environment() {
    let (tx, rx) = std::sync::mpsc::channel();
    let mut reader = None;
    jail(|j| {
        j.set_env("DVARAPALA__CONFIG_WATCH", "soon");
        reader = Some(std::thread::spawn(move || {
            tx.send(()).unwrap();
            load(None).map(|_| ()).map_err(|e| e.to_string())
        }));
        rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        Ok(())
    });
    assert_eq!(reader.unwrap().join().unwrap(), Ok(()));
}
