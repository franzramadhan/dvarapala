//! Test isolation for the process environment (issue 358).
//!
//! `figment::Jail` only serializes Jail tests against each other, so an
//! unjailed `load` could read the `DVARAPALA__*` values a jail sets.

#[cfg(test)]
use figment::Jail;

#[cfg(test)]
thread_local!(static IN_JAIL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) });

/// Runs `f`; under test, holds the jail lock unless this thread already does.
#[cfg_attr(test, allow(clippy::result_large_err))]
pub(super) fn exclusive<T>(f: impl FnOnce() -> T) -> T {
    #[cfg(test)]
    if !IN_JAIL.get() {
        let (mut f, mut out) = (Some(f), None);
        Jail::expect_with(|_| {
            out = Some((f.take().unwrap())());
            Ok(())
        });
        return out.unwrap();
    }
    f()
}

/// `Jail::expect_with` that records the lock is held, for `exclusive`.
#[cfg(test)]
#[allow(clippy::result_large_err)]
pub(crate) fn jail(f: impl FnOnce(&mut Jail) -> figment::error::Result<()>) {
    Jail::expect_with(|j| {
        IN_JAIL.set(true);
        let r = f(j);
        IN_JAIL.set(false);
        r
    });
}

#[cfg(test)]
#[path = "exclusive_tests.rs"]
mod tests;
