//! The admin listener: the RFC 0014 API and, with `ui_enabled`, the RFC
//! 0018 console and its logins.

mod api;
#[cfg(feature = "ui")]
mod login;
#[cfg(feature = "ui")]
mod oidc;
mod serve;
#[cfg(feature = "ui")]
mod ui;

#[cfg(feature = "ui")]
pub use login::Console;
pub use serve::{Admin, serve};
