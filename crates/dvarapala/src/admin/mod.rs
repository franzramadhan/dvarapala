//! The admin listener: the RFC 0014 API and, with `ui_enabled`, the RFC
//! 0018 console and its logins.

mod api;
pub mod history;
#[cfg(feature = "ui")]
mod login;
#[cfg(feature = "ui")]
mod oidc;
mod serve;
pub mod switch;
#[cfg(feature = "ui")]
mod ui;
mod waf;

#[cfg(feature = "ui")]
pub use login::Console;
pub use serve::{Admin, serve};
