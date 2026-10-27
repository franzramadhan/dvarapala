//! Flood detection from the traffic itself: heavy hitters, a learned rate
//! baseline and source entropy feed an attack state machine.

// rfc 0002 stubs: removed once the implementation fills the bodies in
#![allow(dead_code)]

mod baseline;
mod detector;
mod entropy;
mod heavy;
mod sketch;
mod state;

pub use detector::{DetectConfig, DetectError, Detector, WindowReport};
pub use state::State;
