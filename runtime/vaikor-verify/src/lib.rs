//! Static verifier for Vaikor plan language v0 (VKR-L3).
//!
//! Expressions are compiled with the `cel` crate (0.15, cel-rust). That dependency
//! exists because E6 forbids a private expression language. No host
//! functions are registered. Sensitive egress uses `FlowPolicy`; owner-signed
//! stored-plan authentication and per-run checks are in `stored`.

mod plan;

pub use plan::{
    verify, AllowList, Arg, Cap, DeferToCedar, DenySensitive, FlowPolicy, Plan, Step, Summary,
};

pub mod flow;
pub mod stored;
