//! eld, the enterprise-linux control daemon: transport, authentication,
//! roles, settings store, audit and the event bus. Domain logic lives in
//! [`providers`]; [`builtin`] holds the namespaces backed by eld's own state.

pub mod audit;
pub mod authz;
pub mod builtin;
pub mod config;
pub mod events;
pub mod http;
pub mod provider;
pub mod providers;
pub mod server;
pub mod settings;
pub mod store;
pub mod sys;

use std::sync::Arc;

/// Builds the registry with every provider this build ships.
pub fn registry(
    store: Arc<store::Store>,
    audit: Arc<audit::Auditor>,
    config: &config::Config,
) -> Result<provider::Registry, String> {
    use providers::*;
    provider::Registry::new(vec![
        apps::new(),
        compliance::new(),
        desktop::new(),
        device::new(),
        encryption::new(),
        identity::new(),
        network::new(),
        osinfo::new(),
        security::new(),
        updates::new(),
        Arc::new(builtin::Policy(Arc::clone(&store))),
        Arc::new(builtin::Roles { store, max_grant_minutes: config.max_grant_minutes }),
        Arc::new(builtin::Audit(audit)),
    ])
}
