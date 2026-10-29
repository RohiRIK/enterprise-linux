//! Domain providers. Each module exports `pub fn new() -> Arc<dyn Provider>`.

pub mod apps;
pub mod compliance;
pub mod desktop;
pub mod device;
pub mod encryption;
pub mod identity;
pub mod network;
pub mod osinfo;
pub mod security;
pub mod updates;
