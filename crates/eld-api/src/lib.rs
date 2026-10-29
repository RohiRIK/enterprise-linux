//! Wire types shared by `eld` (the control daemon) and `elctl` (the CLI).
//!
//! Everything here is serialised as JSON on the Unix socket and is part of
//! the versioned v1 contract described in `docs/CONTROL-API.md`.

pub mod client;
pub mod time;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// API version served under `/v1`.
pub const VERSION: &str = "v1";

/// Default socket path.
pub const DEFAULT_SOCKET: &str = "/run/eld/api.sock";

/// JSON object, used for facts and free-form data.
pub type Object = Map<String, Value>;

/// Permission role from `docs/PERMISSIONS.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Role {
    #[serde(rename = "user")]
    User,
    #[serde(rename = "power-user")]
    PowerUser,
    #[serde(rename = "helpdesk")]
    Helpdesk,
    #[serde(rename = "local-admin")]
    LocalAdmin,
    #[serde(rename = "break-glass")]
    BreakGlass,
    #[serde(rename = "svc:mdm")]
    SvcMdm,
    #[serde(rename = "svc:edr")]
    SvcEdr,
}

impl Role {
    /// The wire name of the role.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::User => "user",
            Role::PowerUser => "power-user",
            Role::Helpdesk => "helpdesk",
            Role::LocalAdmin => "local-admin",
            Role::BreakGlass => "break-glass",
            Role::SvcMdm => "svc:mdm",
            Role::SvcEdr => "svc:edr",
        }
    }

    /// Parses a wire name.
    pub fn parse(s: &str) -> Option<Role> {
        serde_json::from_value(Value::String(s.to_string())).ok()
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Who set a desired-state value. Precedence is
/// `mdm > local-admin > user` (`docs/CONTROL-API.md` §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Source {
    #[serde(rename = "mdm")]
    Mdm,
    #[serde(rename = "local-admin")]
    LocalAdmin,
    #[serde(rename = "user")]
    User,
}

impl Source {
    /// Orders sources by precedence; higher wins.
    pub fn rank(self) -> u8 {
        match self {
            Source::Mdm => 3,
            Source::LocalAdmin => 2,
            Source::User => 1,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Source::Mdm => "mdm",
            Source::LocalAdmin => "local-admin",
            Source::User => "user",
        }
    }
}

/// Value type of a setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SettingType {
    String,
    Bool,
    Int,
    Enum,
    /// List of strings.
    List,
}

/// One desired-state key owned by a provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingSpec {
    pub key: String,
    #[serde(rename = "type")]
    pub kind: SettingType,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
    pub description: String,
    /// True when eld actually changes the system for this key. When false
    /// the value is stored, reported and used for compliance only.
    pub enforced: bool,
}

impl SettingSpec {
    /// A setting that is stored and reported but not enforced.
    pub fn new(key: &str, kind: SettingType, description: &str) -> Self {
        SettingSpec {
            key: key.into(),
            kind,
            values: vec![],
            default: None,
            description: description.into(),
            enforced: false,
        }
    }

    /// An enum setting with its allowed values.
    pub fn enumeration(key: &str, values: &[&str], description: &str) -> Self {
        let mut s = SettingSpec::new(key, SettingType::Enum, description);
        s.values = values.iter().map(|v| v.to_string()).collect();
        s
    }

    pub fn with_default(mut self, v: Value) -> Self {
        self.default = Some(v);
        self
    }
}

/// One action parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamSpec {
    pub name: String,
    /// `string` | `bool` | `int` | `duration`
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub required: bool,
    pub description: String,
}

impl ParamSpec {
    pub fn new(name: &str, kind: &str, required: bool, description: &str) -> Self {
        ParamSpec { name: name.into(), kind: kind.into(), required, description: description.into() }
    }
}

/// One imperative operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionSpec {
    /// Fully qualified, e.g. `updates.check`.
    pub name: String,
    pub description: String,
    pub min_role: Role,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub destructive: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<ParamSpec>,
    /// False for actions that are declared in the contract but refuse to
    /// run in this build.
    pub implemented: bool,
}

impl ActionSpec {
    pub fn new(name: &str, min_role: Role, description: &str) -> Self {
        ActionSpec {
            name: name.into(),
            description: description.into(),
            min_role,
            destructive: false,
            params: vec![],
            implemented: true,
        }
    }

    pub fn param(mut self, p: ParamSpec) -> Self {
        self.params.push(p);
        self
    }

    pub fn destructive(mut self) -> Self {
        self.destructive = true;
        self
    }

    pub fn not_implemented(mut self) -> Self {
        self.implemented = false;
        self
    }
}

/// Action result statuses.
pub mod status {
    pub const OK: &str = "ok";
    pub const DRY_RUN: &str = "dry-run";
    pub const NOT_IMPLEMENTED: &str = "not-implemented";
    pub const FAILED: &str = "failed";
}

/// Body of `POST /v1/actions/{name}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionRequest {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dry_run: bool,
    /// Required for destructive actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm_token: Option<String>,
}

/// Response of an action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionResult {
    pub action: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(default, skip_serializing_if = "Object::is_empty")]
    pub data: Object,
    /// Native commands that were (or, for a dry run, would be) executed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<Vec<String>>,
}

/// Event severities.
pub mod severity {
    pub const INFO: &str = "info";
    pub const WARNING: &str = "warning";
    pub const HIGH: &str = "high";
}

/// One entry on the event stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: u64,
    /// RFC 3339, UTC.
    pub time: String,
    /// e.g. `policy.applied`
    #[serde(rename = "type")]
    pub kind: String,
    pub severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<Caller>,
    #[serde(default, skip_serializing_if = "Object::is_empty")]
    pub data: Object,
}

/// The process on the other end of the socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Caller {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user: String,
    /// SELinux/AppArmor label of the calling process.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    pub roles: Vec<Role>,
    pub source: Source,
    /// Service principal name, if the caller is a registered agent.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub principal: String,
}

impl Caller {
    /// Display name for audit records.
    pub fn who(&self) -> String {
        if !self.principal.is_empty() {
            format!("principal:{}", self.principal)
        } else if !self.user.is_empty() {
            self.user.clone()
        } else {
            format!("uid:{}", self.uid)
        }
    }
}

/// Stored desired state for one key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingValue {
    pub key: String,
    pub value: Value,
    pub source: Source,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub set_by: String,
    pub updated: String,
}

/// Identifies a policy document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub name: String,
    pub version: String,
}

/// Declarative policy document (`docs/CONTROL-API.md` §4). `spec` is a
/// nested object whose leaves are flattened to dotted setting keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePolicy {
    pub api_version: String,
    pub kind: String,
    pub metadata: PolicyMetadata,
    pub spec: Object,
}

/// Per-key results of a settings write.
pub mod result {
    pub const APPLIED: &str = "applied";
    pub const UNCHANGED: &str = "unchanged";
    pub const REJECTED: &str = "rejected";
    /// A key a full policy document no longer sets.
    pub const REMOVED: &str = "removed";
}

/// Outcome for one key of a settings write.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyResult {
    pub key: String,
    pub result: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new: Option<Value>,
}

/// Response of `PUT /v1/settings`, `PATCH /v1/settings` and the diff
/// endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyResponse {
    pub dry_run: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyMetadata>,
    pub results: Vec<KeyResult>,
    pub etag: String,
}

/// JSON body of every non-2xx response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    /// Stable machine code, see [`code`].
    pub code: String,
    pub message: String,
}

/// Stable error codes.
pub mod code {
    pub const BAD_REQUEST: &str = "bad-request";
    pub const FORBIDDEN: &str = "forbidden";
    pub const NOT_FOUND: &str = "not-found";
    pub const CONFLICT: &str = "conflict";
    pub const PRECONDITION: &str = "precondition-failed";
    pub const TOO_MANY: &str = "rate-limited";
    pub const INTERNAL: &str = "internal";
}
