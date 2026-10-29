//! The only place eld touches the host. Providers read files and run native
//! tools through a [`System`] so they can be tested against a fake root
//! directory and canned command output, and so every command eld runs goes
//! through one code path.

use std::collections::HashMap;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Outcome of a command that ran.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == 0
    }
}

/// Why a command did not produce an [`Output`].
#[derive(Debug)]
pub enum RunError {
    /// The tool is not installed.
    NotFound(String),
    TimedOut(String),
    Io(io::Error),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::NotFound(t) => write!(f, "{t}: not installed"),
            RunError::TimedOut(t) => write!(f, "{t}: timed out"),
            RunError::Io(e) => write!(f, "{e}"),
        }
    }
}

/// Host abstraction used by providers. Paths are absolute host paths.
pub trait System: Send + Sync {
    fn read_file(&self, path: &str) -> io::Result<Vec<u8>>;
    /// Lists entry names of a directory, sorted.
    fn read_dir(&self, path: &str) -> io::Result<Vec<String>>;
    fn exists(&self, path: &str) -> bool;
    /// Runs a native tool. A non-zero exit is an `Ok(Output)`; only a tool
    /// that could not run is an error.
    fn run(&self, cmd: &str, args: &[&str]) -> Result<Output, RunError>;
    /// Reports whether a tool is installed.
    fn installed(&self, tool: &str) -> bool;

    /// Like [`System::run`] with a longer timeout, for scans and log export.
    fn run_long(&self, cmd: &str, args: &[&str], timeout: Duration) -> Result<Output, RunError> {
        let _ = timeout;
        self.run(cmd, args)
    }

    /// Reads a small file (sysfs, procfs) as trimmed text.
    fn read_trimmed(&self, path: &str) -> io::Result<String> {
        let b = self.read_file(path)?;
        Ok(String::from_utf8_lossy(&b).trim().to_string())
    }
}

/// Executes commands. [`Host`] uses [`ExecRunner`] unless told otherwise.
pub trait Runner: Send + Sync {
    fn run(&self, cmd: &str, args: &[&str]) -> Result<Output, RunError>;
    fn installed(&self, tool: &str) -> bool;
    fn run_timeout(&self, cmd: &str, args: &[&str], _timeout: Duration) -> Result<Output, RunError> {
        self.run(cmd, args)
    }
}

/// The real [`System`]. `root` is `/` in production and a fixture
/// directory in tests.
pub struct Host {
    pub root: PathBuf,
    pub runner: Box<dyn Runner>,
}

impl Host {
    /// A host rooted at `/` running real commands.
    pub fn new() -> Self {
        Host { root: PathBuf::from("/"), runner: Box::new(ExecRunner::default()) }
    }

    /// A host rooted at a fixture directory with a fake runner.
    pub fn fake(root: impl Into<PathBuf>, runner: FakeRunner) -> Self {
        Host { root: root.into(), runner: Box::new(runner) }
    }

    fn path(&self, p: &str) -> PathBuf {
        self.root.join(p.trim_start_matches('/'))
    }
}

impl Default for Host {
    fn default() -> Self {
        Host::new()
    }
}

impl System for Host {
    fn read_file(&self, path: &str) -> io::Result<Vec<u8>> {
        std::fs::read(self.path(path))
    }

    fn read_dir(&self, path: &str) -> io::Result<Vec<String>> {
        let mut out: Vec<String> = std::fs::read_dir(self.path(path))?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        out.sort();
        Ok(out)
    }

    fn exists(&self, path: &str) -> bool {
        self.path(path).exists()
    }

    fn run(&self, cmd: &str, args: &[&str]) -> Result<Output, RunError> {
        self.runner.run(cmd, args)
    }

    fn installed(&self, tool: &str) -> bool {
        self.runner.installed(tool)
    }

    fn run_long(&self, cmd: &str, args: &[&str], timeout: Duration) -> Result<Output, RunError> {
        self.runner.run_timeout(cmd, args, timeout)
    }
}

const SEARCH_PATH: &[&str] = &["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

/// Runs real processes with a timeout and a minimal environment. Tools are
/// resolved only from the system directories, never from the caller.
pub struct ExecRunner {
    pub timeout: Duration,
}

impl Default for ExecRunner {
    fn default() -> Self {
        ExecRunner { timeout: Duration::from_secs(30) }
    }
}

impl ExecRunner {
    fn resolve(tool: &str) -> Option<PathBuf> {
        if tool.contains('/') {
            return None;
        }
        SEARCH_PATH.iter().map(|d| PathBuf::from(d).join(tool)).find(|p| p.is_file())
    }
}

impl Runner for ExecRunner {
    fn run(&self, cmd: &str, args: &[&str]) -> Result<Output, RunError> {
        self.run_timeout(cmd, args, self.timeout)
    }

    fn run_timeout(&self, cmd: &str, args: &[&str], timeout: Duration) -> Result<Output, RunError> {
        let path = Self::resolve(cmd).ok_or_else(|| RunError::NotFound(cmd.to_string()))?;
        let mut child = Command::new(path)
            .args(args)
            .env_clear()
            .env("PATH", SEARCH_PATH.join(":"))
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(RunError::Io)?;
        let mut out = child.stdout.take().expect("piped stdout");
        let mut err = child.stderr.take().expect("piped stderr");
        let t_out = std::thread::spawn(move || {
            let mut s = Vec::new();
            let _ = out.read_to_end(&mut s);
            s
        });
        let t_err = std::thread::spawn(move || {
            let mut s = Vec::new();
            let _ = err.read_to_end(&mut s);
            s
        });
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(st) = child.try_wait().map_err(RunError::Io)? {
                break st;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RunError::TimedOut(cmd.to_string()));
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        Ok(Output {
            code: status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&t_out.join().unwrap_or_default()).into_owned(),
            stderr: String::from_utf8_lossy(&t_err.join().unwrap_or_default()).into_owned(),
        })
    }

    fn installed(&self, tool: &str) -> bool {
        Self::resolve(tool).is_some()
    }
}

/// Returns canned output keyed by the full command line (`"cmd arg1 arg2"`).
/// Unknown commands fail as "not installed". Records every call.
#[derive(Default)]
pub struct FakeRunner {
    results: HashMap<String, Output>,
    installed: Option<Vec<String>>,
    pub calls: Mutex<Vec<String>>,
}

impl FakeRunner {
    pub fn new() -> Self {
        FakeRunner::default()
    }

    /// Registers stdout and exit code for a command line.
    pub fn on(mut self, cmdline: &str, code: i32, stdout: &str) -> Self {
        self.results.insert(cmdline.to_string(), Output { code, stdout: stdout.into(), stderr: String::new() });
        self
    }

    /// Restricts `installed` to exactly these tools. By default any tool
    /// that appears in a registered command line is installed.
    pub fn with_installed(mut self, tools: &[&str]) -> Self {
        self.installed = Some(tools.iter().map(|t| t.to_string()).collect());
        self
    }

    /// Command lines run so far.
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl Runner for FakeRunner {
    fn run(&self, cmd: &str, args: &[&str]) -> Result<Output, RunError> {
        let mut line = cmd.to_string();
        for a in args {
            line.push(' ');
            line.push_str(a);
        }
        self.calls.lock().unwrap().push(line.clone());
        self.results.get(&line).cloned().ok_or_else(|| RunError::NotFound(cmd.to_string()))
    }

    fn installed(&self, tool: &str) -> bool {
        match &self.installed {
            Some(list) => list.iter().any(|t| t == tool),
            None => self.results.keys().any(|k| k == tool || k.starts_with(&format!("{tool} "))),
        }
    }
}

/// Substrate family. eld stays distro-agnostic by branching on the family,
/// never on a specific distro name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// Ubuntu, Debian
    Debian,
    /// RHEL, Rocky, Alma, Fedora, CentOS Stream
    Rhel,
    /// SLES, Leap
    Suse,
    Unknown,
}

impl Family {
    pub fn as_str(self) -> &'static str {
        match self {
            Family::Debian => "debian",
            Family::Rhel => "rhel",
            Family::Suse => "suse",
            Family::Unknown => "unknown",
        }
    }
}

/// Parsed `/etc/os-release`.
#[derive(Debug, Clone, Default)]
pub struct OsRelease {
    pub fields: HashMap<String, String>,
}

impl OsRelease {
    /// Parses the os-release(5) format.
    pub fn parse(text: &str) -> Self {
        let mut fields = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let v = v.trim();
                let v = v
                    .strip_prefix('"')
                    .and_then(|x| x.strip_suffix('"'))
                    .or_else(|| v.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')))
                    .unwrap_or(v);
                fields.insert(k.to_string(), v.replace("\\\"", "\"").replace("\\\\", "\\"));
            }
        }
        OsRelease { fields }
    }

    /// Reads `/etc/os-release`, falling back to `/usr/lib/os-release`.
    pub fn read(sys: &dyn System) -> io::Result<Self> {
        let b = sys.read_file("/etc/os-release").or_else(|_| sys.read_file("/usr/lib/os-release"))?;
        Ok(Self::parse(&String::from_utf8_lossy(&b)))
    }

    /// A field or "".
    pub fn get(&self, k: &str) -> &str {
        self.fields.get(k).map(String::as_str).unwrap_or("")
    }

    /// Derives the family from `ID` and `ID_LIKE`.
    pub fn family(&self) -> Family {
        let ids = format!("{} {}", self.get("ID"), self.get("ID_LIKE"));
        for id in ids.split_whitespace() {
            match id {
                "debian" | "ubuntu" => return Family::Debian,
                "rhel" | "fedora" | "centos" | "rocky" | "almalinux" => return Family::Rhel,
                "suse" | "opensuse" | "sles" | "opensuse-leap" => return Family::Suse,
                _ => {}
            }
        }
        Family::Unknown
    }
}

/// Detects the family of a host, `Unknown` if os-release is unreadable.
pub fn family(sys: &dyn System) -> Family {
    OsRelease::read(sys).map(|o| o.family()).unwrap_or(Family::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release_family() {
        let u = OsRelease::parse("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n");
        assert_eq!(u.family(), Family::Debian);
        assert_eq!(u.get("VERSION_ID"), "24.04");
        let r = OsRelease::parse("ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n");
        assert_eq!(r.family(), Family::Rhel);
        assert_eq!(OsRelease::parse("ID=arch").family(), Family::Unknown);
    }

    #[test]
    fn fake_runner() {
        let f = FakeRunner::new().on("systemctl is-active sshd", 3, "inactive\n");
        assert!(f.installed("systemctl"));
        assert!(!f.installed("ssh"));
        assert_eq!(f.run("systemctl", &["is-active", "sshd"]).unwrap().code, 3);
        assert!(matches!(f.run("nope", &[]), Err(RunError::NotFound(_))));
        assert_eq!(f.calls().len(), 2);
    }

    #[test]
    fn exec_runner_rejects_paths() {
        let r = ExecRunner::default();
        assert!(matches!(r.run("/bin/sh", &[]), Err(RunError::NotFound(_))));
    }
}
