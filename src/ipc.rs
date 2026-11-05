use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::config::Mode;
use crate::detect::VpnStatus;
use crate::guard::Protection;

pub const DEFAULT_SOCKET: &str = "/var/run/vpnchecker.sock";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub pid: u32,
    pub config: String,
    pub dry_run: bool,
    /// Unix time of the last VPN state change.
    pub since: u64,
    pub last_check: u64,
    pub allowed: usize,
    pub vpn: VpnStatus,
    #[serde(default)]
    pub mode: Mode,
    /// State of the Claude / Cursor / Rider protection.
    #[serde(default)]
    pub protection: Protection,
    /// Protected processes currently frozen / killed.
    #[serde(default)]
    pub frozen: usize,
    /// Claude / Cursor server addresses blocked outside the tunnel.
    #[serde(default)]
    pub protected_ips: usize,
    /// Local DNS shield for the protected domains is active.
    #[serde(default)]
    pub shield: bool,
    /// Version of the running daemon (empty when the daemon predates this field).
    #[serde(default)]
    pub version: String,
    /// The daemon installs newer releases by itself.
    #[serde(default)]
    pub auto_update: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Status,
    Reload,
    Recheck,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Snapshot>,
}

#[derive(Debug)]
pub enum Control {
    Reload,
    Recheck,
    /// The daemon replaced its own binary with this version and has to exit so launchd starts it.
    Updated(String),
}

pub type Shared = Arc<Mutex<Snapshot>>;

/// Status is readable by anyone; control commands need root or the config owner.
pub fn serve(path: &Path, shared: Shared, tx: mpsc::Sender<Control>, admin_uid: Option<u32>) -> Result<()> {
    let _ = fs::remove_file(path);
    let listener = UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    fs::set_permissions(path, Permissions::from_mode(0o666))?;
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(handle(stream, shared.clone(), tx.clone(), admin_uid));
                }
                Err(e) => warn!(error = %e, "ipc accept failed"),
            }
        }
    });
    Ok(())
}

async fn handle(stream: UnixStream, shared: Shared, tx: mpsc::Sender<Control>, admin_uid: Option<u32>) {
    let peer = stream.peer_cred().ok().map(|c| c.uid());
    let (read, mut write) = stream.into_split();
    let mut line = String::new();
    if BufReader::new(read.take(4096)).read_line(&mut line).await.is_err() {
        return;
    }
    let authorized = peer == Some(0) || (peer.is_some() && peer == admin_uid);
    let response = match serde_json::from_str::<Request>(&line) {
        Ok(Request::Status) => Response {
            ok: true,
            status: Some(shared.lock().unwrap().clone()),
            ..Default::default()
        },
        Ok(_) if !authorized => error("permission denied"),
        Ok(req) => {
            let control = match req {
                Request::Reload => Control::Reload,
                _ => Control::Recheck,
            };
            match tx.send(control).await {
                Ok(()) => Response { ok: true, ..Default::default() },
                Err(_) => error("daemon is shutting down"),
            }
        }
        Err(e) => error(&format!("bad request: {e}")),
    };
    let mut out = serde_json::to_string(&response).unwrap_or_default();
    out.push('\n');
    if let Err(e) = write.write_all(out.as_bytes()).await {
        debug!(error = %e, "ipc write failed");
    }
}

fn error(msg: &str) -> Response {
    Response {
        ok: false,
        error: Some(msg.to_string()),
        status: None,
    }
}

pub async fn request(path: &Path, req: &Request) -> Result<Response> {
    let stream = UnixStream::connect(path)
        .await
        .with_context(|| format!("daemon is not running (cannot connect to {})", path.display()))?;
    let (read, mut write) = stream.into_split();
    let mut msg = serde_json::to_string(req)?;
    msg.push('\n');
    write.write_all(msg.as_bytes()).await?;
    let mut line = String::new();
    BufReader::new(read).read_line(&mut line).await?;
    let resp: Response = serde_json::from_str(&line).context("bad response from daemon")?;
    if !resp.ok {
        bail!(resp.error.unwrap_or_else(|| "request failed".into()));
    }
    Ok(resp)
}
