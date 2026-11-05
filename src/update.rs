//! Self-update from this repository's GitHub releases. The installed daemon finds a newer release, verifies the
//! download, swaps its own binary and exits; launchd starts the new one.

use std::fmt;
use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use nix::unistd::{Gid, Uid, chown};
use tokio::process::Command;
use tokio::time::timeout;

use crate::sys;

pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
const REPO_URL: &str = "https://github.com/pwyllcrusader/vpnchecker";
const ASSET: &str = "vpnchecker-macos-universal.tar.gz";
const MEMBER: &str = "vpnchecker";
// Root-only (0700) under a root-owned parent: nothing a regular user can write may become the binary
// launchd runs as root.
const WORK_DIR: &str = "/var/db/vpnchecker/update";
const CURL: &str = "/usr/bin/curl";
const SHASUM: &str = "/usr/bin/shasum";
const TAR: &str = "/usr/bin/tar";
// HTTPS only, also across the redirects GitHub uses for release assets.
const CURL_BASE: [&str; 6] = ["--proto", "=https", "--proto-redir", "=https", "--tlsv1.2", "-fsSL"];
const CHECK_TIMEOUT: Duration = Duration::from_secs(40);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(330);
const TOOL_TIMEOUT: Duration = Duration::from_secs(30);

/// A plain `X.Y.Z` release. Pre-release tags do not parse, so they are never installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u64, pub u64, pub u64);

impl Version {
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let mut parts = text.strip_prefix('v').unwrap_or(text).split('.');
        let mut next = || parts.next()?.parse::<u64>().ok();
        let version = Self(next()?, next()?, next()?);
        parts.next().is_none().then_some(version)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// Version of the running program.
pub fn current() -> Version {
    Version::parse(CURRENT).expect("the crate version is X.Y.Z")
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    UpToDate { current: Version, latest: Version },
    Updated { from: Version, to: Version },
}

/// Installs the latest release over `target` if it is newer than `current`. The caller restarts the daemon.
pub async fn run(current: Version, config: &Path, target: &Path) -> Result<Outcome> {
    let latest = latest().await?;
    if latest <= current {
        return Ok(Outcome::UpToDate { current, latest });
    }
    let dir = work_dir()?;
    let installed = async {
        let new = fetch(latest, &dir).await?;
        accepts_config(&new, config).await?;
        install_binary(&new, target)
    }
    .await;
    let _ = fs::remove_dir_all(&dir);
    installed.map(|()| Outcome::Updated { from: current, to: latest })
}

/// The newest published release, read from where `releases/latest` redirects: no API, no token, no rate limit.
pub async fn latest() -> Result<Version> {
    let url = format!("{REPO_URL}/releases/latest");
    let mut args = CURL_BASE.to_vec();
    args.extend(["-I", "-o", "/dev/null", "-w", "%{url_effective}", "--max-time", "30", url.as_str()]);
    let effective = output(CURL, &args, CHECK_TIMEOUT).await.context("looking up the latest release")?;
    version_from_release_url(effective.trim())
}

fn version_from_release_url(url: &str) -> Result<Version> {
    let tag = url
        .strip_prefix(REPO_URL)
        .and_then(|rest| rest.strip_prefix("/releases/tag/"))
        .with_context(|| format!("unexpected release location {url:?}"))?;
    Version::parse(tag).with_context(|| format!("release tag {tag:?} is not vX.Y.Z"))
}

/// Downloads the release into `dir` and returns the verified binary.
pub async fn fetch(version: Version, dir: &Path) -> Result<PathBuf> {
    let base = format!("{REPO_URL}/releases/download/v{version}");
    let archive = dir.join(ASSET);
    let sums = dir.join(format!("{ASSET}.sha256"));
    download(&format!("{base}/{ASSET}"), &archive).await?;
    download(&format!("{base}/{ASSET}.sha256"), &sums).await?;
    let checksums = fs::read_to_string(&sums).context("reading the checksum file")?;
    unpack(&archive, &checksums, dir, version).await
}

async fn download(url: &str, dest: &Path) -> Result<()> {
    let mut args = CURL_BASE.to_vec();
    args.extend(["--max-time", "300", "--max-filesize", "104857600", "-o", path_str(dest)?, url]);
    output(CURL, &args, DOWNLOAD_TIMEOUT).await.with_context(|| format!("downloading {url}"))?;
    Ok(())
}

/// Checks the archive against its checksum file, extracts the one expected member and makes sure it is a
/// regular file that reports the announced version.
async fn unpack(archive: &Path, checksums: &str, dir: &Path, version: Version) -> Result<PathBuf> {
    let want = digest(checksums).context("the checksum file is malformed")?;
    let printed = output(SHASUM, &["-a", "256", path_str(archive)?], TOOL_TIMEOUT).await?;
    let got = digest(&printed).context("shasum printed no digest")?;
    if got != want {
        bail!("checksum mismatch: expected {want}, got {got}");
    }
    let bin = dir.join(MEMBER);
    let _ = fs::remove_file(&bin);
    // Only the named member, without the archive's owner: nothing else in it can land on disk.
    let args = ["-xzf", path_str(archive)?, "--no-same-owner", "-C", path_str(dir)?, MEMBER];
    output(TAR, &args, TOOL_TIMEOUT).await.context("extracting the archive")?;
    let meta = fs::symlink_metadata(&bin).context("the archive has no vpnchecker binary")?;
    if !meta.file_type().is_file() {
        bail!("the archive member is not a regular file");
    }
    fs::set_permissions(&bin, Permissions::from_mode(0o755))?;
    let reported = binary_version(&bin).await?;
    if reported != version {
        bail!("the downloaded binary reports {reported}, expected {version}");
    }
    Ok(bin)
}

/// First field of `shasum` output or of a `.sha256` file.
fn digest(text: &str) -> Option<String> {
    let digest = text.split_whitespace().next()?.to_ascii_lowercase();
    (digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())).then_some(digest)
}

/// What `<bin> --version` reports.
pub async fn binary_version(bin: &Path) -> Result<Version> {
    let printed = output(path_str(bin)?, &["--version"], TOOL_TIMEOUT).await?;
    printed
        .split_whitespace()
        .last()
        .and_then(Version::parse)
        .with_context(|| format!("unexpected version output {:?}", printed.trim()))
}

/// A release whose config schema rejects the current config would leave launchd restarting a daemon that
/// cannot start, so such a release is not installed.
async fn accepts_config(bin: &Path, config: &Path) -> Result<()> {
    let args = ["--config", path_str(config)?, "config", "validate"];
    output(path_str(bin)?, &args, TOOL_TIMEOUT)
        .await
        .context("the new version rejects the current config, not installing it")?;
    Ok(())
}

/// Puts `new` in place of `target`. Renamed, never overwritten: the running daemon keeps its file, and a
/// crash in between leaves either the old or the new binary, never half of one.
fn install_binary(new: &Path, target: &Path) -> Result<()> {
    let staged = target.with_extension("new");
    let _ = fs::remove_file(&staged);
    fs::copy(new, &staged).context("staging the new binary")?;
    if sys::is_root() {
        chown(&staged, Some(Uid::from_raw(0)), Some(Gid::from_raw(0))).context("chown binary")?;
    }
    fs::set_permissions(&staged, Permissions::from_mode(0o755))?;
    fs::rename(&staged, target).context("replacing the binary")?;
    Ok(())
}

fn work_dir() -> Result<PathBuf> {
    let dir = PathBuf::from(WORK_DIR);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).with_context(|| format!("creating {WORK_DIR}"))?;
    fs::set_permissions(&dir, Permissions::from_mode(0o700))?;
    Ok(dir)
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str().with_context(|| format!("non-UTF-8 path {}", path.display()))
}

async fn output(program: &str, args: &[&str], limit: Duration) -> Result<String> {
    let run = Command::new(program).args(args).stdin(Stdio::null()).kill_on_drop(true).output();
    let out = timeout(limit, run)
        .await
        .with_context(|| format!("{program} timed out"))?
        .with_context(|| format!("running {program}"))?;
    if !out.status.success() {
        bail!("{program} failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vpnchecker-update-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sh(program: &str, args: &[&str]) -> String {
        let out = std::process::Command::new(program).args(args).output().unwrap();
        assert!(out.status.success(), "{program} {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// An archive holding `vpnchecker`, plus the text of its checksum file.
    fn archive(dir: &Path, name: &str, make_member: impl FnOnce(&Path)) -> (PathBuf, String) {
        let src = dir.join(format!("{name}-src"));
        fs::create_dir_all(&src).unwrap();
        make_member(&src.join(MEMBER));
        let archive = dir.join(format!("{name}.tar.gz"));
        sh(TAR, &["-C", src.to_str().unwrap(), "-czf", archive.to_str().unwrap(), MEMBER]);
        let sums = sh(SHASUM, &["-a", "256", archive.to_str().unwrap()]);
        (archive, sums)
    }

    fn fake_binary(path: &Path) {
        fs::write(path, "#!/bin/sh\necho vpnchecker 9.9.9\n").unwrap();
        fs::set_permissions(path, Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn versions_parse_and_order() {
        assert_eq!(Version::parse("v0.1.2"), Some(Version(0, 1, 2)));
        assert_eq!(Version::parse(" 1.20.3\n"), Some(Version(1, 20, 3)));
        assert_eq!(Version::parse(CURRENT), Some(current()));
        for bad in ["", "v1.2", "1.2.3.4", "v1.2.3-rc1", "1.2.x", "latest", "v-1.2.3"] {
            assert_eq!(Version::parse(bad), None, "{bad:?}");
        }
        assert!(Version(0, 1, 10) > Version(0, 1, 9), "numeric, not lexical");
        assert!(Version(1, 0, 0) > Version(0, 99, 99));
        assert_eq!(Version(0, 1, 2).to_string(), "0.1.2");
    }

    #[test]
    fn latest_version_comes_from_the_release_redirect() {
        let url = format!("{REPO_URL}/releases/tag/v0.1.3");
        assert_eq!(version_from_release_url(&url).unwrap(), Version(0, 1, 3));
        for bad in [
            format!("{REPO_URL}/releases"),
            format!("{REPO_URL}/releases/tag/v0.2.0-rc1"),
            "https://github.com/someone/else/releases/tag/v9.9.9".to_string(),
            format!("{REPO_URL}.evil.example/releases/tag/v9.9.9"),
            "https://github.com/login".to_string(),
        ] {
            assert!(version_from_release_url(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn digests() {
        let hex = "aaa4cc7a7207b515763aff95fd51de4d597de861484d73800929b5846224184f";
        assert_eq!(digest(&format!("{hex}  vpnchecker-macos-universal.tar.gz\n")).as_deref(), Some(hex));
        assert_eq!(digest(&hex.to_ascii_uppercase()).as_deref(), Some(hex));
        for bad in ["", "abc", &hex[1..], &format!("{}g", &hex[1..]), "not found"] {
            assert_eq!(digest(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn replaces_the_binary_by_rename() {
        let dir = tmp("install");
        let (new, target) = (dir.join("new"), dir.join("vpnchecker"));
        fs::write(&target, "old").unwrap();
        fs::write(&new, "new").unwrap();
        install_binary(&new, &target).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "new");
        assert_eq!(fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o755);
        assert!(!dir.join("vpnchecker.new").exists(), "nothing staged is left behind");
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn unpacks_only_a_verified_binary_of_the_announced_version() {
        let dir = tmp("unpack");
        let out = dir.join("out");
        fs::create_dir_all(&out).unwrap();
        let (good, sums) = archive(&dir, "good", fake_binary);

        let bin = unpack(&good, &sums, &out, Version(9, 9, 9)).await.unwrap();
        assert_eq!(binary_version(&bin).await.unwrap(), Version(9, 9, 9));

        let err = unpack(&good, &sums, &out, Version(9, 9, 8)).await.unwrap_err();
        assert!(format!("{err:#}").contains("reports 9.9.9"), "{err:#}");

        let wrong = format!("{}  good.tar.gz\n", "0".repeat(64));
        let err = unpack(&good, &wrong, &out, Version(9, 9, 9)).await.unwrap_err();
        assert!(format!("{err:#}").contains("checksum mismatch"), "{err:#}");
        assert!(unpack(&good, "garbage", &out, Version(9, 9, 9)).await.is_err());

        let (link, link_sums) = archive(&dir, "link", |member| std::os::unix::fs::symlink("/bin/sh", member).unwrap());
        let err = unpack(&link, &link_sums, &out, Version(9, 9, 9)).await.unwrap_err();
        assert!(format!("{err:#}").contains("not a regular file"), "{err:#}");
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_binary_that_rejects_the_config_is_not_accepted() {
        let dir = tmp("config");
        let (ok, bad) = (dir.join("ok"), dir.join("bad"));
        fs::write(&ok, "#!/bin/sh\nexit 0\n").unwrap();
        fs::write(&bad, "#!/bin/sh\necho 'unknown field' >&2\nexit 2\n").unwrap();
        for bin in [&ok, &bad] {
            fs::set_permissions(bin, Permissions::from_mode(0o755)).unwrap();
        }
        let config = dir.join("config.yaml");
        assert!(accepts_config(&ok, &config).await.is_ok());
        let err = accepts_config(&bad, &config).await.unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"), "{err:#}");
        let _ = fs::remove_dir_all(dir);
    }

    /// Run with `cargo test -- --ignored`: downloads and verifies the real v0.1.2 release.
    #[tokio::test]
    #[ignore = "network"]
    async fn fetches_a_real_release() {
        let dir = tmp("fetch");
        assert!(latest().await.unwrap() >= Version(0, 1, 2));
        let bin = fetch(Version(0, 1, 2), &dir).await.unwrap();
        assert_eq!(binary_version(&bin).await.unwrap(), Version(0, 1, 2));
        let _ = fs::remove_dir_all(dir);
    }
}
