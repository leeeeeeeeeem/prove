//! Allow-lists: which executables may inject (`allow-inject.toml`) and which may ask for
//! consent (`requesters.toml`). Both use the same entry format and the same verification.

use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, bail};
use prove_common::{AllowEntry, ExeId, allow, user::exe::exe_id_of_metadata, user::maps};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize, Debug, Default)]
struct ListFile {
    #[serde(default)]
    tool: Vec<RawEntry>,
    #[serde(default)]
    requester: Vec<RawEntry>,
}

#[derive(Deserialize, Debug, Clone)]
struct RawEntry {
    name: String,
    path: PathBuf,
    sha256: String,
    #[serde(default)]
    flags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Verified {
    pub name: String,
    pub path: PathBuf,
    pub sha256: String,
    pub flags: u32,
    pub id: ExeId,
}

/// The verified contents of both lists.
#[derive(Debug, Default)]
pub struct Lists {
    pub tools: HashMap<ExeId, Verified>,
    pub requesters: HashMap<ExeId, Verified>,
}

impl Lists {
    pub fn describe(&self, id: &ExeId) -> Option<&Verified> {
        self.tools.get(id).or_else(|| self.requesters.get(id))
    }
}

fn root_owned_not_writable(md: &std::fs::Metadata, what: &Path) -> Result<()> {
    if md.uid() != 0 {
        bail!("{} is not owned by root", what.display());
    }
    if md.mode() & 0o022 != 0 {
        bail!("{} is writable by group or others", what.display());
    }
    Ok(())
}

/// Verify one entry: the file and every parent directory are root-owned and not writable
/// by group or others, and the SHA-256 matches. Identity is taken from the same open file
/// that was hashed.
fn verify(raw: &RawEntry) -> Result<Verified> {
    if !raw.path.is_absolute() {
        bail!("path is not absolute");
    }
    let path = std::fs::canonicalize(&raw.path).context("resolving path")?;
    let mut file = File::open(&path).context("opening")?;
    let md = file.metadata()?;
    if !md.is_file() {
        bail!("not a regular file");
    }
    root_owned_not_writable(&md, &path)?;
    let mut dir = path.parent();
    while let Some(d) = dir {
        root_owned_not_writable(&std::fs::metadata(d)?, d)?;
        dir = d.parent();
    }

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let got: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if !got.eq_ignore_ascii_case(raw.sha256.trim()) {
        bail!("sha256 mismatch (file has {got})");
    }

    let mut flags = 0;
    for f in &raw.flags {
        match f.as_str() {
            "inject" => flags |= allow::INJECT,
            "assistive" => flags |= allow::ASSISTIVE,
            other => bail!("unknown flag {other:?}"),
        }
    }
    Ok(Verified { name: raw.name.clone(), path, sha256: got, flags, id: exe_id_of_metadata(&md) })
}

fn load_file(path: &Path) -> Result<ListFile> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            // The list itself must not be attacker-writable either.
            root_owned_not_writable(&std::fs::metadata(path)?, path)?;
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ListFile::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn verify_all(entries: &[RawEntry], list: &str, log: &mut dyn FnMut(String)) -> HashMap<ExeId, Verified> {
    let mut out = HashMap::new();
    for raw in entries {
        match verify(raw) {
            Ok(v) => {
                out.insert(v.id, v);
            }
            Err(e) => log(format!("{list}: entry {:?} ({}) rejected: {e:#}", raw.name, raw.path.display())),
        }
    }
    out
}

/// Load and verify both lists. Rejected entries are reported through `log` and skipped;
/// an unreadable or unparsable file yields an empty list (fail closed).
pub fn load(tools_path: &Path, requesters_path: &Path, log: &mut dyn FnMut(String)) -> Lists {
    let tools = match load_file(tools_path) {
        Ok(f) => verify_all(&f.tool, "allow-inject", log),
        Err(e) => {
            log(format!("allow-inject list ignored: {e:#}"));
            HashMap::new()
        }
    };
    let requesters = match load_file(requesters_path) {
        Ok(f) => verify_all(&f.requester, "requesters", log),
        Err(e) => {
            log(format!("requesters list ignored: {e:#}"));
            HashMap::new()
        }
    };
    Lists { tools, requesters }
}

/// Make the kernel's `ALLOW_INJECT` map equal to the verified tool list.
pub fn sync_kernel(lists: &Lists) -> Result<()> {
    let mut map = maps::allow_inject()?;
    let stale: Vec<ExeId> =
        map.keys().filter_map(|k| k.ok()).filter(|k| !lists.tools.contains_key(k)).collect();
    for k in stale {
        let _ = map.remove(&k);
    }
    for v in lists.tools.values() {
        map.insert(v.id, AllowEntry { flags: v.flags }, 0)?;
    }
    Ok(())
}
