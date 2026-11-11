//! Wire formats: the consent protocol between a requester and `provd` (SPEC 8.2), and the
//! private protocol between `provd` and its `prove-consent` helper.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

/// Upper bound for one consent message body.
pub const MAX_MSG: usize = 64 * 1024;
pub const MAX_ACTION_LEN: usize = 4096;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PromptMode {
    /// Only a key press on a device classed `hardware` approves.
    Physical,
    /// Additionally accepts the uinput device of an allow-listed assistive tool that holds
    /// the grab on the hardware keyboard.
    Assistive,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Approved,
    Denied,
    Timeout,
    Error,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Approved => "approved",
            Verdict::Denied => "denied",
            Verdict::Timeout => "timeout",
            Verdict::Error => "error",
        }
    }
}

/// requester -> provd
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum ClientMsg {
    Request { nonce: String, action: String, mode: PromptMode },
}

/// provd -> requester
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ServerMsg {
    Challenge { key: String, timeout_ms: u64 },
    Result { nonce: String, action_sha256: String, verdict: Verdict, reason: String },
}

/// Write one length-prefixed JSON message (u32 little-endian length + body).
pub fn write_msg<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let body = serde_json::to_vec(msg)?;
    let len = u32::try_from(body.len()).map_err(io::Error::other)?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

/// Read one length-prefixed JSON message.
pub fn read_msg<R: Read, T: DeserializeOwned>(r: &mut R) -> io::Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_MSG {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

pub fn valid_nonce(nonce: &str) -> bool {
    nonce.len() == 32 && nonce.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A key a prompt may ask for: protocol name, evdev code, and label for humans.
pub struct ChallengeKey {
    pub name: &'static str,
    pub code: u16,
    pub label: &'static str,
}

macro_rules! keys {
    ($(($name:literal, $code:literal, $label:literal)),* $(,)?) => {
        &[$(ChallengeKey { name: $name, code: $code, label: $label }),*]
    };
}

/// The fixed challenge set: F1..F12 and the digit row.
pub const CHALLENGE_KEYS: &[ChallengeKey] = keys![
    ("KEY_F1", 59, "F1"),
    ("KEY_F2", 60, "F2"),
    ("KEY_F3", 61, "F3"),
    ("KEY_F4", 62, "F4"),
    ("KEY_F5", 63, "F5"),
    ("KEY_F6", 64, "F6"),
    ("KEY_F7", 65, "F7"),
    ("KEY_F8", 66, "F8"),
    ("KEY_F9", 67, "F9"),
    ("KEY_F10", 68, "F10"),
    ("KEY_F11", 87, "F11"),
    ("KEY_F12", 88, "F12"),
    ("KEY_1", 2, "1"),
    ("KEY_2", 3, "2"),
    ("KEY_3", 4, "3"),
    ("KEY_4", 5, "4"),
    ("KEY_5", 6, "5"),
    ("KEY_6", 7, "6"),
    ("KEY_7", 8, "7"),
    ("KEY_8", 9, "8"),
    ("KEY_9", 10, "9"),
    ("KEY_0", 11, "0"),
];

pub fn challenge_key_by_name(name: &str) -> Option<&'static ChallengeKey> {
    CHALLENGE_KEYS.iter().find(|k| k.name == name)
}

// ---- provd <-> prove-consent (newline-delimited JSON over a socketpair) -----------------

/// First line, provd -> helper.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HelperParams {
    pub key_code: u16,
    pub timeout_ms: u64,
    pub mode: PromptMode,
}

/// helper -> provd
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum HelperMsg {
    /// Ask for the provenance record of `inputN`. Answered with [`DeviceReply`].
    Device { n: u64 },
    /// Ask who holds the evdev grab on `inputN`. Answered with [`GrabReply`].
    Grab { n: u64 },
    /// Final outcome; `device` is the input number the approving key came from.
    Done { verdict: Verdict, reason: String, device: Option<u64> },
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceInfo {
    pub class: u32,
    pub registered_ns: u64,
    pub inject_count: u64,
    /// (kernel dev, inode) of the creator's executable.
    pub creator_exe: (u32, u64),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceReply {
    pub record: Option<DeviceInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct HolderInfo {
    pub exe: (u32, u64),
    /// The holder's executable is allow-listed with the `assistive` flag.
    pub assistive: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GrabReply {
    pub holder: Option<HolderInfo>,
}

pub fn write_line<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let mut line = serde_json::to_vec(msg)?;
    line.push(b'\n');
    w.write_all(&line)?;
    w.flush()
}

pub fn parse_line<T: DeserializeOwned>(line: &str) -> io::Result<T> {
    serde_json::from_str(line.trim_end()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
