//! prove-requester-demo: a minimal requester for the PROVE consent contract (SPEC 8.5).
//!
//! It stands in for a polkit agent or an AI agent harness's permission layer: it asks
//! `provd` for consent to one action, shows the action and the challenge key, and reports
//! the verdict. Exit status: 0 approved, 2 denied, 3 timeout, 4 error.

use std::{
    io::{IsTerminal as _, Write as _},
    os::unix::net::UnixStream,
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use prove_common::user::{
    CONSENT_SOCK,
    proto::{
        ClientMsg, PromptMode, ServerMsg, Verdict, challenge_key_by_name, read_msg, sha256_hex,
        write_msg,
    },
};
use serde_json::json;

const USAGE: &str = "usage: prove-requester-demo [--mode physical|assistive] [--json] [--socket PATH] ACTION
  ACTION   text describing what is being approved
  --json   print one JSON object per protocol step instead of the terminal prompt";

struct Args {
    mode: PromptMode,
    json: bool,
    socket: String,
    action: String,
}

fn parse_args() -> Result<Args> {
    let mut a = Args {
        mode: PromptMode::Physical,
        json: false,
        socket: CONSENT_SOCK.to_string(),
        action: String::new(),
    };
    let mut it = std::env::args().skip(1);
    let mut words = Vec::new();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--mode" => {
                a.mode = match it.next().as_deref() {
                    Some("physical") => PromptMode::Physical,
                    Some("assistive") => PromptMode::Assistive,
                    _ => bail!("{USAGE}"),
                }
            }
            "--json" => a.json = true,
            "--socket" => a.socket = it.next().context(USAGE)?,
            "-h" | "--help" => bail!("{USAGE}"),
            _ => words.push(arg),
        }
    }
    if words.is_empty() {
        bail!("{USAGE}");
    }
    a.action = words.join(" ");
    Ok(a)
}

fn expiry_line(secs: u64) -> String {
    format!("Anything else is ignored; the request expires in {secs} s.")
}

/// The terminal prompt: a box whose width fits the longest line.
#[derive(Clone, Copy)]
struct PromptBox {
    width: usize,
}

impl PromptBox {
    const TITLE: &str = "─ PROVE consent request ";
    const MIN_WIDTH: usize = 62;

    fn new(lines: &[String]) -> Self {
        let longest = lines.iter().map(|l| l.chars().count()).max().unwrap_or(0);
        Self { width: Self::MIN_WIDTH.max(longest + 2) }
    }

    fn row(&self, text: &str) -> String {
        // Inside the borders: one space, the text, padding, one space.
        let pad = self.width.saturating_sub(text.chars().count() + 2);
        format!("│ {text}{} │", " ".repeat(pad))
    }

    fn print(&self, lines: &[String]) {
        let fill = self.width - Self::TITLE.chars().count();
        println!("┌{}{}┐", Self::TITLE, "─".repeat(fill));
        for l in lines {
            println!("{}", self.row(l));
        }
        println!("└{}┘", "─".repeat(self.width));
    }
}

/// Rewrites the expiry line (the last row inside the box) once a second.
struct Countdown {
    stop: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

impl Countdown {
    fn start(prompt: PromptBox, timeout_ms: u64) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let handle = std::thread::spawn(move || {
            let mut shown = timeout_ms.div_ceil(1000);
            while !flag.load(Ordering::Relaxed) {
                let left = deadline.saturating_duration_since(Instant::now()).as_millis() as u64;
                let secs = left.div_ceil(1000);
                if secs != shown {
                    shown = secs;
                    let mut out = std::io::stdout().lock();
                    // Up two lines (past the bottom border), rewrite, back down.
                    let _ = write!(out, "\x1b[2A\r{}\x1b[2B\r", prompt.row(&expiry_line(secs)));
                    let _ = out.flush();
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        Self { stop, handle }
    }

    fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.handle.join();
    }
}

fn run(args: &Args) -> Result<Verdict> {
    let mut nonce_bytes = [0u8; 16];
    getrandom::fill(&mut nonce_bytes).map_err(|e| anyhow::anyhow!("CSPRNG failure: {e}"))?;
    let nonce: String = nonce_bytes.iter().map(|b| format!("{b:02x}")).collect();
    let action_hash = sha256_hex(args.action.as_bytes());

    let mut sock = UnixStream::connect(&args.socket)
        .with_context(|| format!("connecting to {} (is provd running?)", args.socket))?;
    write_msg(
        &mut sock,
        &ClientMsg::Request { nonce: nonce.clone(), action: args.action.clone(), mode: args.mode },
    )?;

    let mut countdown: Option<Countdown> = None;
    loop {
        match read_msg::<_, ServerMsg>(&mut sock).context("reading from provd")? {
            ServerMsg::Challenge { key, timeout_ms } => {
                let label = challenge_key_by_name(&key).map(|k| k.label).unwrap_or(&key);
                if args.json {
                    println!(
                        "{}",
                        json!({"event": "challenge", "key": key, "label": label, "timeout_ms": timeout_ms})
                    );
                } else {
                    let how = match args.mode {
                        PromptMode::Physical => "on a physical keyboard",
                        PromptMode::Assistive => "on your keyboard (assistive tools accepted)",
                    };
                    let lines = [
                        format!("requester : prove-requester-demo (pid {})", std::process::id()),
                        format!("action    : {}", args.action),
                        String::new(),
                        format!("To approve, press  [ {label} ]  {how}."),
                        expiry_line(timeout_ms.div_ceil(1000)),
                    ];
                    let prompt = PromptBox::new(&lines);
                    prompt.print(&lines);
                    if std::io::stdout().is_terminal() {
                        countdown = Some(Countdown::start(prompt, timeout_ms));
                    }
                }
            }
            ServerMsg::Result { nonce: got_nonce, action_sha256, verdict, reason } => {
                // An approval only counts if it is bound to this request.
                let bound = got_nonce == nonce && action_sha256 == action_hash;
                let verdict = match verdict {
                    Verdict::Approved if !bound => Verdict::Error,
                    v => v,
                };
                let reason =
                    if bound || verdict != Verdict::Error { reason } else { format!("{reason} (result not bound to this request)") };
                if args.json {
                    println!(
                        "{}",
                        json!({"event": "result", "verdict": verdict.as_str(), "reason": reason})
                    );
                } else {
                    if let Some(c) = countdown.take() {
                        c.stop();
                    }
                    println!("verdict: {} ({reason})", verdict.as_str().to_uppercase());
                }
                return Ok(verdict);
            }
        }
    }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(64);
        }
    };
    match run(&args) {
        Ok(Verdict::Approved) => ExitCode::SUCCESS,
        Ok(Verdict::Denied) => ExitCode::from(2),
        Ok(Verdict::Timeout) => ExitCode::from(3),
        Ok(Verdict::Error) => ExitCode::from(4),
        Err(e) => {
            if args.json {
                println!("{}", json!({"event": "result", "verdict": "error", "reason": format!("{e:#}")}));
            } else {
                eprintln!("error: {e:#}");
            }
            ExitCode::from(4)
        }
    }
}
