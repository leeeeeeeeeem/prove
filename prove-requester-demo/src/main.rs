//! prove-requester-demo: a minimal requester for the PROVE consent contract (SPEC 8.5).
//!
//! It stands in for a polkit agent or an AI agent harness's permission layer: it asks
//! `provd` for consent to one action, shows the action and the challenge key, and reports
//! the verdict. Exit status: 0 approved, 2 denied, 3 timeout, 4 error.

use std::{os::unix::net::UnixStream, process::ExitCode};

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
                    println!("┌─ PROVE consent request ─────────────────────────────────────");
                    println!("│ requester : prove-requester-demo (pid {})", std::process::id());
                    println!("│ action    : {}", args.action);
                    println!("│");
                    println!("│ To approve, press  [ {label} ]  {how}.");
                    println!("│ Anything else is ignored; the request expires in {} s.", timeout_ms / 1000);
                    println!("└─────────────────────────────────────────────────────────────");
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
