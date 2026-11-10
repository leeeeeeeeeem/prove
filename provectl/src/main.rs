//! provectl: root CLI for PROVE. See SPEC.md section 8.4.

use std::{fs, os::unix::process::CommandExt, process::Command};

use anyhow::{Context as _, Result, bail};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use prove_common::{
    ABI_VERSION, Creator, PIN_DIR, allow, class, mode,
    user::{JOURNAL_ID, PID_FILE, comm_str, exe, maps, sysfs},
};

const USAGE: &str = "usage: provectl <command>
  status                 mode, pins, daemon and allow-list state
  devices [--tsv]        provenance record of every input device
  mode audit|enforce     switch the enforcement mode
  reload                 make provd re-read the allow-lists
  unload                 detach and unpin everything (removes enforcement)
  log [journalctl args]  follow PROVE audit records";

fn provd_pid() -> Option<Pid> {
    let pid: i32 = fs::read_to_string(PID_FILE).ok()?.trim().parse().ok()?;
    let pid = Pid::from_raw(pid);
    kill(pid, None).ok().map(|_| pid)
}

fn describe_exe(c: &Creator) -> String {
    if c.exe.is_unknown() {
        return "-".into();
    }
    match exe::exe_of_pid(c.tgid) {
        Ok((live, path)) if live == c.exe => path,
        _ => exe::fmt_exe_id(&c.exe),
    }
}

fn status() -> Result<()> {
    let lsm = fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    let lsm_active = lsm.trim().split(',').any(|l| l == "bpf");
    println!("bpf lsm:     {}", if lsm_active { "active" } else { "NOT ACTIVE" });
    match provd_pid() {
        Some(pid) => println!("provd:       running (pid {pid})"),
        None => println!("provd:       not running"),
    }
    if !maps::pins_present() {
        println!("pins:        none ({PIN_DIR} is empty: PROVE is not loaded)");
        return Ok(());
    }
    let cfg = maps::read_config()?;
    let mut pins: Vec<String> = fs::read_dir(PIN_DIR)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    pins.sort();
    let links = pins.iter().filter(|p| p.starts_with("link_")).count();
    println!("pins:        {PIN_DIR} ({links} attached programs)");
    println!(
        "abi:         {}{}",
        cfg.abi,
        if cfg.abi == ABI_VERSION { "" } else { " (MISMATCH with this provectl)" }
    );
    println!("mode:        {}", if cfg.mode == mode::ENFORCE { "enforce" } else { "audit" });
    println!("devices:     {}", maps::devices()?.keys().count());
    println!("grabs:       {}", maps::grabs()?.keys().count());
    let allow_map = maps::allow_inject()?;
    println!("allow-list:  {} executable(s)", allow_map.keys().count());
    for item in allow_map.iter() {
        let (id, entry) = item?;
        let mut flags = Vec::new();
        if entry.flags & allow::INJECT != 0 {
            flags.push("inject");
        }
        if entry.flags & allow::ASSISTIVE != 0 {
            flags.push("assistive");
        }
        println!("  {}  [{}]", exe::fmt_exe_id(&id), flags.join(","));
    }
    Ok(())
}

fn devices(tsv: bool) -> Result<()> {
    let devs = maps::devices()?;
    let grabs = maps::grabs()?;
    let mut rows = Vec::new();
    for item in devs.iter() {
        let (n, rec) = item?;
        let c = &rec.creator;
        let holder = grabs
            .get(&n, 0)
            .ok()
            .map(|g| format!("{}({})", comm_str(&g.holder.comm), g.holder.tgid))
            .unwrap_or_else(|| "-".into());
        let (pid, uid, comm) = if c.is_unknown() {
            ("-".to_string(), "-".to_string(), "-".to_string())
        } else {
            (c.tgid.to_string(), c.uid.to_string(), comm_str(&c.comm))
        };
        rows.push((
            n,
            vec![
                format!("input{n}"),
                class::name(rec.class).to_string(),
                pid,
                uid,
                comm,
                describe_exe(c),
                holder,
                rec.inject_count.to_string(),
                sysfs::input_name(n),
            ],
        ));
    }
    rows.sort_by_key(|(n, _)| *n);
    let header = ["DEVICE", "CLASS", "PID", "UID", "COMM", "EXE", "GRAB", "INJECTED", "NAME"];
    if tsv {
        println!("{}", header.join("\t"));
        for (_, r) in &rows {
            println!("{}", r.join("\t"));
        }
        return Ok(());
    }
    let mut width: Vec<usize> = header.iter().map(|h| h.len()).collect();
    for (_, r) in &rows {
        for (i, cell) in r.iter().enumerate() {
            width[i] = width[i].max(cell.chars().count());
        }
    }
    let print = |cells: &[String]| {
        let line: Vec<String> =
            cells.iter().enumerate().map(|(i, c)| format!("{c:<w$}", w = width[i])).collect();
        println!("{}", line.join("  ").trim_end());
    };
    print(&header.map(String::from));
    for (_, r) in &rows {
        print(r);
    }
    Ok(())
}

fn set_mode(arg: Option<&str>) -> Result<()> {
    let wanted = match arg {
        Some("audit") => mode::AUDIT,
        Some("enforce") => mode::ENFORCE,
        _ => bail!("usage: provectl mode audit|enforce"),
    };
    if wanted == mode::ENFORCE {
        let lsm = fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
        if !lsm.trim().split(',').any(|l| l == "bpf") {
            bail!("BPF LSM is not active; enforce mode would have no effect");
        }
    }
    let mut cfg = maps::read_config().context("PROVE is not loaded")?;
    cfg.mode = wanted;
    maps::write_config(cfg)?;
    println!("mode: {}", arg.unwrap());
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str);
    if matches!(cmd, None | Some("-h" | "--help" | "help")) {
        println!("{USAGE}");
        return Ok(());
    }
    if !nix::unistd::geteuid().is_root() {
        bail!("provectl must run as root");
    }
    match cmd.unwrap() {
        "status" => status(),
        "devices" => devices(args.get(1).is_some_and(|a| a == "--tsv")),
        "mode" => set_mode(args.get(1).map(String::as_str)),
        "reload" => {
            let pid = provd_pid().context("provd is not running")?;
            kill(pid, Signal::SIGHUP)?;
            println!("reload requested (provd pid {pid})");
            Ok(())
        }
        "unload" => {
            if let Some(pid) = provd_pid() {
                let _ = kill(pid, Signal::SIGTERM);
            }
            maps::unload()?;
            println!("PROVE unloaded: programs detached, pins removed");
            Ok(())
        }
        "log" => {
            let mut c = Command::new("journalctl");
            c.args(["-t", JOURNAL_ID]);
            if args.len() > 1 {
                c.args(&args[1..]);
            } else {
                c.arg("-f");
            }
            Err(c.exec()).context("running journalctl")
        }
        other => bail!("unknown command {other:?}\n{USAGE}"),
    }
}
