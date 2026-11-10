use which::which;

/// Rebuild when the `bpf-linker` binary changes (it is an undeclared build dependency).
fn main() {
    let bpf_linker = which("bpf-linker").expect("bpf-linker not found in PATH");
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}
