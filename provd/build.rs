use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

/// Nightly used for the BPF target; keep in sync with scripts/setup-vm.sh.
const EBPF_TOOLCHAIN: &str = "nightly-2026-11-13";

/// Builds `prove-ebpf` for the BPF target (pinned nightly + bpf-linker) and places the object in
/// `OUT_DIR/prove`, from where `provd` embeds it.
fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let cargo_metadata::Package { name, manifest_path, .. } = packages
        .into_iter()
        .find(|p| p.name.as_str() == "prove-ebpf")
        .ok_or_else(|| anyhow!("prove-ebpf package not found"))?;
    let package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([package], Toolchain::Custom(EBPF_TOOLCHAIN))
}
