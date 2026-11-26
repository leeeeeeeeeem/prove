"""Host-side test harness for PROVE: drives the VM over SSH and QMP.

The SSH user is the unprivileged "desktop user" of the threat model (no group `input`).
It has passwordless sudo, which only the harness itself uses (`sudo=True`); attack scripts
never do.
"""
import json, os, shlex, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "vm"))
from qmp import Qmp  # noqa: E402

SSH_PORT = os.environ.get("SSH_PORT", "2222")
SSH_KEY = os.environ.get("SSH_KEY", os.path.expanduser("~/.ssh/id_ed25519"))
VM_USER = "user"
LIB = "~/prove/tests/lib"

def default_out():
    """Where the runners write their JSON unless --out is given: results/<today>/."""
    return os.path.join(ROOT, "results", time.strftime("%Y-%m-%d"))

def _key(name, code, qcode, hid, x11):
    return {"name": name, "code": code, "qcode": qcode, "hid": hid, "x11": x11}

# Challenge key table: evdev code, QMP qcode, HID usage, X11/xkb keysym name.
KEYS = {}
for i in range(1, 13):
    KEYS[f"KEY_F{i}"] = _key(f"KEY_F{i}", [59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 87, 88][i - 1],
                             f"f{i}", 0x3A + i - 1, f"F{i}")
for i in range(1, 10):
    KEYS[f"KEY_{i}"] = _key(f"KEY_{i}", 1 + i, str(i), 0x1E + i - 1, str(i))
KEYS["KEY_0"] = _key("KEY_0", 11, "0", 0x27, "0")

# The emulated "physical" keyboards and how to (re)plug them.
KEYBOARDS = {
    "usbkbd0": ("usb-kbd", {"bus": "xhci0.0"}),
    "usbkbd1": ("usb-kbd", {"bus": "xhci1.0"}),
    "viokbd0": ("virtio-keyboard-pci", {"bus": "hp0"}),
}

class VM:
    def __init__(self):
        ctl = os.path.join(ROOT, "vm", "run", "ssh-ctl")
        self.ssh = ["ssh", "-p", SSH_PORT, "-i", SSH_KEY, "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
                    "-o", "ControlMaster=auto", "-o", f"ControlPath={ctl}", "-o", "ControlPersist=120",
                    f"{VM_USER}@127.0.0.1"]
        self._qmp = None

    # ---- shell ----
    def _wrap(self, cmd, sudo):
        return f"sudo bash -c {shlex.quote(cmd)}" if sudo else cmd

    def sh(self, cmd, sudo=False, timeout=120):
        """Run a command in the VM. Returns (exit status, stdout+stderr)."""
        r = subprocess.run(self.ssh + [self._wrap(cmd, sudo)], capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout + r.stderr

    def popen(self, cmd, sudo=False, stdin=False):
        return subprocess.Popen(self.ssh + [self._wrap(cmd, sudo)], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,
                                text=True, bufsize=1)

    def attacker(self, script_and_args, timeout=60):
        """Run one of tests/lib/*.py as the unprivileged user."""
        return self.sh(f"python3 {LIB}/{script_and_args}", timeout=timeout)

    def attacker_bg(self, script_and_args, stdin=False):
        return self.popen(f"python3 -u {LIB}/{script_and_args}", stdin=stdin)

    # ---- PROVE state ----
    def mode(self, mode):
        rc, out = self.sh(f"provectl mode {mode}", sudo=True)
        assert rc == 0, out

    def get_mode(self):
        _, out = self.sh("provectl status", sudo=True)
        for line in out.splitlines():
            if line.startswith("mode:"):
                return line.split()[1]
        return None

    def set_consent_timeout(self, ms):
        """Write consent_timeout_ms into provd.toml. Takes effect on the next restart_provd."""
        rc, out = self.sh(f"sed -i 's/^consent_timeout_ms = .*/consent_timeout_ms = {int(ms)}/' /etc/prove/provd.toml",
                          sudo=True)
        assert rc == 0, out

    def restart_provd(self, mode):
        rc, out = self.sh("systemctl restart provd", sudo=True)
        assert rc == 0, out
        self.mode(mode)

    def devices(self):
        """Provenance records as a list of dicts (keys are lower-case column names)."""
        rc, out = self.sh("provectl devices --tsv", sudo=True)
        assert rc == 0, out
        lines = out.strip().splitlines()
        cols = [c.lower() for c in lines[0].split("\t")]
        return [dict(zip(cols, l.split("\t"))) for l in lines[1:]]

    def wait_devices(self, pred, timeout=20):
        end = time.time() + timeout
        while True:
            devs = self.devices()
            if pred(devs):
                return devs
            if time.time() > end:
                raise TimeoutError("device condition not reached")
            time.sleep(0.3)

    def journal_cursor(self):
        _, out = self.sh("journalctl -t prove -n 0 --show-cursor --no-pager | tail -1", sudo=True)
        return out.strip().removeprefix("-- cursor: ")

    def journal_since(self, cursor):
        _, out = self.sh(f"journalctl -t prove --no-pager -o cat --after-cursor={shlex.quote(cursor)}", sudo=True)
        return out

    def info(self):
        _, kernel = self.sh("uname -r")
        return {"kernel": kernel.strip()}

    # ---- hypervisor ("physical") input ----
    @property
    def qmp(self):
        if self._qmp is None:
            self._qmp = Qmp()
        return self._qmp

    def press(self, key):
        """Press a key on the emulated hardware. `key` is a KEYS entry or a qcode."""
        self.qmp.key(key["qcode"] if isinstance(key, dict) else key)

    def unplug(self, dev_id):
        self.qmp.cmd("device_del", id=dev_id)

    def plug(self, dev_id, driver, props, timeout=30):
        end = time.time() + timeout
        while True:
            try:
                self.qmp.cmd("device_add", driver=driver, id=dev_id, **props)
                return
            except RuntimeError as e:  # the old instance may still be going away
                if "Duplicate" not in str(e) and "in use" not in str(e) or time.time() > end:
                    raise
                time.sleep(0.5)

    def keyboards(self, devs=None):
        return [d for d in (devs or self.devices()) if d["class"] == "hardware" and "Keyboard" in d["name"]]


class Prompt:
    """One consent request made through the listed demo requester."""

    def __init__(self, vm, mode="physical", action="harness test action"):
        self.vm = vm
        self.proc = vm.popen(f"prove-requester-demo --json --mode {mode} {shlex.quote(action)}")
        first = self._read()
        self.result = first if first.get("event") == "result" else None
        self.key = KEYS.get(first.get("key")) if self.result is None else None
        if self.key:
            time.sleep(0.6)  # let the helper finish grabbing before anything is pressed

    def _read(self):
        line = self.proc.stdout.readline()
        if not line:
            return {"event": "result", "verdict": "error", "reason": "requester produced no output"}
        return json.loads(line)

    def finish(self):
        """Wait for the verdict. Returns the result dict (verdict, reason)."""
        if self.result is None:
            self.result = self._read()
        self.proc.wait(timeout=30)
        return self.result

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if self.proc.poll() is None:
            self.proc.kill()
        return False


def lines(out):
    return [l.strip() for l in out.strip().splitlines() if l.strip()]

def brief(out):
    return "; ".join(lines(out)) or "(no output)"
