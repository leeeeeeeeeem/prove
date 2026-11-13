"""A3: XTest injection (xdotool) while a prompt is open. PROVE does not block XTest; the
prompt is immune because the helper reads evdev, not the display server."""
from harness import Prompt, brief

ID, TITLE = "A3", "XTest key (xdotool) at the prompt"
EXPECT = {m: "injection not blocked, prompt not approved" for m in ("audit", "enforce")}

def run(vm, mode):
    vm.sh("pkill -x Xvfb; (Xvfb :99 >/dev/null 2>&1 &); sleep 1")
    try:
        with Prompt(vm) as p:
            rc, out = vm.sh(f"DISPLAY=:99 xdotool key {p.key['x11']} && echo xdotool-ok")
            res = p.finish()
    finally:
        vm.sh("pkill -x Xvfb")
    ok = "xdotool-ok" in out and res["verdict"] != "approved"
    return ok, f"xdotool: {'sent' if 'xdotool-ok' in out else brief(out)}; prompt: {res['verdict']}", {"result": res}
