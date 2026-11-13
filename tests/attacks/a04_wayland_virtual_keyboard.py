"""A4: Wayland virtual-keyboard injection (wtype) while a prompt is open. Runs against a
headless wlroots compositor (sway); GNOME does not implement the protocol wtype uses."""
from harness import Prompt, brief

ID, TITLE = "A4", "Wayland virtual keyboard (wtype) at the prompt"
EXPECT = {m: "injection not blocked, prompt not approved" for m in ("audit", "enforce")}
ENV = "XDG_RUNTIME_DIR=/run/user/$(id -u)"

def run(vm, mode):
    vm.sh(f"pkill -x sway; rm -f /run/user/$(id -u)/wayland-*; "
          f"({ENV} WLR_BACKENDS=headless WLR_LIBINPUT_NO_DEVICES=1 sway -c /dev/null >/dev/null 2>&1 &); sleep 2")
    try:
        with Prompt(vm) as p:
            rc, out = vm.sh(f"export {ENV}; export WAYLAND_DISPLAY=$(basename $(ls $XDG_RUNTIME_DIR/wayland-? | head -1)); "
                            f"wtype -k {p.key['x11']} && echo wtype-ok")
            res = p.finish()
    finally:
        vm.sh("pkill -x sway")
    ok = "wtype-ok" in out and res["verdict"] != "approved"
    return ok, f"wtype: {'sent' if 'wtype-ok' in out else brief(out)}; prompt: {res['verdict']}", {"result": res}
