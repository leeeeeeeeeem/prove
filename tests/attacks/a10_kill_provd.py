"""A10: kill provd with SIGKILL, then inject and ask for consent."""
from harness import Prompt, brief

ID, TITLE = "A10", "kill provd, then inject"
EXPECT = {"enforce": "injection still denied; consent fails closed",
          "audit": "consent fails closed (injection allowed as in baseline)"}

def run(vm, mode):
    # Run provd outside systemd so that nothing restarts it after the kill.
    vm.sh("systemctl stop provd; rm -f /run/prove/consent.sock; (setsid /usr/bin/provd >/dev/null 2>&1 &); "
              "for i in $(seq 50); do test -S /run/prove/consent.sock && break; sleep 0.1; done", sudo=True)
    vm.mode(mode)
    vm.sh("pkill -9 -x provd; sleep 0.3", sudo=True)
    try:
        _, alive = vm.sh("pgrep -x provd || echo dead")
        _, out = vm.attacker("uinput_kbd.py --key 30 --hold 0.2")
        with Prompt(vm) as p:
            res = p.finish()
    finally:
        vm.restart_provd(mode)
    ok = "dead" in alive and res["verdict"] == "error"
    ok = ok and ("create EPERM" in out if mode == "enforce" else "wrote" in out)
    return ok, f"provd: {alive.strip()}; attacker: {brief(out)}; prompt: {res['verdict']}", {"result": res}
