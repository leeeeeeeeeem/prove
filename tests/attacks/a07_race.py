"""A7: race. The attacker continuously creates look-alike keyboards and presses every
possible challenge key while prompts are being set up and waited on."""
from harness import Prompt, brief

ID, TITLE = "A7", "device creation racing prompt set-up"
EXPECT = {"enforce": "no prompt approved (all creations denied)",
          "audit": "no prompt approved"}
ROUNDS = 3

def run(vm, mode):
    proc = vm.attacker_bg(f"race.py --duration {ROUNDS * 5 + 2}")
    verdicts = []
    for _ in range(ROUNDS):
        with Prompt(vm) as p:
            verdicts.append(p.finish()["verdict"])
    out = proc.stdout.read(); proc.wait(timeout=30)
    ok = "approved" not in verdicts and "race created=" in out
    if mode == "enforce":
        ok = ok and "created=0 " in out
    return ok, f"attacker: {brief(out)}; prompts: {verdicts}", {}
