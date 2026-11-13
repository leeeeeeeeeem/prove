"""A11: replace an allow-listed binary. The desktop user cannot; and if an administrator
lists a binary that others can write, the entry is rejected at load."""
from harness import brief

ID, TITLE = "A11", "replace an allow-listed binary"
EXPECT = {m: "replacement impossible; writable entry rejected" for m in ("audit", "enforce")}
HELPER = "/usr/libexec/prove-test/inject-helper"
WW = "/usr/libexec/prove-test/world-writable-tool"

def run(vm, mode):
    _, out = vm.sh(f"cp /bin/true {HELPER} 2>&1; echo cp=$?; (echo x >> {HELPER}) 2>&1; echo append=$?; "
                   f"mv {HELPER} {HELPER}.old 2>&1; echo mv=$?")
    user_blocked = "cp=0" not in out and "append=0" not in out and "mv=0" not in out

    cursor = vm.journal_cursor()
    vm.sh(f"cp /etc/prove/allow-inject.toml /tmp/allow.bak; cp {HELPER} {WW}; chmod 0777 {WW}; "
          f"printf '[[tool]]\\nname=\"ww\"\\npath=\"{WW}\"\\nsha256=\"%s\"\\nflags=[\"inject\"]\\n' "
          f"$(sha256sum {WW} | cut -d' ' -f1) >> /etc/prove/allow-inject.toml; provectl reload; sleep 1", sudo=True)
    log = vm.journal_since(cursor)
    _, typed = vm.sh(f"{WW} type 30")
    vm.sh(f"cp /tmp/allow.bak /etc/prove/allow-inject.toml; rm -f {WW} /tmp/allow.bak; provectl reload; sleep 0.5", sudo=True)
    rejected = "\"ww\"" in log and "rejected" in log and "writable" in log
    ok = user_blocked and rejected
    if mode == "enforce":
        ok = ok and "create EPERM" in typed
    return ok, f"user replace: {'blocked' if user_blocked else 'POSSIBLE'}; " \
               f"writable entry: {'rejected' if rejected else 'ACCEPTED'}; its use: {brief(typed)}", {"log": log}
