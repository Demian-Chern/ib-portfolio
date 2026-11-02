#!/usr/bin/env python3
"""angr solver for the hiCTF Sentinel Gateway challenge.

Run in Kali:
    python3 -m venv .venv && source .venv/bin/activate
    pip install angr
    python3 solve.py ./challenge

The accepted input is 47 bytes: b"hiCTF{" + 40 printable bytes + b"}".
"""
import sys
import time
import angr
import claripy

BIN = sys.argv[1] if len(sys.argv) > 1 else "./challenge"
ENTRY = 0x4010C0
SUCCESS = 0x401E24
FAIL = [0x401538, 0x401575, 0x401570]


def main():
    proj = angr.Project(BIN, auto_load_libs=True)

    # fgets() receives 47 printable input bytes followed by a newline.
    # fgets adds the terminating NUL itself.
    raw = claripy.BVS("passkey", 48 * 8)
    stdin_bytes = [raw.get_byte(i) for i in range(48)]

    content = claripy.Concat(*stdin_bytes)
    simfile = angr.SimFileStream(name="stdin", content=content, has_end=True)
    state = proj.factory.entry_state(
        addr=ENTRY,
        stdin=simfile,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            angr.options.LAZY_SOLVES,
        },
    )

    # Exact framing and length. The newline is consumed by fgets; the
    # validator strips it before checking the 47-byte passkey.
    state.solver.add(raw.get_byte(0) == ord('h'))
    state.solver.add(raw.get_byte(1) == ord('i'))
    state.solver.add(raw.get_byte(2) == ord('C'))
    state.solver.add(raw.get_byte(3) == ord('T'))
    state.solver.add(raw.get_byte(4) == ord('F'))
    state.solver.add(raw.get_byte(5) == ord('{'))
    state.solver.add(raw.get_byte(45) == ord('}'))
    state.solver.add(raw.get_byte(46) == 0x0a)

    # Keep the unknown part printable. Avoid newline, NUL and braces so the
    # input cannot be truncated or accidentally change the framing.
    for i in range(6, 45):
        c = raw.get_byte(i)
        state.solver.add(c >= 0x21, c <= 0x7e)
        state.solver.add(c != ord('{'), c != ord('}'))

    # The success block is reached only after the validator's arithmetic
    # checks. Failure blocks print "Access Denied".
    sm = proj.factory.simulation_manager(state, save_unsat=True)
    start = time.time()
    print(f"[*] Searching for success at {SUCCESS:#x} ...", flush=True)
    sm.explore(find=SUCCESS, avoid=FAIL)
    print(f"[*] Exploration finished in {time.time() - start:.1f}s")

    if not sm.found:
        print("[-] No solution found.")
        print("    Try increasing angr's resources or inspect any unconstrained paths.")
        print(f"    active={len(sm.active)} deadended={len(sm.deadended)}")
        return 1

    found = sm.found[0]
    answer = found.solver.eval(raw, cast_to=bytes)
    # The first 47 bytes are the passkey; byte 47 is the input newline.
    passkey = answer[:47]
    print("[+] PASSKEY:", passkey.decode("ascii", errors="replace"))
    print("[+] HEX:    ", passkey.hex())

    # Verify with the original executable outside angr.
    print("\n[*] Verify with:")
    print("    printf '%s\\n' '" + passkey.decode("ascii") + "' | ./challenge")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
