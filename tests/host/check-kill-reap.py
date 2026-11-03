#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host check: env.MADEIRA_KILL_REAP in build/ntdll-unix/process_ios.c (NtTerminateProcess on another process's handle).

Why: a Windows process that another process ends never runs process_exit_wrapper, so its FEX code buffers (32 to 96 MB), guest window,
fd cache and child-table slot stay allocated. Ubisoft Connect's game starter ends the suspended copy of the game it could not
inject into this way in every session (12 of 12 logs on BCD 0.1.625, an iPhone), and the buffers then count against every later program's code-buffer budget.
The change calls ios_end_child_process_async (the teardown the storm guard already uses for a child ended from outside) after the
server accepted the kill. On by default, like the exit reclaim it completes; env.MADEIRA_KILL_REAP = 0 turns it off.

What this checks: (1) the pure decision function between `kill-reap-test:begin/end`, compiled with -Wall -Wextra -Werror and run over
its truth table; (2) the call order in NtTerminateProcess, as text: the target's PEB is read BEFORE the terminate_process request,
the reap runs after SERVER_END_REQ and before the `if (self)` block, only for a handle that is neither 0 nor the current process, and
only through ios_kill_reap_wanted.

NOT covered (process_ios.c does not build on a host, and none of this can be exercised without a phone): that the teardown is safe when
the victim's threads are still running, the master-socket close from the killer's thread, the fixed-base-image owner (excluded by the
predicate), the interaction with the server's own kill handling.
"""
from pathlib import Path
import shutil, subprocess, sys, tempfile

SRC = (Path(__file__).resolve().parents[2] / "build/ntdll-unix/process_ios.c").read_text()
ok = True


def check(what, cond, detail=""):
    global ok
    print(("ok   " if cond else "FAIL ") + what + (("\n     " + str(detail)[:1500]) if (detail and not cond) else ""))
    ok = ok and bool(cond)


a, b = "/* kill-reap-test:begin", "/* kill-reap-test:end */"
check("the region is present once", SRC.count(a) == 1 and SRC.count(b) == 1)
region = SRC[SRC.index(a):SRC.index(b)]
fn = SRC[SRC.index("NTSTATUS WINAPI NtTerminateProcess("):]
fn = fn[:fn.index("\n}\n") + 3]
q = fn.index("NtQueryInformationProcess( handle, ProcessBasicInformation")
req = fn.index("SERVER_START_REQ( terminate_process )")
end = fn.index("SERVER_END_REQ;", req)
reap = fn.index("ios_end_child_process_async( reap_peb")
selfblk = fn.index("    if (self)\n", end)
check("the PEB is read before the terminate_process request", q < req)
check("the reap runs after the request and before the self block", end < reap < selfblk)
check("the query is only for another process's handle, behind the switch",
      "handle && handle != NtCurrentProcess() && ios_kill_reap_enabled()" in fn)
check("the reap is gated by the pure predicate and logs", "ios_kill_reap_wanted( 1, !ret, self, 1," in fn and "[kill-reap]" in fn)
check("the switch is on by default (only the string 0 turns it off)", 'getenv( "MADEIRA_KILL_REAP" )' in SRC and "cached = (e && e[0] == '0' && !e[1]) ? 0 : 1;" in SRC)

HARNESS = r'''
#include <stdio.h>
''' + region + r'''
static int fails;
#define T(c) do { if (!(c)) { printf( "FAIL line %d: %s\n", __LINE__, #c ); fails++; } } while (0)
int main( void )
{
    /* wanted(enabled, status_ok, server_says_self, have_peb, is_current_peb, live_child, owns_exe_win) */
    T(  ios_kill_reap_wanted( 1, 1, 0, 1, 0, 1, 0 ) );     /* the launcher kills the injected child */
    T( !ios_kill_reap_wanted( 0, 1, 0, 1, 0, 1, 0 ) );     /* default off */
    T( !ios_kill_reap_wanted( 1, 0, 0, 1, 0, 1, 0 ) );     /* the server refused the kill */
    T( !ios_kill_reap_wanted( 1, 1, 1, 1, 0, 1, 0 ) );     /* the server says it was this process itself */
    T( !ios_kill_reap_wanted( 1, 1, 0, 0, 0, 1, 0 ) );     /* PEB unknown */
    T( !ios_kill_reap_wanted( 1, 1, 0, 1, 1, 1, 0 ) );     /* the handle resolved to the caller's own PEB */
    T( !ios_kill_reap_wanted( 1, 1, 0, 1, 0, 0, 0 ) );     /* not a live child (already gone, or not a pseudo-process) */
    T( !ios_kill_reap_wanted( 1, 1, 0, 1, 0, 1, 1 ) );     /* the owner of the fixed-base image keeps the old behaviour */
    puts( fails ? "FAILED" : "ok: truth table" );
    return fails != 0;
}
'''
cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
with tempfile.TemporaryDirectory() as tmp:
    c = Path(tmp) / "t.c"; c.write_text(HARNESS); exe = Path(tmp) / "t"
    r = subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-o", str(exe), str(c)],
                       capture_output=True, text=True)
    check("the decision function compiles (-Werror, ASAN/UBSAN)", r.returncode == 0, r.stderr[-1500:])
    if r.returncode == 0:
        run = subprocess.run([str(exe)], capture_output=True, text=True)
        print("     " + (run.stdout + run.stderr).strip())
        check("the truth table holds", run.returncode == 0, run.stdout + run.stderr)
sys.exit(0 if ok else 1)
