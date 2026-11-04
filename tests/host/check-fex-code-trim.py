#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""madeira-bcd code-trim: a 32-bit process gives its FEX code buffers back for a small one when BCD's ntdll asks.

tools/patch-fex-ios-code-trim.py adds IosTrimCodeBuffer to FEXCore (beside the generation sweep) and the request poll to the WOW64
module's syscall exit; build/ntdll-unix/virtual_ios.c keeps one control block per process (ios_code_trim_control) and
process_ios.c hands its address to FEX through the Wine-private NtQueryInformationProcess class 1011.

Checks:
  1. the FEX patch (FEX tree: the checkout's FEX/ submodule, else FEX_SRC, else ~/madeira-bcd/FEX; that part is skipped without
     one): applies after the other WOW64 patches that touch Module.cpp, in the build's order; a second run says "already in" and
     changes nothing; a changed anchor refuses the whole patch and writes nothing; the poll comes after the syscall's depth is
     restored and before the existing redirect; a declined request is tried at most 30 times; the trim declines at a first look
     when a thread is plainly not parked, probes the new size before it claims the sweep, takes the locks and the
     gate in the sweep's order, allocates only when every other thread is parked and no thread has a signal frame, marks moved
     threads while the gate is set, and clears the gate before it releases the locks; both registry-full paths set the flag; no
     export is added (the WOW64 build ships only a module whose exports equal the committed one's);
  2. both sides agree: the class number, the magic and the control block's fields in the same order and of the same widths;
  3. the CI and local WOW64 builds apply it last, without failing the build, and restore the files it patches;
  4. ntdll's side compiled (-Wall -Wextra -Werror, then ASan/UBSan): ios_code_trim_control makes one block per process (the same
     on a second ask, with the magic), NULL when the table is full or env.MADEIRA_POOL_CODE_TRIM = 0, and a block comes free when
     its process ends; ios_query_code_trim answers the address for the calling process only, STATUS_INFO_LENGTH_MISMATCH for a
     wrong size and STATUS_INVALID_INFO_CLASS otherwise, and NtQueryInformationProcess answers the class before its switch;
  5. CI runs this check.
"""
from pathlib import Path
import os, re, shutil, subprocess, sys, tempfile

root = Path(__file__).resolve().parents[2]
ok = True


def check(what, cond, detail=""):
    global ok
    print(("ok   " if cond else "FAIL ") + what + (("\n     " + str(detail)[:2000]) if (detail and not cond) else ""))
    ok = ok and bool(cond)


def cut(text, start, end="\n}\n"):
    at = text.index(start)
    return text[at:text.index(end, at) + len(end)]


patch = root / "tools/patch-fex-ios-code-trim.py"
FILES = ("FEXCore/Source/Interface/Core/CPUBackend.h", "FEXCore/Source/Interface/Core/CPUBackend.cpp", "Source/Windows/WOW64/Module.cpp")
fex = next((p for p in (root / "FEX", Path(os.environ.get("FEX_SRC", "/nonexistent")), Path.home() / "madeira-bcd/FEX")
            if (p / FILES[2]).is_file()), None)
virtual = (root / "build/ntdll-unix/virtual_ios.c").read_text()
process = (root / "build/ntdll-unix/process_ios.c").read_text()

# ---------------------------------------------------------------- 1. the FEX patch
if fex is None:
    print("skip: no FEX tree here (FEX/, FEX_SRC or ~/madeira-bcd/FEX); the CI runs the source part")
    patched = {}
else:
    with tempfile.TemporaryDirectory(prefix="madeira-fex-trim-") as tmp:
        tree = Path(tmp)
        for f in FILES:
            (tree / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(fex / f, tree / f)
        for other in ("patch-fex-ios-wow-threads-ctor.py", "patch-fex-ios-thread-init-nomem.py"):
            r = subprocess.run([sys.executable, str(root / "tools" / other), str(tree)], capture_output=True, text=True)
            check("the build's earlier Module.cpp patch applies first: " + other, r.returncode == 0, r.stdout + r.stderr)
        before = {f: (tree / f).read_text() for f in FILES}
        r1 = subprocess.run([sys.executable, str(patch), str(tree)], capture_output=True, text=True)
        patched = {f: (tree / f).read_text() for f in FILES}
        r2 = subprocess.run([sys.executable, str(patch), str(tree)], capture_output=True, text=True)
        check("it applies once to all three files; a second run says so and changes nothing",
              r1.returncode == 0 and r2.returncode == 0 and "already in" in r2.stdout and all(patched[f] != before[f] for f in FILES)
              and all((tree / f).read_text() == patched[f] for f in FILES), r1.stdout + r1.stderr + r2.stdout + r2.stderr)
        for f in FILES:
            (tree / f).write_text(before[f])
        (tree / FILES[2]).write_text(before[FILES[2]].replace("  TD->IosSyscallDepth = Depth;\n", "  TD->IosSyscallDepth = Depth; \n"))
        r3 = subprocess.run([sys.executable, str(patch), str(tree)], capture_output=True, text=True)
        check("a changed anchor refuses the whole patch and writes no file",
              r3.returncode != 0 and "anchor changed" in (r3.stdout + r3.stderr)
              and all((tree / f).read_text() == before[f] for f in FILES[:2]), r3.stdout + r3.stderr)

    module, backend, header = patched[FILES[2]], patched[FILES[1]], patched[FILES[0]]
    syscall = cut(module, "extern \"C\" IosSyscallResume IosWowSyscallC(")
    check("the poll runs at an armed outermost syscall's end: after the depth is restored, before the existing redirect",
          syscall.index("Obj->HandleSyscall(Frame, Args);") < syscall.index("TD->IosSyscallDepth = Depth;")
          < syscall.index("IosCodeTrim::Poll(TLS.ThreadState(), TD);") < syscall.index("if (Arm && TD->IosMigrated) {")
          and syscall.count("IosCodeTrim::Poll(") == 1
          and "  if (Arm) {\n    IosCodeTrim::Poll(TLS.ThreadState(), TD);" in syscall)
    poll = cut(module, "static void Poll(FEXCore::Core::InternalThreadState* Thread, FrontendThreadData* TD) {")
    check("the poll: nothing unless a block was offered and a request is newer than the last one done; one try a second",
          poll.index("if (!C) {") < poll.index("if (Request == __atomic_load_n(&C->Done, __ATOMIC_RELAXED)) {")
          < poll.index("NtQuerySystemTime(&Now);") < poll.index("IosTrimCodeBuffer(")
          and "Now.QuadPart + 10000000" in poll)
    check("a declined or busy try leaves the request pending, at most 30 times; a finished one sets IosMigrated only when this "
          "thread moved",
          "static constexpr uint32_t GiveUp = 30;" in module
          and poll.index("if ((Result == 0 || Result == -2) && __atomic_add_fetch(&C->Declined, 1, __ATOMIC_RELAXED) < GiveUp) {")
          < poll.index("return;\n  }\n  if (Result == 1) {")
          and "    TD->IosMigrated = 1;" in poll[poll.index("if (Result == 1) {"):poll.index("__atomic_store_n(&C->Done")]
          and poll.index("__atomic_store_n(&C->Result") < poll.index("__atomic_store_n(&C->Done, Request, __ATOMIC_RELEASE);"))
    get = cut(module, "static Control* Get() {")
    check("the block is asked for once per process, checked by its magic, and published before the state",
          "NtQueryInformationProcess(NtCurrentProcess(), static_cast<PROCESSINFOCLASS>(ProcessWineIosCodeTrim)" in get
          and "C->Magic == ControlMagic" in get and get.index("Ctl = Offered ? C : nullptr;") < get.index("State.store(Offered ? 1 : 0"))
    trim = cut(backend, "extern \"C\" int IosTrimCodeBuffer(", "\n  }\n")
    order = ["IosSweepRegistryFull.load(", "Out[2] += *IosSweepSlots[i].InSim != 0;", "return 0; // a thread is plainly not parked",
             "FEXCore::Allocator::VirtualAlloc(Size, true)", "IosSweepBusy.exchange(1", "Invalidation.try_lock_shared()",
             "Manager.CodeBufferWriteMutex.try_lock()", "__atomic_store_n(&IosCodeBufferSweepGate, 1", "if (*Snap[i].InSim != 0) {",
             "if (!NotParked && !SignalFrames) {", "Manager.IosStartCodeBuffer(Size)", "IosRemoteMigrateStale(Latest) == 1",
             "*Snap[i].Migrated = 1;", "CallerThread->CPUBackend->IosRemoteMigrateStale(Latest)",
             "__atomic_store_n(&IosCodeBufferSweepGate, 0", "    Manager.CodeBufferWriteMutex.unlock();\n    Invalidation.unlock_shared();",
             "IosSweepBusy.store(0, std::memory_order_release);\n    Out[0]"]
    at = [trim.find(o) for o in order]
    check("the trim: a first look at the threads, probe, sweep claim, locks, gate, all parked, allocate, move every thread "
          "(marked under the gate), gate down, locks back", all(a >= 0 for a in at) and at == sorted(at), list(zip(order, at)))
    check("every early return releases what it took",
          "      Invalidation.unlock_shared();\n      IosSweepBusy.store(0, std::memory_order_release);\n      return -2;" in trim
          and "      IosSweepBusy.store(0, std::memory_order_release);\n      return -2;" in trim
          and trim.index("return -1;") < trim.index("IosSweepBusy.exchange(1") and trim.index("return -3;") < trim.index("IosSweepBusy.exchange(1"))
    check("only in the WOW64 build of the sweep block; the registry's two full paths set the flag the trim checks",
          backend.index("#if defined(FEX_IOS_HOST) && defined(_WIN32)") < backend.index("#if !defined(ARCHITECTURE_arm64ec)\n  /* madeira-bcd code-trim")
          and backend.count("IosSweepRegistryFull.store(true, std::memory_order_relaxed);") == 2
          and "if (IosSweepRegistryFull.load(std::memory_order_relaxed)) {\n      return -1;" in trim)
    check("the manager's new public helper only starts a buffer (AllocateNew stays private)",
          "    fextl::shared_ptr<CodeBuffer> IosStartCodeBuffer(size_t Size) {\n      return AllocateNew(Size);\n    }\n#endif\n\n  private:" in header)
    check("no export is added", all("dllexport" not in patched[f].replace(before_text, "") for f, before_text in before.items())
          and "dllexport" not in Path(patch).read_text())

    # ---------------------------------------------------------------- 2. both sides agree
    fex_struct = cut(module, "struct Control {", "\n};\n")
    c_struct = cut(virtual, "struct ios_code_trim\n{", "\n};\n")
    fex_fields = re.findall(r"^\s+(?:volatile )?(u?int32_t) (\w+);", fex_struct, re.M)
    c_fields = re.findall(r"^\s+(?:volatile )?(u?int32_t) (\w+);", c_struct, re.M)
    names = list(zip([t for t, _ in fex_fields], [t for t, _ in c_fields]))
    check("the control block: the same six 32-bit fields in the same order on both sides",
          len(fex_fields) == len(c_fields) == 6 and all(a == b for a, b in names)
          and [n.lower() for _, n in fex_fields] == ["magic", "sizemb", "request", "done", "result", "declined"]
          and [n for _, n in c_fields] == ["magic", "size_mb", "request", "done", "result", "declined"], (fex_fields, c_fields))
    check("the same class number and magic",
          "static constexpr ULONG ProcessWineIosCodeTrim = 1011;" in module and "#define IOS_PROCESS_CODE_TRIM_CLASS 1011" in process
          and "static constexpr uint32_t ControlMagic = 0x4d495254;" in module and "#define IOS_CODE_TRIM_MAGIC 0x4d495254" in virtual)

# ---------------------------------------------------------------- 3. the builds
ci = (root / "tools/build-xtajit-wow64.sh").read_text()
local = (root / "build/fex-wow64/build.sh").read_text()
restored = ("FEXCore/Source/Interface/Core/CPUBackend.cpp", "FEXCore/Source/Interface/Core/CPUBackend.h", "Source/Windows/WOW64/Module.cpp")
ci_restore = ci[ci.index("restore() {"):ci.index("trap restore EXIT")]
check("the CI build applies it last, without failing the build, and restores the three files",
      'python3 "$R/tools/patch-fex-ios-code-trim.py" "$R/FEX" || echo "::warning::' in ci
      and ci.index("patch-fex-ios-cpuid-classic.py") < ci.index("patch-fex-ios-code-trim.py\" \"$R/FEX\"") < ci.index("restore() {")
      and all(f in ci_restore for f in restored))
check("the local build applies it the same way, before its restore trap, which restores the three files",
      'python3 "$R/tools/patch-fex-ios-code-trim.py" "$R/FEX" || echo' in local
      and local.index("patch-fex-ios-code-trim.py") < local.index("trap 'git -C")
      and all(f in local[local.index("trap 'git -C"):] for f in restored))

# ---------------------------------------------------------------- 4. ntdll's side, compiled
ctl_code = cut(virtual, "struct ios_code_trim\n{", "\n};\n") + "\n" + \
    virtual[virtual.index("#define IOS_CODE_TRIM_MAGIC"):virtual.index("static pthread_mutex_t ios_code_trim_lock")] + \
    "static pthread_mutex_t ios_code_trim_lock = PTHREAD_MUTEX_INITIALIZER;\n" + \
    cut(virtual, "static int ios_pool_code_trim_enabled(void)") + cut(virtual, "void *ios_code_trim_control( void *peb )") + \
    cut(virtual, "static void ios_code_trim_owner_died( void *peb )")
query = process[process.index("#define IOS_PROCESS_CODE_TRIM_CLASS 1011"):process.index("#endif\n\nNTSTATUS WINAPI NtQueryInformationProcess(")]
nqip = cut(process, "NTSTATUS WINAPI NtQueryInformationProcess( HANDLE handle, PROCESSINFOCLASS class, void *info,")
check("NtQueryInformationProcess answers the class before its switch, for WINE_IOS only",
      nqip.index("if (class == (PROCESSINFOCLASS)IOS_PROCESS_CODE_TRIM_CLASS) return ios_query_code_trim( handle, info, size, ret_len );")
      < nqip.index("switch (class)") and "#ifdef WINE_IOS\n    if (class == (PROCESSINFOCLASS)IOS_PROCESS_CODE_TRIM_CLASS)" in nqip)
reclaim = cut(virtual, "void ios_jit_reclaim_process( void *peb )")
check("a process that ends gives its block back", "    ios_code_trim_owner_died( peb );   /* madeira-bcd code-trim */" in reclaim)

HARNESS = r'''
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
typedef int32_t NTSTATUS; typedef unsigned long ULONG_PTR; typedef uint32_t ULONG; typedef void *HANDLE;
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#define STATUS_INVALID_INFO_CLASS ((NTSTATUS)0xC0000003)
#define GetCurrentProcess() ((HANDLE)~(ULONG_PTR)0)
static struct { void *Peb; } teb;
#define NtCurrentTeb() (&teb)
''' + ctl_code + query + r'''
static int fails;
#define T(c) do { if (!(c)) { printf( "FAIL line %d: %s\n", __LINE__, #c ); fails++; } } while (0)
int main( int argc, char **argv )
{
    static char pebs[IOS_CODE_TRIM_MAX + 1];
    struct ios_code_trim *a, *b;
    ULONG_PTR out = 0;
    ULONG len = 99;
    int i;

    (void)argv;
    if (argc > 1)   /* env.MADEIRA_POOL_CODE_TRIM = 0 */
    {
        teb.Peb = &pebs[0];
        T( !ios_code_trim_control( &pebs[0] ) );
        T( ios_query_code_trim( GetCurrentProcess(), &out, sizeof(out), &len ) == STATUS_INVALID_INFO_CLASS && !out && !len );
        return fails != 0;
    }
    a = ios_code_trim_control( &pebs[0] );
    T( a && a->magic == IOS_CODE_TRIM_MAGIC && !a->request && !a->done && ios_code_trim_control( &pebs[0] ) == a );
    T( !ios_code_trim_control( NULL ) );
    for (i = 1; i < IOS_CODE_TRIM_MAX; i++) T( ios_code_trim_control( &pebs[i] ) && ios_code_trim_control( &pebs[i] ) != a );
    T( !ios_code_trim_control( &pebs[IOS_CODE_TRIM_MAX] ) );                     /* the table is full */
    a->request = 7;
    ios_code_trim_owner_died( &pebs[0] );                                        /* its process ended: the block comes free */
    b = ios_code_trim_control( &pebs[IOS_CODE_TRIM_MAX] );
    T( b == a && b->magic == IOS_CODE_TRIM_MAGIC && !b->request );               /* reused, fresh */
    teb.Peb = &pebs[3];
    T( ios_query_code_trim( GetCurrentProcess(), &out, sizeof(out), &len ) == STATUS_SUCCESS && len == sizeof(ULONG_PTR) &&
       out == (ULONG_PTR)ios_code_trim_control( &pebs[3] ) );
    T( ios_query_code_trim( GetCurrentProcess(), &out, 4, &len ) == STATUS_INFO_LENGTH_MISMATCH );
    T( ios_query_code_trim( (HANDLE)0x44, &out, sizeof(out), &len ) == STATUS_INVALID_INFO_CLASS && !len );   /* another process */
    T( ios_query_code_trim( GetCurrentProcess(), &out, sizeof(out), NULL ) == STATUS_SUCCESS );
    puts( fails ? "HARNESS FAILED" : "harness ok" );
    return fails != 0;
}
'''
cc = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
if not cc:
    check("a C compiler", False, "none on PATH")
else:
    with tempfile.TemporaryDirectory(prefix="madeira-code-trim-") as tmp:
        c, exe = Path(tmp) / "t.c", Path(tmp) / "t"
        c.write_text(HARNESS)
        for flags, what in ((["-Wall", "-Wextra", "-Werror"], "strict"), (["-fsanitize=address,undefined", "-fno-sanitize-recover=undefined"], "ASan/UBSan")):
            b = subprocess.run([cc, "-std=gnu11", "-O1", "-g", "-Wno-unused-function"] + flags + [str(c), "-o", str(exe), "-lpthread"],
                               capture_output=True, text=True)
            check("ntdll's control table and query compile (" + what + ")", b.returncode == 0, b.stderr)
            if b.returncode:
                continue
            env = {k: v for k, v in os.environ.items() if k != "MADEIRA_POOL_CODE_TRIM"}
            r = subprocess.run([str(exe)], capture_output=True, text=True, env=env)
            check("one block per process, the same on a second ask; a full table and NULL get none; an ended process's block is "
                  "reused fresh; the query answers its own process only (" + what + ")", r.returncode == 0, r.stdout + r.stderr)
            r = subprocess.run([str(exe), "off"], capture_output=True, text=True, env=dict(env, MADEIRA_POOL_CODE_TRIM="0"))
            check("MADEIRA_POOL_CODE_TRIM=0: no block, the class is unknown (" + what + ")", r.returncode == 0, r.stdout + r.stderr)

wf = (root / ".github/workflows/build-ipa.yml").read_text()
check("CI runs this check", "python3 tests/host/check-fex-code-trim.py" in wf)
print("PASS: fex-code-trim" if ok else "FAILED: fex-code-trim")
sys.exit(0 if ok else 1)
