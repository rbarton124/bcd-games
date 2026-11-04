#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""tools/patch-wine-hard-error-text.py: a 64-bit program's NtRaiseHardError logs the strings of its message (log only).

Why: Far Cry 4's FC64.dll gave up with a STATUS_SERVICE_NOTIFICATION message box (0x50000018, count 4, mask 3: text and
caption) and the log showed only the stub's numbers. The 32-bit side's [ubi-harderror-v1] trace (dlls/wow64) already
logs the text for 32-bit programs.

Checks:
  1. the patch changes the stock system.c, a second run changes nothing, undoing it gives the stock text back, a stub
     that changed upstream fails;
  2. madeira_hard_error_text and the patched NtRaiseHardError cut from the patched file, compiled with -Wall -Wextra
     -Werror and under ASan + UBSan, with virtual_check_buffer_for_read refusing a real PROT_NONE page:
       - a service notification logs its text and caption (string 0 and 1) and nothing for the two numbers; the call
         still returns STATUS_NOT_IMPLEMENTED and leaves *response untouched;
       - an empty string, a NULL string, an unreadable descriptor or buffer, and an unreadable parameter array each
         give their own line and nothing is read from the refused page;
       - no mask, no count or no parameters log nothing; a count over 32 stops at 32;
       - at most 8 calls are logged per session;
       - three deliberate breakages are caught (the mask ignored, the buffer not checked, no limit on count);
  3. CI runs this check and then applies the patch to wine/dlls/ntdll/unix/system.c.
Needs the wine submodule checked out and `cc` on PATH. In CI this runs before the patch step; a patched file is first
restored to the text before this patch.
"""
from pathlib import Path
import importlib.util, os, shutil, subprocess, sys, tempfile

root = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("he", root / "tools/patch-wine-hard-error-text.py")
he = importlib.util.module_from_spec(spec)
spec.loader.exec_module(he)
path = root / "wine/dlls/ntdll/unix/system.c"
if not path.is_file():
    print(f"FAIL: {path.relative_to(root)} missing (check out the wine submodule)")
    sys.exit(1)
cc = os.environ.get("CC") or shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
ok = True


def check(what, cond, detail=""):
    global ok
    print(("PASS: " if cond else "FAIL: ") + what + (("\n      " + str(detail)[:2000]) if detail and not cond else ""))
    ok = ok and bool(cond)


text = path.read_text()
stock = he.unpatch(text) if he.MARKER in text else text
patched = he.patch(stock)
check("the patch changes system.c and adds its marker", patched != stock and he.MARKER in patched)
check("a second run changes nothing", he.patch(patched) == patched)
check("undoing it gives back the text before the patch", he.unpatch(patched) == stock)
try:
    he.patch(stock.replace(he.CALL_OLD, he.CALL_OLD.replace("return STATUS_NOT_IMPLEMENTED;", "return STATUS_SUCCESS;")))
    check("a stub that changed upstream fails", False)
except SystemExit:
    check("a stub that changed upstream fails", True)


def cut(src, start, end="\n}\n"):
    at = src.index(start)
    return src[at:src.index(end, at) + len(end)]


CUT = cut(patched, "static void madeira_hard_error_text(") + "\n" + cut(patched, "NTSTATUS WINAPI NtRaiseHardError(")
check("the call is after the stub's FIXME and before its unchanged return",
      CUT.count("madeira_hard_error_text( status, count, params_mask, params );") == 1 and
      he.CALL_NEW in CUT and "return STATUS_NOT_IMPLEMENTED;\n}" in CUT)

HEAD = r'''
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
typedef int32_t NTSTATUS; typedef uint32_t ULONG; typedef int32_t LONG; typedef uint16_t USHORT, WCHAR;
typedef uintptr_t ULONG_PTR; typedef size_t SIZE_T; typedef int BOOL; typedef void *HANDLE;
typedef struct { USHORT Length, MaximumLength; WCHAR *Buffer; } UNICODE_STRING;
typedef enum { OptionOk = 1 } HARDERROR_RESPONSE_OPTION;
typedef enum { ResponseNotHandled = 0, ResponseOk = 6 } HARDERROR_RESPONSE;
#define WINAPI
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002)
#define HandleToULong(h) ((ULONG)(ULONG_PTR)(h))
static struct { struct { HANDLE UniqueProcess; } ClientId; } teb = { { (HANDLE)0xa8 } };
#define NtCurrentTeb() (&teb)
static LONG InterlockedIncrement( LONG *p ) { return __atomic_add_fetch( p, 1, __ATOMIC_SEQ_CST ); }
#define ERR(...) fprintf( stderr, __VA_ARGS__ )
#define FIXME(...) fprintf( stderr, "fixme:" __VA_ARGS__ )
static char *bad;   /* one PROT_NONE page: virtual_check_buffer_for_read refuses it, and a read of it faults */
static int n_checks;
static BOOL virtual_check_buffer_for_read( const void *p, SIZE_T n )
{
    n_checks++;
    if ((ULONG_PTR)p < 0x10000) return 0;
    return !((const char *)p < bad + 0x4000 && (const char *)p + n > bad);
}
/* the wine/debug.h form, with its 300-byte buffer */
static const char *debugstr_wn( const WCHAR *s, int n )
{
    static char buf[300];
    char *d = buf;
    if (!s) return "(null)";
    *d++ = 'L'; *d++ = '"';
    while (n-- > 0 && d <= buf + sizeof(buf) - 10) { WCHAR c = *s++; *d++ = (c >= ' ' && c < 127) ? (char)c : '?'; }
    *d++ = '"';
    if (n >= 0) { *d++ = '.'; *d++ = '.'; *d++ = '.'; }
    *d = 0;
    return buf;
}
'''

TESTS = r'''
static int fails;
#define T(c) do { if (!(c)) { printf( "FAIL line %d: %s\n", __LINE__, #c ); fails++; } } while (0)
static WCHAR w_text[] = { 'E','r','r','o','r',' ','a','t',' ','h','o','o','k','i','n','g' };
static WCHAR w_cap[] = { 'F','C','6','4' };
static UNICODE_STRING s(WCHAR *b, USHORT bytes) { UNICODE_STRING u = { bytes, bytes, b }; return u; }

static NTSTATUS raise( NTSTATUS status, ULONG count, ULONG mask, void **params )
{
    HARDERROR_RESPONSE r = (HARDERROR_RESPONSE)77;
    NTSTATUS ret = NtRaiseHardError( status, count, mask, params, OptionOk, &r );
    T( r == (HARDERROR_RESPONSE)77 );
    return ret;
}

int main( int argc, char **argv )
{
    UNICODE_STRING text = s( w_text, sizeof(w_text) ), cap = s( w_cap, sizeof(w_cap) ), empty = s( w_text, 0 );
    UNICODE_STRING badbuf, *badstr;
    void *params[40];
    int i;

    bad = mmap( NULL, 0x4000, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
    if (bad == MAP_FAILED) return 2;
    badbuf = s( (WCHAR *)bad, 8 );
    badstr = (UNICODE_STRING *)bad;
    if (argc > 1 && !strcmp( argv[1], "budget" ))
    {
        params[0] = &text; params[1] = &cap;
        for (i = 0; i < 12; i++) T( raise( 0x50000018, 2, 3, params ) == STATUS_NOT_IMPLEMENTED );
        return fails != 0;
    }
    if (argc > 1 && !strcmp( argv[1], "count" ))
    {
        for (i = 0; i < 40; i++) params[i] = (void *)(ULONG_PTR)0x10;   /* not strings */
        params[31] = &cap;
        T( raise( 0xc0000001, 40, 0x80000000u, params ) == STATUS_NOT_IMPLEMENTED );
        return fails != 0;
    }
    /* the service notification: text, caption, type, timeout */
    params[0] = &text; params[1] = &cap; params[2] = (void *)(ULONG_PTR)0x10; params[3] = (void *)(ULONG_PTR)0xffffffff;
    T( raise( 0x50000018, 4, 3, params ) == STATUS_NOT_IMPLEMENTED );
    /* nothing to log */
    T( raise( 0x50000018, 4, 0, params ) == STATUS_NOT_IMPLEMENTED );
    T( raise( 0x50000018, 0, 3, params ) == STATUS_NOT_IMPLEMENTED );
    T( raise( 0x50000018, 4, 3, NULL ) == STATUS_NOT_IMPLEMENTED );
    /* refused reads: the parameter array; a NULL, unreadable or empty string; an unreadable buffer */
    T( raise( 0x50000018, 2, 3, (void **)bad ) == STATUS_NOT_IMPLEMENTED );
    params[0] = NULL; params[1] = badstr; params[2] = &badbuf; params[3] = &empty;
    T( raise( 0xc0000135, 4, 0xf, params ) == STATUS_NOT_IMPLEMENTED );
    printf( "%s\n", fails ? "HARNESS FAILED" : "harness ok" );
    return fails != 0;
}
'''

BREAKS = [
    ("the mask ignored", "        if (!(params_mask & (1u << i))) continue;\n", ""),
    ("the buffer not checked", "(!copy.Buffer || !virtual_check_buffer_for_read( copy.Buffer, copy.Length ))", "!copy.Buffer"),
    ("no limit on count", "    if (count > 32) count = 32;   /* params_mask has 32 bits */\n", ""),
]

if not cc:
    check("a C compiler", False, "no cc/clang/gcc on PATH")
else:
    with tempfile.TemporaryDirectory() as tmp:
        def build(code, name, sanitize):
            c, exe = os.path.join(tmp, name + ".c"), os.path.join(tmp, name)
            Path(c).write_text(HEAD + code + TESTS)
            flags = [cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function"]
            if sanitize:
                flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=undefined"]
            return subprocess.run(flags + [c, "-o", exe], capture_output=True, text=True), exe

        def run(exe, *args):
            try:
                return subprocess.run([exe, *args], capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired as e:
                return subprocess.CompletedProcess(e.cmd, 1, "timeout", "")

        def lines(r):
            return [l for l in r.stderr.splitlines() if l.startswith("[harderror]")]

        b, exe = build(CUT, "strict", False)
        check("the cut functions compile with -Wall -Wextra -Werror", b.returncode == 0, b.stderr)
        b, exe = build(CUT, "san", True)
        check("and under AddressSanitizer + UndefinedBehaviorSanitizer", b.returncode == 0, b.stderr)
        want = [
            '[harderror] pid=00a8 status=50000018 string 0 (16 chars): L"Error at hooking"',
            '[harderror] pid=00a8 status=50000018 string 1 (4 chars): L"FC64"',
            '[harderror] pid=00a8 status=50000018 parameters unreadable at %p',
            '[harderror] pid=00a8 status=c0000135 string 0 unreadable at (nil)',
            '[harderror] pid=00a8 status=c0000135 string 1 unreadable at %p',
            '[harderror] pid=00a8 status=c0000135 string 2 unreadable at %p',
            '[harderror] pid=00a8 status=c0000135 string 3 (0 chars): L""',
        ]

        def matches(got):
            if len(got) != len(want):
                return False
            for g, w in zip(got, want):
                if "%p" in w:
                    head, tail = w.split("%p")
                    if not (g.startswith(head) and g.endswith(tail) and len(g) > len(head) + len(tail)):
                        return False
                elif g != w and not (w.endswith("at (nil)") and g in (w, w.replace("(nil)", "0x0"))):
                    return False
            return True

        if b.returncode == 0:
            r = run(exe)
            got = lines(r)
            check("text and caption logged, the numbers not read; empty, NULL, unreadable descriptor, buffer and "
                  "array each one line; no mask, count or parameters nothing; STATUS_NOT_IMPLEMENTED, *response untouched",
                  r.returncode == 0 and "harness ok" in r.stdout and matches(got), "\n".join(got) + "\n" + r.stdout + r.stderr[-1500:])
            check("the stub's FIXME line is still printed for every call", r.stderr.count("fixme:") == 6, r.stderr[-800:])
            r = run(exe, "budget")
            check("at most 8 calls are logged (2 lines each)", r.returncode == 0 and len(lines(r)) == 16 and
                  r.stderr.count("fixme:") == 12, "\n".join(lines(r)))
            r = run(exe, "count")
            check("a count over 32 stops at 32 (bit 31's string is logged, nothing past it is read)",
                  r.returncode == 0 and lines(r) == ['[harderror] pid=00a8 status=c0000001 string 31 (4 chars): L"FC64"'],
                  "\n".join(lines(r)) + r.stderr[-800:])
        for what, old, new in BREAKS:
            hit = CUT.count(old) == 1
            bb, bexe = build(CUT.replace(old, new), "broken", True) if hit else (None, None)
            caught = hit and bb.returncode == 0 and any(run(bexe, *a).returncode != 0 or
                                                        (not a and not matches(lines(run(bexe)))) for a in ((), ("count",)))
            check("breakage caught: " + what, caught, bb.stderr if bb else "anchor not found")

wf = (root / ".github/workflows/build-ipa.yml").read_text()
step = "python3 tools/patch-wine-hard-error-text.py wine/dlls/ntdll/unix/system.c"
check("CI runs this check, then applies the patch", "run: python3 tests/host/check-hard-error-text.py" in wf and step in wf and
      wf.index("run: python3 tests/host/check-hard-error-text.py") < wf.index(step))

print("PASS: hard-error-text" if ok else "FAILED: hard-error-text")
sys.exit(0 if ok else 1)
