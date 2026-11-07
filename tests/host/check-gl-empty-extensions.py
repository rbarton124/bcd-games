#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""env.MADEIRA_GL_EMPTY_EXTENSIONS = 1: a 64-bit glGetString(GL_EXTENSIONS) gets "" instead of NULL (virtual_ios.c, OpenGL stub table).

Why: Far Cry 4's systemdetection64.dll ignores its failed OpenGL context, calls glGetString(GL_EXTENSIONS) and passes the result
to its own strstr, whose ASSERT(string) ends in an int3 (exit 0x80000003 right after "DetectionOpenGlWindow", runs 34 and 35).

Checks:
  1. the stub tables cut from virtual_ios.c, compiled with -Wall -Wextra -Werror and ASan/UBSan, one process per value of the
     switch (it is read once): unset, "0", "11" and "" leave code 130 NOT_SUPPORTED with ret untouched; "1" answers
     GL_EXTENSIONS with SUCCESS and an empty string, leaves GL_VENDOR/GL_VERSION as before, still marks the calling process
     once, and the 32-bit table's code 130 and the 64-bit table's other codes fail as before;
  2. code 130 is glGetString: read from the shipped app/Madeira/arm64ec-windows/opengl32.dll (its glGetString export's x64
     thunk, then the `mov w1, #code` before the unix call), and from wine/dlls/opengl32/unixlib.h when the submodule is present;
  3. the wiring: opengl32's branch hands the 64-bit table to 64-bit callers and the separate table to 32-bit ones; CI runs this
     check; the catalog documents the key.
NOT covered: what Far Cry 4 does after the detection; only a device shows that.
"""
from pathlib import Path
import os, re, shutil, struct, subprocess, sys, tempfile

root = Path(__file__).resolve().parents[2]
src = (root / "build/ntdll-unix/virtual_ios.c").read_text()
wf = (root / ".github/workflows/build-ipa.yml").read_text()
cat = (root / "app/Madeira/ConfigCatalog.generated.swift").read_text()
gen = (root / "build/tools/gen-config-catalog.py").read_text()
cc = os.environ.get("CC") or shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
ok = True


def check(what, cond, detail=""):
    global ok
    print(("PASS: " if cond else "FAIL: ") + what + (("\n      " + str(detail)[:2000]) if detail and not cond else ""))
    ok = ok and bool(cond)


# ---------------------------------------------------------------- 1. the tables, per value of the switch
stubs = src[src.index("static NTSTATUS ios_stub_unix_call(void *args) {"):src.index("/* DXMT's unix call table, statically linked")]
harness = r"""
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int NTSTATUS;
typedef NTSTATUS (*unixlib_entry_t)(void *);
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BB)
static int marks;
void *ios_jit_current_peb(void) { return (void *)0x1000; }
void ios_child_slot_gl_call(void *peb) { (void)peb; marks++; }
""" + stubs + r"""
struct p64 { void *teb; unsigned int name; const unsigned char *ret; };
int main( void )
{
    static const unsigned char sentinel[] = "untouched";
    struct p64 a = { 0, 0x1F03, sentinel }, v = { 0, 0x1F00, sentinel }, ver = { 0, 0x1F02, sentinel }, w = { 0, 0x1F03, sentinel };
    NTSTATUS sa, sv, sver, sw, s3, s131;
    pthread_once( &ios_stub_tables_once, ios_init_stub_tables );
    sa = ios_gl_stub_unix_call_table[130]( &a );
    int first_mark = marks;   /* code 130 itself marks the process, as every OpenGL call does */
    sv = ios_gl_stub_unix_call_table[130]( &v );
    sver = ios_gl_stub_unix_call_table[130]( &ver );
    sw = ios_gl_stub_wow64_unix_call_table[130]( &w );
    s3 = ios_gl_stub_unix_call_table[3]( NULL );
    s131 = ios_gl_stub_unix_call_table[131]( NULL );
    printf( "first=%d ext=%s:%s vendor=%s:%d version=%s:%d wow=%s:%d other=%d,%d marks=%d attach=%d\n",
            first_mark, sa == STATUS_SUCCESS ? "ok" : "ns", a.ret == sentinel ? "untouched" : (a.ret && !a.ret[0] ? "empty" : "other"),
            sv == STATUS_SUCCESS ? "ok" : "ns", v.ret == sentinel, sver == STATUS_SUCCESS ? "ok" : "ns", ver.ret == sentinel,
            sw == STATUS_SUCCESS ? "ok" : "ns", w.ret == sentinel,
            s3 == STATUS_NOT_SUPPORTED, s131 == STATUS_NOT_SUPPORTED, marks,
            ios_gl_stub_unix_call_table[0]( NULL ) == STATUS_SUCCESS && ios_gl_stub_wow64_unix_call_table[2]( NULL ) == STATUS_SUCCESS );
    return 0;
}
"""
if not cc:
    check("a C compiler for the host test", False, "no cc/clang/gcc")
else:
    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        (t / "h.c").write_text(harness)
        exe = t / "h"
        flags = ["-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", "-Wno-unused-parameter", "-g", "-O1", "-pthread",
                 "-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
        r = subprocess.run([cc, *flags, str(t / "h.c"), "-o", str(exe)], capture_output=True, text=True)
        if r.returncode:
            r = subprocess.run([cc, *[f for f in flags if "sanitize" not in f], str(t / "h.c"), "-o", str(exe)],
                               capture_output=True, text=True)
        check("the stub tables compile with -Wall -Wextra -Werror", r.returncode == 0, r.stderr)
        if r.returncode == 0:
            def run(value):
                env = {k: v for k, v in os.environ.items() if k != "MADEIRA_GL_EMPTY_EXTENSIONS"}
                if value is not None:
                    env["MADEIRA_GL_EMPTY_EXTENSIONS"] = value
                p = subprocess.run([str(exe)], capture_output=True, text=True, env=env)
                return p.returncode, p.stdout.strip(), p.stderr

            before = "first=1 ext=ns:untouched vendor=ns:1 version=ns:1 wow=ns:1 other=1,1 marks=1 attach=1"
            for value in (None, "0", "11", "", "true"):
                rc, out, err = run(value)
                check("switch %s: code 130 fails as before, nothing written, the process marked once" %
                      ("unset" if value is None else repr(value)), rc == 0 and out == before and "[gl-empty-ext]" not in err,
                      (rc, out, err))
            rc, out, err = run("1")
            check("switch 1: GL_EXTENSIONS gets SUCCESS and an empty string, one log line; GL_VENDOR and GL_VERSION fail as "
                  "before with ret untouched; the 32-bit table and the other codes fail as before; still one mark",
                  rc == 0 and out == "first=1 ext=ok:empty vendor=ns:1 version=ns:1 wow=ns:1 other=1,1 marks=1 attach=1"
                  and err.count("[gl-empty-ext]") == 1, (rc, out, err))

# ---------------------------------------------------------------- 2. code 130 is glGetString
def dll_code(path):
    d = path.read_bytes()
    pe = struct.unpack_from("<I", d, 0x3c)[0]
    n = struct.unpack_from("<H", d, pe + 6)[0]
    osz = struct.unpack_from("<H", d, pe + 20)[0]
    opt = pe + 24
    secs = []
    for i in range(n):
        s = opt + osz + i * 40
        vs, va, rs, ro = struct.unpack_from("<IIII", d, s + 8)
        secs.append((va, max(vs, rs), ro))

    def off(rva):
        for va, size, ro in secs:
            if va <= rva < va + size:
                return ro + rva - va
        raise ValueError("rva %#x outside every section" % rva)

    er = struct.unpack_from("<I", d, opt + 0x70)[0]
    e = off(er)
    nn, af, an, ao = struct.unpack_from("<IIII", d, e + 24)
    for i in range(nn):
        name_off = off(struct.unpack_from("<I", d, off(an) + 4 * i)[0])
        if d[name_off:d.index(b"\0", name_off)] != b"glGetString":
            continue
        rva = struct.unpack_from("<I", d, off(af) + 4 * struct.unpack_from("<H", d, off(ao) + 2 * i)[0])[0]
        at = off(rva)
        j = d.find(b"\xe9", at, at + 16)                       # the x64 thunk's jmp rel32 to the ARM64EC body
        if j < 0:
            raise ValueError("no jmp in glGetString's x64 thunk")
        body = rva + (j - at) + 5 + struct.unpack_from("<i", d, j + 1)[0]
        code = None
        for k in range(64):
            w = struct.unpack_from("<I", d, off(body) + 4 * k)[0]
            if (w & 0xffe0001f) == 0x52800001:                  # movz w1, #imm16
                code = (w >> 5) & 0xffff
            if (w & 0xfc000000) == 0x94000000 and code is not None:   # bl __wine_unix_call
                return code
        raise ValueError("no `mov w1, #code; bl` in glGetString")
    raise ValueError("no glGetString export")


try:
    shipped = dll_code(root / "app/Madeira/arm64ec-windows/opengl32.dll")
except (OSError, ValueError, struct.error) as error:
    shipped = error
check("the shipped arm64ec-windows/opengl32.dll's glGetString passes unix code 130", shipped == 130, shipped)
check("the source names the same code", "#define IOS_GL_UNIX_GLGETSTRING 130" in src and
      "ios_gl_stub_unix_call_table[IOS_GL_UNIX_GLGETSTRING] = ios_gl_stub_get_string;" in src)
hdr = root / "wine/dlls/opengl32/unixlib.h"
if hdr.is_file():
    h = hdr.read_text(errors="replace")
    enum = h[h.index("enum unix_funcs"):]
    names = re.findall(r"^\s*(unix_\w+),", enum[:enum.index("};")], re.M)
    check("wine/dlls/opengl32/unixlib.h: unix_glGetString is entry 130", names.index("unix_glGetString") == 130)
    check("its 64-bit arguments are { TEB *teb; GLenum name; const GLubyte *ret; }",
          re.search(r"struct glGetString_params\s*\{\s*TEB \*teb;\s*GLenum name;\s*const GLubyte \*ret;\s*\};", h))
else:
    print("note: wine/dlls/opengl32/unixlib.h is not checked out; the shipped DLL above is the authority")

# ---------------------------------------------------------------- 3. the wiring
gl_branch = src[src.index('} else if (match && strstr(match, "opengl32")) {'):]
gl_branch = gl_branch[:gl_branch.index("} else {")]
check("opengl32: 64-bit callers get the table that answers, 32-bit callers their own",
      "funcs64 = (const void *)ios_gl_stub_unix_call_table;" in gl_branch
      and "funcs_wow64 = (const void *)ios_gl_stub_wow64_unix_call_table;" in gl_branch)
enabled = src[src.index("static int ios_gl_empty_extensions_enabled( void )"):]
enabled = enabled[:enabled.index("\n}\n")]
check("the switch is read with getenv once, only the exact value 1 counts",
      src.count('getenv( "MADEIRA_GL_EMPTY_EXTENSIONS" )') == 1 and "cached = (s && s[0] == '1' && !s[1]) ? 1 : 0;" in enabled)
check("CI runs this check", "python3 tests/host/check-gl-empty-extensions.py" in wf)
check("the catalog documents env.MADEIRA_GL_EMPTY_EXTENSIONS (generator and generated file)",
      'key: "env.MADEIRA_GL_EMPTY_EXTENSIONS"' in cat and '"env.MADEIRA_GL_EMPTY_EXTENSIONS"' in gen)

sys.exit(0 if ok else 1)
