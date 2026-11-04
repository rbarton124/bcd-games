#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host check: FEX code buffers for the program being played (BCD_GAME_FOLDER) in build/ntdll-unix/virtual_ios.c.

Why: ios_pool_code_cap is first come, first served and knows nothing about who asks. Ubisoft Connect + Far Cry 3 (BCD 0.1.625 on an
iPhone, five sessions each of two experiments): the launcher's helpers took about 450 MB of the 884 MB pool (upc.exe 128, one
UplayWebCore 128, about ten 16 MB buffers) before the game, which starts last, asked; its 128 MB request was cut to 16 MB and it rotated
its code buffer every one to two seconds. The app knows the folder of the program the player launched and publishes it for the
session (BCD_GAME_FOLDER); a process whose image lies inside it keeps exactly today's budget cap, every other process of the session
is held to 32 MB per buffer (a game with no other processes sees no change).

What this compiles: the pure functions between `pool-code-policy-test:begin/end`, the production ios_pool_hole_between /
ios_pool_code_cap and the production ios_pool_fg_adjust (cut by signature, as check-pool-code-exit.py does) against a minimal PEB, with
-Wall -Wextra -Werror and ASAN/UBSAN. The numbers are the 13:08:32 session's log rows (pool 0x37410000, hole 0x22000000..0x23410000).

NOT covered: the call site's effect on a real FEX process (the carve table, pinned generations, retired buffers), the real PEB and
image paths Wine writes, thread timing, the app's Swift (no swiftc here; source slices only), and anything on a device.
"""
from pathlib import Path
import shutil, subprocess, sys, tempfile

ROOT = Path(__file__).resolve().parents[2]
SRC = (ROOT / "build/ntdll-unix/virtual_ios.c").read_text()
ok = True


def check(what, cond, detail=""):
    global ok
    print(("ok   " if cond else "FAIL ") + what + (("\n     " + str(detail)[:1500]) if (detail and not cond) else ""))
    ok = ok and bool(cond)


def function(signature):
    start = SRC.index(signature)
    return SRC[start:SRC.index("\n}", start) + 2] + "\n"


a, b = "/* pool-code-policy-test:begin", "/* pool-code-policy-test:end */"
check("the policy region is present once", SRC.count(a) == 1 and SRC.count(b) == 1)
region = SRC[SRC.index(a):SRC.index(b)]
funcs = function("static size_t ios_pool_hole_between(") + function("static size_t ios_pool_code_cap(")
helper = function("static size_t ios_pool_fg_adjust(")

# the call site keeps the production call text unchanged (check-pool-split.py pins it) and adds the class step after it
call = SRC[SRC.index("size_t cap = ios_pool_code_cap( ios_jit_pool_size_global, head_now, tail_now,"):][:2600]
check("the original budget call is untouched and the class step follows it, once",
      "ios_pool_head_reserve +\n" in call and "cap = ios_pool_fg_adjust( cap, head_now, tail_now, &carve_fg );" in call
      and call.index("budget_cap = cap;") > call.index("ios_pool_fg_adjust(") and SRC.count("ios_pool_fg_adjust( cap,") == 1)
check("the helper reads the app's folder and the one off switch, and takes the image path from the caller's own PEB",
      'getenv( "BCD_GAME_FOLDER" )' in helper and 'getenv( "MADEIRA_POOL_CODE_FOREGROUND" )' in helper
      and "ios_jit_current_peb()" in helper and "pp->ImagePathName.Buffer" in helper
      and "if (!n || (off && !strcmp( off, \"0\" ))) return budget_cap;" in helper)
check("the log line is written once per process (by its id), for up to 64 processes",
      "pid = ios_jit_current_pid();" in helper and "if (i == logged_n && logged_n < 64)" in helper and "logged_pid[logged_n++] = pid;" in helper
      and "static ULONG ios_jit_current_pid(void)" in SRC and "return teb ? teb->Peb : NULL;" in function("void *ios_jit_current_peb(void)\n{"))
# the app's side (Swift, read as source slices: no swiftc here): who publishes the folder, and that a session's end takes it away
APP = ROOT / "app/Madeira"
lib, dock, bridge = ((APP / n).read_text() for n in ("Library.swift", "MadeiraDock.swift", "WineProcessBridge.m"))
launch = lib[lib.index("    func configureLaunch() {"):]
launch = launch[:launch.index("\n    }\n") + 6]
prop = lib[lib.index("    var gameFolder: String? {"):]
prop = prop[:prop.index("\n    }\n") + 6]
check("a library start publishes its program's folder (a Steam game's install folder), none for the Desktop entry",
      "if desktop == true { return nil }" in prop and "return steamAppID != nil ? windowsPath : Self.folder(of: launchWindowsPath)" in prop
      and 'if let gameFolder { setenv("BCD_GAME_FOLDER", gameFolder, 1) } else { unsetenv("BCD_GAME_FOLDER") }' in launch
      and launch.index('setenv("BCD_GAME_FOLDER"') > launch.index("if !startsSteamGameDirectly {"))
configure = dock[dock.index("    static func configure(_ game: DockGame, launchOption: UInt32 = 0) {"):]
configure = configure[:configure.index("\n    }\n")]
check("a Dock start publishes the game's install folder, the one Valve's client must resolve to",
      'setenv("BCD_GAME_FOLDER", game.windowsInstallPath, 1)' in configure
      and 'setenv("MADEIRA_STEAM_HOST_EXPECTED_INSTALL", game.windowsInstallPath, 1)' in configure)
end = bridge[bridge.index("static void wine_session_end(void)\n{"):]
check("the session's end unsets it, and only the app sets it",
      'unsetenv("BCD_GAME_FOLDER");' in end[:end.index("stopping wineserver")]
      and sum(t.count('setenv("BCD_GAME_FOLDER"') - t.count('unsetenv("BCD_GAME_FOLDER"') for t in (lib, dock, bridge)) == 2)
check("no program names and no lists", "MADEIRA_POOL_FG_PROCS" not in SRC and "MADEIRA_POOL_BG_PROCS" not in SRC
      and ".exe" not in region.split("*/", 1)[1].replace("farcry3_d3d11.exe", "").replace("fc3_blooddragon_d3d11.exe", ""))

# the helper's own log lines are counted (only the helper's dprintf is replaced)
COUNT = r'''
#include <stdarg.h>
#include <string.h>
static int n_fg_lines, log_mark;
static int log_count( void ) { return n_fg_lines; }
static int pool_fg_dprintf( int fd, const char *fmt, ... )
{
    va_list a; int r;
    if (strstr( fmt, "[pool-fg]" )) n_fg_lines++;
    va_start( a, fmt ); r = vdprintf( fd, fmt, a ); va_end( a );
    return r;
}
#define dprintf pool_fg_dprintf
'''
HARNESS = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <time.h>
#include <unistd.h>
typedef unsigned short WCHAR;
typedef unsigned short USHORT;
typedef struct { USHORT Length, MaximumLength; WCHAR *Buffer; } UNICODE_STRING;
typedef struct { UNICODE_STRING ImagePathName; } RTL_USER_PROCESS_PARAMETERS;
typedef struct { RTL_USER_PROCESS_PARAMETERS *ProcessParameters; } PEB;
typedef unsigned int ULONG;
#define MB ((size_t)1 << 20)
static size_t ios_pool_head_reserve;
static PEB *current;
static ULONG current_pid;
static void *ios_jit_current_peb( void ) { return current; }
static ULONG ios_jit_current_pid( void ) { return current_pid; }
''' + funcs + region + COUNT + helper + "#undef dprintf\n" + r'''
static int fails;
#define T(c) do { if (!(c)) { printf( "FAIL line %d: %s\n", __LINE__, #c ); fails++; } } while (0)
#define TOTAL 0x37410000u
#define HO 0x22000000u
#define HE 0x23410000u
static size_t reserve = 128 * MB;   /* the lab's MADEIRA_POOL_HEAD_RESERVE_MB in that session; BCD's default is 48 */
static size_t fg_cap( size_t head, size_t tail, int on, int fg )
{
    size_t budget = ios_pool_code_cap( TOTAL, head, tail, HO, HE, reserve );
    return on ? ios_pool_code_class_cap( fg, budget ) : budget;
}
static WCHAR wbuf[260];
static size_t wide( const char *path )
{
    size_t n = 0;
    while (path[n] && n < 259) { wbuf[n] = (unsigned char)path[n]; n++; }
    return n;
}
static int inside( const char *folder, const char *path )
{
    size_t len = wide( path );
    return ios_pool_path_in_folder( wbuf, len, folder, ios_pool_game_folder_len( folder ) );
}
static int pid_fixed;
/* the production helper as the caller sees it: `path` is the calling process's image, NULL for no PEB */
static int last_fg = -1;   /* pool-fg-keep: the class ios_pool_fg_adjust reported */
static size_t adjusted( const char *folder, const char *off, const char *path, size_t head, size_t tail )
{
    static RTL_USER_PROCESS_PARAMETERS pp;
    static PEB peb;
    size_t budget;
    if (folder) setenv( "BCD_GAME_FOLDER", folder, 1 ); else unsetenv( "BCD_GAME_FOLDER" );
    if (off) setenv( "MADEIRA_POOL_CODE_FOREGROUND", off, 1 ); else unsetenv( "MADEIRA_POOL_CODE_FOREGROUND" );
    peb.ProcessParameters = &pp;
    pp.ImagePathName.Buffer = wbuf;
    pp.ImagePathName.Length = (USHORT)(wide( path ? path : "" ) * sizeof(WCHAR));
    current = path ? &peb : NULL;
    if (!pid_fixed) current_pid = path ? 0x100 + (ULONG)strlen( path ) : 0;   /* one process per program (the same PEB, as a reused window) */
    budget = ios_pool_code_cap( TOTAL, head, tail, HO, HE, ios_pool_head_reserve );
    return ios_pool_fg_adjust( budget, head, tail, &last_fg );
}
int main( void )
{
    const char *fc3 = "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Far Cry 3";
    const char *game = "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Far Cry 3\\bin\\farcry3_d3d11.exe";
    const char *upc = "C:\\Program Files (x86)\\Ubisoft\\Ubisoft Game Launcher\\upc.exe";
    size_t tail, g1, g2, i;
    /* policy off: the production numbers of the log */
    T( fg_cap( 0x12348000, 0x13018000, 0, 0 ) == 128 * MB );      /* tail BIG: granting 0x8000000 (tail_resv=0x13018000) */
    T( fg_cap( 0x124ac000, 0x1d410000, 0, 0 ) == 16 * MB );       /* tail CAP: refusing 0x8000000 (cap 0x1000000, tail_resv=0x1d410000) */
    T( fg_cap( 0x13fd0000, 0x20410000, 0, 1 ) == 16 * MB );       /* the game's big ask, as it was */
    /* policy on, the log as it was: the program being played keeps exactly today's cap; so does another program below 32 MB */
    T( fg_cap( 0x13fd0000, 0x20410000, 1, 1 ) == fg_cap( 0x13fd0000, 0x20410000, 0, 1 ) );
    T( fg_cap( 0x12348000, 0x13018000, 1, 1 ) == 128 * MB );      /* a game alone in its session: 128 MB, as today */
    T( fg_cap( 0x124ac000, 0x1d410000, 1, 0 ) == 16 * MB );
    T( fg_cap( 0x124ac000, 0x08000000, 0, 0 ) == 128 * MB );      /* early in a session a helper got 128 MB ... */
    T( fg_cap( 0x124ac000, 0x08000000, 1, 0 ) == 32 * MB );       /* ... and is held to 32 MB with the policy */
    /* the same session if the three big launcher buffers (64, 128, 128 MB) had been 32 MB each */
    tail = 0x20410000u - 224 * MB;
    g1 = fg_cap( 0x13fd0000, tail, 1, 1 );
    g2 = fg_cap( 0x13fd0000, tail + g1, 1, 1 );
    T( g1 == 64 * MB && g2 == 64 * MB );                          /* the lab's reserve 128: two overlapping 64 MB generations */
    reserve = 48 * MB;                                            /* BCD's default reserve */
    g1 = fg_cap( 0x13fd0000, tail, 1, 1 );
    g2 = fg_cap( 0x13fd0000, tail + g1, 1, 1 );
    T( g1 == 128 * MB && g2 == 64 * MB );                         /* 128 MB, then 64 MB while the first is pinned */
    T( fg_cap( 0x13fd0000, tail + g1 + g2, 1, 1 ) >= 32 * MB );   /* a third still gets 32 MB or more */
    reserve = 128 * MB;
    /* flat limit for another program, whatever the room; and the 16 MB floor is never lowered */
    for (i = 0; i < 400; i += 16) T( fg_cap( 0x10000000, i * MB, 1, 0 ) <= 32 * MB );
    T( fg_cap( 0x37000000, 0x00800000, 1, 0 ) == 16 * MB );
    /* the folder rule: inside, outside, case, separators, a prefix without a separator, empty */
    T( inside( fc3, game ) );                                                              /* the game, in its bin folder */
    T( inside( fc3, "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Far Cry 3\\farcry3.exe" ) );   /* directly in the folder */
    T( !inside( fc3, upc ) );                                                              /* Ubisoft's launcher: outside */
    T( !inside( fc3, "C:\\windows\\system32\\dockhost.exe" ) && !inside( fc3, "C:\\windows\\explorer.exe" ) );
    T( inside( "c:\\program files (x86)\\steam\\steamapps\\common\\far cry 3", game ) );   /* case of the folder */
    T( inside( fc3, "c:\\PROGRAM FILES (X86)\\STEAM\\STEAMAPPS\\COMMON\\FAR CRY 3\\BIN\\FARCRY3_D3D11.EXE" ) );   /* case of the image */
    T( inside( "C:/Program Files (x86)/Steam/steamapps/common/Far Cry 3", game ) );        /* either slash */
    T( inside( "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Far Cry 3\\", game ) ); /* a trailing separator */
    T( !inside( fc3, "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Far Cry 3 Blood Dragon\\fc3_blooddragon_d3d11.exe" ) );   /* prefix, no separator */
    T( !inside( fc3, "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Far Cry 3" ) );   /* the folder itself is no image inside it */
    T( !inside( fc3, "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Far Cry" ) && !inside( fc3, "" ) );
    T( ios_pool_game_folder_len( NULL ) == 0 && ios_pool_game_folder_len( "" ) == 0 );     /* empty: no folder */
    T( ios_pool_game_folder_len( "C:\\" ) == 0 && ios_pool_game_folder_len( "C:" ) == 0 && ios_pool_game_folder_len( "\\\\" ) == 0 );   /* a root: no folder */
    T( ios_pool_game_folder_len( "C:\\Games\\\xe4\xb8\x89" ) == 0 );                      /* outside ASCII: no folder */
    T( ios_pool_game_folder_len( "C:\\Games\\X\\\\" ) == 10 && ios_pool_game_folder_len( fc3 ) == strlen( fc3 ) );
    T( !ios_pool_path_in_folder( NULL, 0, fc3, strlen( fc3 ) ) && !ios_pool_path_in_folder( wbuf, wide( game ), NULL, 0 ) );
    /* the production helper: the 13:08:32 rows with and without a folder */
    ios_pool_head_reserve = 128 * MB;
    T( adjusted( NULL, NULL, game, 0x13fd0000, 0x20410000 ) == 16 * MB );        /* no folder: nothing changes */
    T( adjusted( "", NULL, game, 0x13fd0000, 0x20410000 ) == 16 * MB );
    T( adjusted( "C:\\", NULL, game, 0x13fd0000, 0x20410000 ) == 16 * MB );      /* a drive root: off */
    T( adjusted( fc3, NULL, game, 0x13fd0000, 0x20410000 ) == 16 * MB );         /* the game: exactly today's cap */
    T( adjusted( fc3, NULL, game, 0x13fd0000, 0x20410000 - 224 * MB ) == 64 * MB );
    T( adjusted( fc3, NULL, upc, 0x124ac000, 0x08000000 ) == 32 * MB );          /* the launcher early in the session: 32, not 128 */
    T( adjusted( fc3, "0", upc, 0x124ac000, 0x08000000 ) == 128 * MB );          /* the off switch: as before */
    T( adjusted( fc3, "0", game, 0x13fd0000, 0x20410000 ) == 16 * MB );
    T( adjusted( fc3, "1", upc, 0x124ac000, 0x08000000 ) == 32 * MB );           /* any other value: on */
    T( adjusted( fc3, NULL, NULL, 0x124ac000, 0x08000000 ) == 32 * MB );         /* no PEB: another program */
    /* pool-fg-keep: the class is reported to the allocator (its carves are held and keep their size only for the game) */
    adjusted( fc3, NULL, game, 0x13fd0000, 0x20410000 ); T( last_fg == 1 );
    adjusted( fc3, NULL, upc, 0x13fd0000, 0x20410000 ); T( last_fg == 0 );
    adjusted( fc3, "0", game, 0x13fd0000, 0x20410000 ); T( last_fg == 0 );     /* the off switch: no class */
    adjusted( NULL, NULL, game, 0x13fd0000, 0x20410000 ); T( last_fg == 0 );   /* no folder: no class */
    /* one line per process: the same process again writes none; a new process in the same window (same PEB) writes its own */
    {
        int i;
        fflush( stderr );
        log_mark = log_count();
        T( adjusted( fc3, NULL, game, 0x13fd0000, 0x20410000 ) == 16 * MB && log_count() == log_mark );   /* the game's process: logged above */
        pid_fixed = 1;
        current_pid = 0x777;                                                                               /* the copy the starter starts next */
        T( adjusted( fc3, NULL, game, 0x13fd0000, 0x20410000 ) == 16 * MB && log_count() == log_mark + 1 );
        T( adjusted( fc3, NULL, game, 0x13fd0000, 0x20410000 ) == 16 * MB && log_count() == log_mark + 1 );
        for (i = 0; i < 100; i++) { current_pid = 0x1000 + i; adjusted( fc3, NULL, upc, 0x124ac000, 0x08000000 ); }
        T( log_count() <= 64 );                                                                             /* at most 64 processes */
        pid_fixed = 0;
    }
    puts( fails ? "FAILED" : "ok: log rows, the game keeps today's cap, others at most 32 MB, two overlapping generations, folder rule, helper and off switch, one line per process" );
    return fails != 0;
}
'''
cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
with tempfile.TemporaryDirectory() as tmp:
    c = Path(tmp) / "t.c"; c.write_text(HARNESS); exe = Path(tmp) / "t"
    r = subprocess.run([cc, "-std=c11", "-D_POSIX_C_SOURCE=200809L", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                        "-fsanitize=address,undefined", "-fno-sanitize-recover=undefined", "-o", str(exe), str(c)],
                       capture_output=True, text=True)
    check("the production cap function, the policy region and the helper compile (-Werror, ASAN/UBSAN)", r.returncode == 0, r.stderr[-2000:])
    if r.returncode == 0:
        run = subprocess.run([str(exe)], capture_output=True, text=True)
        out = run.stdout + run.stderr
        print("     " + run.stdout.strip().replace("\n", "\n     "))
        check("the policy behaves as documented", run.returncode == 0, out)
        check("the helper's log line names the program and its class",
              '[pool-fg] madeira-bcd: farcry3_d3d11.exe is the program being played (game folder "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Far Cry 3"): '
              "code-buffer cap 0x1000000, 0x1000000 without the policy" in run.stderr
              and "[pool-fg] madeira-bcd: upc.exe is another program" in run.stderr
              and "[pool-fg] madeira-bcd: (no image path) is another program" in run.stderr, run.stderr[-1500:])
sys.exit(0 if ok else 1)
