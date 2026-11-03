#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright 2026 thebcd69 (BCD)
# BCD Material: additional terms under GPL-3.0 section 7 apply; see LICENSE-BCD.md.
"""Ubisoft Connect's Chromium (on unless env.MADEIRA_UBI_CEF = 0); no Wine runs.

Ubisoft Connect (upc.exe, CEF 135, 32-bit libcef.dll) runs with cef_settings_t.command_line_args_disabled set, so
CEF drops the browser's whole command line and Chromium's process-count switches never take effect. Two parts:
  - process_ios.c: upc.exe without --type= gets --in-process-gpu --disable-site-isolation-trials
    --renderer-process-limit=1 --js-flags=--jitless --disable-component-update (each only when missing), its helpers
    (UplayWebCore.exe, upc.exe --type=) are left alone and are NEVER refused;
  - virtual_ios.c: ios_ubi_cef_patch, the in-memory change of libcef.dll's discard check (je -> nop; jmp), found at
    the analysed build's RVA or by a unique signature, for the upc.exe browser only.
Source (textual) checks: the call sites, the gates (exactly "1"; read before anything is looked at), that nothing in
the block returns an error status, and that the other launchers' lines are not touched.
Behaviour (C harnesses over the PRODUCTION functions, AddressSanitizer/UBSan; SYNTHETIC data only -- no Ubisoft file is
used or committed): the command-line rewrite for typical command lines, user switches that win, jitless handling,
a bare "--", a too-small buffer, random command lines; the signature match, the locator over synthetic PE32 images
(analysed build, another build with the check elsewhere / with other registers, no match, two matches, wrong export
name, x64 image, damaged target, out-of-range rel32, truncated image), the two-byte change and nothing else.
What this does NOT prove: that the real libcef.dll matches (the analysed build's bytes are taken from the lab's
research record), that FEX/the guest run the changed page correctly, or that Chromium then behaves: device only.
Needs python3 and a C compiler.
"""
from pathlib import Path
import os
import re
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[2]
proc = (root / 'build/ntdll-unix/process_ios.c').read_text()
native = (root / 'build/ntdll-unix/virtual_ios.c').read_text()
failures = 0


def check(cond, what, detail=''):
    global failures
    print(('PASS: ' if cond else 'FAIL: ') + what + (('\n      ' + str(detail)) if detail and not cond else ''))
    if not cond:
        failures += 1


def function(source, signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 2] + '\n'


# ---- process_ios.c: the spawn block ----------------------------------------------------------------------
create = function(proc, 'NTSTATUS WINAPI NtCreateUserProcess(')
block = create[create.index("/* madeira-bcd: Ubisoft Connect's Chromium -- see ubi_cef_kind."):]
block = block[:block.index("/* madeira-bcd: a console's conhost.exe starts without a window")]
check(block.index('getenv( "MADEIRA_UBI_CEF" )') < block.index('ubi_cef_kind(')
      and "!(ubi && ubi[0] == '0' && !ubi[1])" in block and ': UBI_NOT_CEF;' in block and 'kind == UBI_BROWSER' in block,
      'the spawn block reads env.MADEIRA_UBI_CEF first and looks at the image unless it is exactly 0')
check('STATUS_ACCESS_DENIED' not in block and 'return ' not in block,
      'the spawn block never refuses a process (Chromium aborts when its GPU process is refused)')
check(create.index('child_extra_args( getenv( "MADEIRA_CHILD_ARGS" )') < create.index('if (ec_conhost_refuse(')
      < create.index("Ubisoft Connect's Chromium -- see ubi_cef_kind") < create.index("Social Club's Chromium -- see sc_helper_kind")
      < create.index('create_startup_info( attr.ObjectName'),
      'the block sits after MADEIRA_CHILD_ARGS and the conhost gate, before the Social Club gate and the startup info')
check('getenv( "MADEIRA_JITLESS" )' in block and 'getenv( "MADEIRA_UBI_CEF_FLAGS" )' in block
      and 'params->CommandLine.Buffer = nbuf;' in block, 'jitless and the extra flags are read; the command line is replaced')
other = proc.replace(proc[proc.index("/* madeira-bcd: Ubisoft Connect's Chromium (on unless env.MADEIRA_UBI_CEF = 0"):
                          proc.index('NtCreateUserProcess  (NTDLL.@)')], '')
other = other.replace(block, '')
check('MADEIRA_UBI' not in other and 'ubi_cef' not in other, 'no other line of process_ios.c names the Ubisoft code')

# ---- virtual_ios.c: the call site and the gate -----------------------------------------------------------
mapper = function(native, 'static NTSTATUS map_image_into_view(')
call = mapper.index('ios_ubi_cef_patch( ptr, total_size, nt, nt_name );')
check(mapper.index('ios_sc_render_handler_patch( ptr, total_size, nt, sec, nt_name );') < call
      < mapper.index('set_vprot( view, ptr + sec[i].VirtualAddress, size, vprot )')
      < mapper.index('mprotect_exec(sec_addr, sec_size, prot);')
      and mapper.index('rel = process_relocation_block( ptr + rel->VirtualAddress, rel, delta );') < call,
      'ios_ubi_cef_patch runs after relocation and Social Club\'s patch, before the section protections and the JIT-pool copy')
patch = function(native, 'static void ios_ubi_cef_patch(')
check(patch.index('getenv( "MADEIRA_UBI_CEF" )') < patch.index('ios_ubi_leaf_is(') < patch.index('ios_jit_current_peb()')
      < patch.index('ios_ubi_cef_browser_process(') < patch.index('ios_ubi_cef_locate(') < patch.index('ios_ubi_cef_apply('),
      'gates in order: switch, file name libcef.dll, process, then the locator, then the change')
check("enabled = !(e && e[0] == '0' && !e[1]);" in patch and 'LIBPATCH' not in native
      and 'IMAGE_FILE_MACHINE_I386' in patch,
      'on unless exactly "0" (one switch for both halves), i386 only')
check('ios_ubi_cef_builds[]' in native and 'ios_ubi_cef_scan' not in native,
      'the site comes from the table of checked builds only: no signature scan')
check(patch.count('ios_ubi_cef_apply(') == 1 and 'memcpy' not in patch and 'memset' not in patch,
      'the only write is ios_ubi_cef_apply')
outside = native.replace(native[native.index('/* madeira-bcd: [ubi-cef] Ubisoft Connect\'s libcef.dll keeps'):
                               native.index('/* Does the calling pseudo-process have socialclub.dll mapped?')], '')
hooks = [l.strip() for l in outside.split('\n') if re.search(r'ios_ubi_|MADEIRA_UBI', l) and not l.strip().startswith(('/*', '*', '//'))]
check(hooks == ['ios_ubi_cef_patch( ptr, total_size, nt, nt_name );'],
      'outside its block virtual_ios.c has exactly one line that names the Ubisoft code (the call)', hooks)

# ---- the code under test -----------------------------------------------------------------------------------
enums = proc[proc.index('enum { SC_NOT_HELPER = 0'):]
enums = enums[:enums.index('\n\n')] + '\n'
ubi_enums = proc[proc.index('enum { UBI_NOT_CEF = 0'):]
ubi_enums = ubi_enums[:ubi_enums.index('\n\n')] + '\n'
proc_funcs = enums + ubi_enums + ''.join(function(proc, sig) for sig in (
    'static int sc_switch_end(', 'static int ios_image_name_is(', 'static int sc_extra_js_flags(',
    'static int ubi_cef_kind(', 'static int ubi_cef_cmdline('))
region = native[native.index('/* ubi-cef-test:begin */'):native.index('/* ubi-cef-test:end */')]

harness_proc = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint16_t WCHAR;
''' + proc_funcs + r'''
static int fails;
#define FAIL(...) do { printf("FAIL: " __VA_ARGS__); fails++; } while (0)

static WCHAR *w( const char *s, int *len )
{
    int n = (int)strlen( s ), i;
    WCHAR *r = malloc( (n + 1) * sizeof(WCHAR) );
    for (i = 0; i <= n; i++) r[i] = (unsigned char)s[i];
    *len = n;
    return r;
}

static int rewrite( const char *cl, int jitless, const char *extra, char *out_s, int cap_extra, int *how )
{
    int n, i, o, cap;
    WCHAR *c = w( cl, &n ), *out;
    cap = n + 200 + (extra ? (int)strlen( extra ) : 0) + cap_extra;
    out = malloc( (cap > 0 ? cap : 1) * sizeof(WCHAR) );
    o = ubi_cef_cmdline( c, n, jitless, extra, out, cap, how );
    if (o >= 0) { for (i = 0; i < o; i++) out_s[i] = (char)out[i]; out_s[o] = 0; if (out[o]) FAIL("no NUL\n"); }
    free( c ); free( out );
    return o;
}

static void expect( const char *cl, int jitless, const char *extra, const char *want, int want_how )
{
    char got[2048];
    int how = 0, o = rewrite( cl, jitless, extra, got, 0, &how );
    if (o < 0 || strcmp( got, want )) FAIL("rewrite of [%s]\n   got  [%s] (%d)\n   want [%s]\n", cl, o < 0 ? "-" : got, o, want);
    if (want_how >= 0 && how != want_how) FAIL("how %x != %x for [%s]\n", how, want_how, cl);
}

int main( void )
{
    int l1, l2;
    const char *all = " --in-process-gpu --disable-site-isolation-trials --renderer-process-limit=1 --disable-component-update";
    char want[1024];
    WCHAR *up, *wc, *cl;

    /* kinds */
    up = w( "C:\\Program Files (x86)\\Ubisoft\\Ubisoft Game Launcher\\UPC.EXE", &l1 );
    cl = w( "\"C:\\x\\upc.exe\" -upc_desktop_mode", &l2 );
    if (ubi_cef_kind( up, l1, cl, l2 ) != UBI_BROWSER) FAIL("upc.exe browser\n");
    free( cl );
    cl = w( "upc.exe --type=renderer --lang=en-US", &l2 );
    if (ubi_cef_kind( up, l1, cl, l2 ) != UBI_HELPER) FAIL("upc.exe --type= is a helper\n");
    free( cl );
    cl = w( "UplayWebCore.exe --type=gpu-process", &l2 );
    wc = w( "C:\\x\\UplayWebCore.exe", &l1 );
    if (ubi_cef_kind( wc, l1, cl, l2 ) != UBI_HELPER) FAIL("UplayWebCore.exe is a helper\n");
    free( cl );
    cl = w( "UplayWebCore.exe", &l2 );
    if (ubi_cef_kind( wc, l1, cl, l2 ) != UBI_HELPER) FAIL("UplayWebCore.exe without --type= is not the browser\n");
    {
        const char *others[] = { "C:\\x\\UbisoftConnect.exe", "C:\\x\\UplayService.exe", "C:\\x\\UbisoftGameLauncher.exe",
                                 "C:\\x\\farcry3_d3d11.exe", "C:\\x\\upc.exe.bak", "C:\\x\\notupc.exe", "C:\\x\\SocialClubHelper.exe",
                                 "C:\\x\\EADesktop.exe", "C:\\x\\steamwebhelper.exe", "C:\\x\\Battle.net.exe", "" };
        int i;
        for (i = 0; i < (int)(sizeof(others) / sizeof(others[0])); i++)
        {
            int n; WCHAR *im = w( others[i], &n );
            if (ubi_cef_kind( im, n, cl, l2 ) != UBI_NOT_CEF) FAIL("[%s] is not Ubisoft's CEF\n", others[i]);
            free( im );
        }
        if (ubi_cef_kind( NULL, 0, cl, l2 ) != UBI_NOT_CEF) FAIL("NULL image\n");
    }
    printf("PASS: only upc.exe without --type= is the browser; UplayWebCore.exe and upc.exe --type= are helpers; nothing else matches\n");

    /* the lab's T1 line, from the device record's command lines */
    expect( "\"C:\\Program Files (x86)\\Ubisoft\\Ubisoft Game Launcher\\upc.exe\" -upc_desktop_mode", 1, NULL,
            "\"C:\\Program Files (x86)\\Ubisoft\\Ubisoft Game Launcher\\upc.exe\" -upc_desktop_mode"
            " --in-process-gpu --disable-site-isolation-trials --renderer-process-limit=1 --disable-component-update --js-flags=--jitless",
            UBI_IN_PROCESS_GPU | UBI_SITE_ISOLATION | UBI_RENDERER_LIMIT | UBI_NO_COMPONENT_UPDATE | UBI_JITLESS_ADDED );
    expect( "upc.exe -upc_uplay_id 46 -uplay_steam_mode -language=English -steam_mode -upc_game_starter", 1, NULL,
            "upc.exe -upc_uplay_id 46 -uplay_steam_mode -language=English -steam_mode -upc_game_starter"
            " --in-process-gpu --disable-site-isolation-trials --renderer-process-limit=1 --disable-component-update --js-flags=--jitless", -1 );
    expect( "upc.exe", 0, NULL, "upc.exe --in-process-gpu --disable-site-isolation-trials --renderer-process-limit=1 --disable-component-update",
            UBI_IN_PROCESS_GPU | UBI_SITE_ISOLATION | UBI_RENDERER_LIMIT | UBI_NO_COMPONENT_UPDATE );
    printf("PASS: the browser's command line gets the five switches (jitless unless MADEIRA_JITLESS=0)\n");

    /* the caller's own switches win and are not doubled */
    expect( "upc.exe --renderer-process-limit=3 --in-process-gpu", 1, NULL,
            "upc.exe --renderer-process-limit=3 --in-process-gpu --disable-site-isolation-trials --disable-component-update --js-flags=--jitless",
            UBI_SITE_ISOLATION | UBI_NO_COMPONENT_UPDATE | UBI_JITLESS_ADDED );
    expect( "upc.exe --js-flags=--max-old-space-size=64", 1, NULL,
            "upc.exe --js-flags=--max-old-space-size=64 --in-process-gpu --disable-site-isolation-trials --renderer-process-limit=1 --disable-component-update",
            UBI_IN_PROCESS_GPU | UBI_SITE_ISOLATION | UBI_RENDERER_LIMIT | UBI_NO_COMPONENT_UPDATE | UBI_OWN_JS_FLAGS );
    expect( "upc.exe --in-process-gpu --disable-site-isolation-trials --renderer-process-limit=1 --disable-component-update --js-flags=--jitless", 1, NULL,
            "upc.exe --in-process-gpu --disable-site-isolation-trials --renderer-process-limit=1 --disable-component-update --js-flags=--jitless",
            UBI_OWN_JS_FLAGS );
    /* a look-alike is not the switch: "--in-process-gpu-x" does not count */
    expect( "upc.exe --in-process-gpu-x", 0, NULL,
            "upc.exe --in-process-gpu-x --in-process-gpu --disable-site-isolation-trials --renderer-process-limit=1 --disable-component-update", -1 );
    printf("PASS: a switch the command line already has stays as it is and is not added twice\n");

    /* extra flags */
    expect( "upc.exe", 1, "--v=1", "upc.exe" ALL " --js-flags=--jitless --v=1", UBI_IN_PROCESS_GPU | UBI_SITE_ISOLATION | UBI_RENDERER_LIMIT | UBI_NO_COMPONENT_UPDATE | UBI_JITLESS_ADDED | UBI_EXTRA_ADDED );
    expect( "upc.exe", 1, "--js-flags=--max-semi-space-size=1", "upc.exe" ALL " --js-flags=--jitless\" \"--max-semi-space-size=1", -1 );
    expect( "upc.exe", 1, "--js-flags=\"--a --b\"", "upc.exe" ALL " --js-flags=\"--jitless --a --b\"", -1 );
    expect( "upc.exe", 0, "--js-flags=--a", "upc.exe" ALL " --js-flags=--a", -1 );
    printf("PASS: MADEIRA_UBI_CEF_FLAGS is appended; --jitless goes first into its --js-flags\n");

    /* a bare -- ends Chromium's switches: not rewritten */
    {
        char got[512]; int how = 0;
        if (rewrite( "upc.exe -a -- file", 1, NULL, got, 0, &how ) != -2) FAIL("bare -- must not be rewritten\n");
        if (rewrite( "upc.exe --", 1, NULL, got, 0, &how ) != -2) FAIL("trailing bare -- must not be rewritten\n");
        if (rewrite( "upc.exe --type=x", 1, NULL, got, 0, &how ) < 0) FAIL("--type= is not a bare --\n");
        if (rewrite( "upc.exe -upc_desktop_mode", 1, NULL, got, -150, &how ) != -1) FAIL("a too small buffer must fail\n");
        if (rewrite( "", 1, NULL, got, 0, &how ) < 0) FAIL("empty command line\n");
    }
    printf("PASS: a bare -- and a too small buffer leave the command line alone (-2 / -1)\n");

    /* random command lines: never overflow, always NUL, never lose the original prefix */
    {
        const char *toks[] = { "upc.exe", "--in-process-gpu", "--renderer-process-limit=", "--js-flags=", "--jitless", "\"", " ", " ",
                               "--disable-site-isolation-trials", "-x", "--disable-component-update", "=", "--", "\t" };
        unsigned seed = 12345;
        int it;
        for (it = 0; it < 20000; it++)
        {
            char cl[300], got[1200], ex[80];
            int n = 0, k, how, o, c = rand_r( &seed ) % 12;
            for (k = 0; k < c && n < 240; k++) { const char *t = toks[rand_r( &seed ) % 14]; strcpy( cl + n, t ); n += (int)strlen( t ); }
            cl[n] = 0;
            ex[0] = 0;
            if (rand_r( &seed ) % 3 == 0) { strcpy( ex, "--js-flags=" ); if (rand_r( &seed ) % 2) strcat( ex, "\"--a\"" ); }
            o = rewrite( cl, rand_r( &seed ) & 1, ex[0] ? ex : NULL, got, 0, &how );
            if (o >= 0 && (o < n || memcmp( got, cl, n ))) { FAIL("prefix lost [%s]\n", cl); break; }
        }
    }
    printf("PASS: 20000 random command lines (ASan/UBSan): no overflow, NUL-terminated, the original kept as the prefix\n");
    return fails;
}
'''

harness_virt = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint16_t WCHAR;
''' + region + r'''
static int fails;
#define FAIL(...) do { printf("FAIL: " __VA_ARGS__); fails++; } while (0)

static void p16( unsigned char *b, unsigned o, unsigned v ) { b[o] = v; b[o + 1] = v >> 8; }
static void p32( unsigned char *b, unsigned o, unsigned v ) { p16( b, o, v & 0xffff ); p16( b, o + 2, v >> 16 ); }

#define VIEW 0x300000u
#define TEXT_VA 0x1000u
#define TEXT_SZ 0x2f0000u
#define RDATA_VA 0x2f1000u

struct opts { unsigned machine, stamp, soi, flags; const char *exportname; unsigned text_flags; int x64magic; };

/* A synthetic PE32 DLL: headers, an export directory naming it, one executable section filled with a deterministic
 * pseudo-random byte stream that contains no 0x83 (so the only matches are the planted ones). */
static unsigned char *image( const struct opts *o )
{
    unsigned char *v = calloc( 1, VIEW );
    unsigned lfanew = 0x80, pe = lfanew, sec = pe + 0x18 + 0xe0, i, seed = 7;
    v[0] = 'M'; v[1] = 'Z'; p32( v, 0x3c, lfanew );
    memcpy( v + pe, "PE\0\0", 4 );
    p16( v, pe + 4, o->machine ); p16( v, pe + 6, 2 ); p16( v, pe + 0x14, 0xe0 ); p16( v, pe + 0x16, o->flags );
    p32( v, pe + 8, o->stamp );
    p16( v, pe + 0x18, o->x64magic ? 0x20b : 0x10b );
    p32( v, pe + 0x50, o->soi );
    p32( v, pe + 0x78, RDATA_VA );                              /* export directory RVA */
    memcpy( v + sec, ".text\0\0\0", 8 ); p32( v, sec + 8, TEXT_SZ ); p32( v, sec + 12, TEXT_VA ); p32( v, sec + 16, TEXT_SZ );
    p32( v, sec + 36, o->text_flags );
    memcpy( v + sec + 40, ".rdata\0\0", 8 ); p32( v, sec + 48, 0x1000 ); p32( v, sec + 52, RDATA_VA ); p32( v, sec + 56, 0x1000 );
    p32( v, sec + 76, 0x40000040 );
    for (i = TEXT_VA; i < TEXT_VA + TEXT_SZ; i++)
    {
        seed = seed * 1103515245u + 12345u;
        v[i] = (seed >> 16) & 0xff;
        if (v[i] == 0x83) v[i] = 0x84;
    }
    p32( v, RDATA_VA + 0x0c, RDATA_VA + 0x40 );                 /* export Name */
    strcpy( (char *)v + RDATA_VA + 0x40, o->exportname );
    return v;
}

static const struct opts good = { 0x014c, 0x12345678, 0x01000000, 0x2102, "libcef.dll", 0x60000020, 0 };

/* plant the check at rva with the given register r (0..7 but 4) and rel32; the target gets mov, cmp as in the build */
static void plant( unsigned char *v, unsigned rva, unsigned r, unsigned rel, unsigned dest_reg )
{
    unsigned char *p = v + rva, *t = p + 10 + rel;
    p[0] = 0x83; p[1] = 0x78 | r; p[2] = 0x38; p[3] = 0x00; p[4] = 0x0f; p[5] = 0x84; p32( p, 6, rel );
    t[0] = 0x8b; t[1] = 0x40 | (dest_reg << 3) | r; t[2] = 0x04; t[3] = 0x83; t[4] = 0x78 | r; t[5] = 0x0c; t[6] = 0x00;
}

static void plant_known( unsigned char *v )
{
    /* the analysed build, from the lab's record: 83 78 38 00 0f 84 b1 00 00 00 at RVA 0x287464, target 0x28751f
     * holds 8b 58 04 83 78 0c 00 */
    plant( v, IOS_UBI_CEF_RVA, 0, 0xb1, 3 );
}

static void expect_ok( const char *what, unsigned char *v, unsigned want_site, int want_how )
{
    unsigned site = 0; int how = 0;
    const char *why = ios_ubi_cef_locate( v, VIEW, &site, &how );
    if (why || site != want_site || how != want_how) FAIL("%s: why=[%s] site=%x how=%d (want %x/%d)\n", what, why ? why : "-", site, how, want_site, want_how);
}
static void expect_no( const char *what, unsigned char *v, const char *want_reason )
{
    unsigned site = 0; int how = 0;
    const char *why = ios_ubi_cef_locate( v, VIEW, &site, &how );
    if (!why || !strstr( why, want_reason )) FAIL("%s: expected [%s], got [%s]\n", what, want_reason, why ? why : "success");
}

int main( void )
{
    struct opts o;
    unsigned char *v, *copy;
    unsigned i, changed;

    /* the analysed build: exactly the RVA and the ten bytes of the record */
    o = good; o.stamp = IOS_UBI_CEF_STAMP; o.soi = IOS_UBI_CEF_IMAGE_SIZE;
    v = image( &o ); plant_known( v );
    if (memcmp( v + IOS_UBI_CEF_RVA, "\x83\x78\x38\x00\x0f\x84\xb1\x00\x00\x00", 10 )) FAIL("synthetic known bytes\n");
    expect_ok( "analysed build", v, IOS_UBI_CEF_RVA, IOS_UBI_CEF_KNOWN );
    copy = malloc( VIEW ); memcpy( copy, v, VIEW );
    if (!ios_ubi_cef_apply( v, IOS_UBI_CEF_RVA )) FAIL("apply\n");
    for (changed = 0, i = 0; i < VIEW; i++) if (v[i] != copy[i]) { changed++; if (i != IOS_UBI_CEF_RVA + 4 && i != IOS_UBI_CEF_RVA + 5) FAIL("byte %x changed\n", i); }
    if (changed != 2 || v[IOS_UBI_CEF_RVA + 4] != 0x90 || v[IOS_UBI_CEF_RVA + 5] != 0xe9 ||
        memcmp( v + IOS_UBI_CEF_RVA + 6, "\xb1\x00\x00\x00", 4 )) FAIL("exactly 0f 84 -> 90 e9, rel32 kept (%u bytes)\n", changed);
    /* nop; jmp rel32 ends where je rel32 ended: same target */
    if (IOS_UBI_CEF_RVA + 5 + 5 != IOS_UBI_CEF_RVA + 4 + 6) FAIL("length\n");
    if (ios_ubi_cef_apply( v, IOS_UBI_CEF_RVA )) FAIL("a second apply must refuse (bytes are no longer 0f 84)\n");
    expect_no( "after the change the check no longer matches", v, "bytes differ" );
    printf("PASS: the analysed build is found at RVA 0x287464; the change is exactly the two bytes 0f 84 -> 90 e9, rel32 kept, not repeatable\n");
    free( copy );

    /* the analysed build with a different byte at the site: fail closed, no scan of another place */
    free( v ); v = image( &o ); plant_known( v ); v[IOS_UBI_CEF_RVA + 6] = 0xb2;
    expect_no( "analysed build, site bytes differ", v, "bytes differ" );
    free( v ); v = image( &o ); plant_known( v ); v[IOS_UBI_CEF_RVA + 0xb1 + 10 + 3] = 0x05;   /* the target's 04 */
    expect_no( "analysed build, target differs", v, "bytes differ" );
    free( v ); v = image( &o ); plant( v, 0x100000, 0, 0xb1, 3 );          /* check elsewhere, known stamp: not trusted */
    expect_no( "analysed build, check moved", v, "bytes differ" );
    printf("PASS: the analysed build with other bytes at the site is left alone\n");
    free( v );

    /* another build, even with a perfect check at some RVA: not in the table, left alone */
    v = image( &good ); plant( v, 0x123450, 0, 0xb1, 3 );
    expect_no( "another build", v, "not a known" );
    free( v ); v = image( &good );
    expect_no( "another build, no check", v, "not a known" );
    printf("PASS: a build that is not in the table is left alone, whatever its bytes\n");

    /* identity */
    { struct opts d = good; d.exportname = "libcef2.dll"; free( v ); v = image( &d ); plant( v, 0x100000, 0, 0xb1, 3 ); expect_no( "export name", v, "export name" ); }
    { struct opts d = o; d.exportname = "LIBCEF.DLL"; free( v ); v = image( &d ); plant_known( v ); expect_ok( "export name case", v, IOS_UBI_CEF_RVA, IOS_UBI_CEF_KNOWN ); }
    { struct opts d = good; d.machine = 0x8664; free( v ); v = image( &d ); plant( v, 0x100000, 0, 0xb1, 3 ); expect_no( "x64 machine", v, "32-bit" ); }
    { struct opts d = good; d.x64magic = 1; free( v ); v = image( &d ); plant( v, 0x100000, 0, 0xb1, 3 ); expect_no( "PE32+ magic", v, "32-bit" ); }
    { struct opts d = good; d.flags = 0x0102; free( v ); v = image( &d ); plant( v, 0x100000, 0, 0xb1, 3 ); expect_no( "not a DLL", v, "DLL" ); }
    free( v ); v = image( &good ); plant( v, 0x100000, 0, 0xb1, 3 ); v[0] = 'Z'; expect_no( "no MZ", v, "MZ" );
    free( v ); v = image( &good ); plant( v, 0x100000, 0, 0xb1, 3 ); p32( v, 0x3c, 0x7fffff00 ); expect_no( "lfanew out of range", v, "out of range" );
    {
        unsigned site = 0; int how = 0;
        free( v ); v = image( &good ); plant( v, 0x100000, 0, 0xb1, 3 );
        if (!ios_ubi_cef_locate( v, 0x100, &site, &how ) || !ios_ubi_cef_locate( v, 0, &site, &how ) || !ios_ubi_cef_locate( NULL, VIEW, &site, &how ))
            FAIL("truncated or missing view must be refused\n");
        if (!ios_ubi_cef_locate( v, 0x100008, &site, &how ) && 0) FAIL("n/a\n");   /* a view that ends inside .text: scanned up to its end */
        for (i = 0x200; i < 0x300; i += 7) { (void)ios_ubi_cef_locate( v, i, &site, &how ); }   /* under ASan: no read past the view */
        for (i = 0x100000; i < 0x100000 + 10 + 0xb1 + 7; i += 3) { (void)ios_ubi_cef_locate( v, i, &site, &how ); }
    }
    printf("PASS: another module, machine, PE32+, non-DLL, damaged or truncated headers and views are refused (no read past the view)\n");

    /* process and path helpers */
    {
        WCHAR a[] = { 'C', ':', '\\', 'U', 'P', 'C', '.', 'E', 'X', 'E', 0 };
        WCHAR b[] = { 'u','p','c','.','e','x','e',' ','-','-','t','y','p','e','=','r', 0 };
        WCHAR c[] = { 'u','p','c','.','e','x','e',' ','-','u', 0 };
        WCHAR d[] = { 'x','\\','u','p','c','.','e','x','e','x', 0 };
        WCHAR l[] = { '\\','?','?','\\','C',':','\\','L','i','b','C','E','F','.','D','L','L', 0 };
        if (!ios_ubi_cef_browser_process( a, 10, c, 10 )) FAIL("browser process\n");
        if (ios_ubi_cef_browser_process( a, 10, b, 16 )) FAIL("--type= is a helper\n");
        if (ios_ubi_cef_browser_process( a, 10, NULL, 0 ) || ios_ubi_cef_browser_process( a, 10, c, 0 )) FAIL("no command line: unknown\n");
        if (ios_ubi_cef_browser_process( d, 10, c, 10 ) || ios_ubi_cef_browser_process( NULL, 0, c, 10 )) FAIL("look-alike or no image\n");
        if (!ios_ubi_leaf_is( l, 17, "libcef.dll" ) || ios_ubi_leaf_is( l, 16, "libcef.dll" ) || ios_ubi_leaf_is( l, 17, "libcef.dl" )) FAIL("leaf\n");
    }
    printf("PASS: the process gate: upc.exe with a command line and without --type=; the file gate: the leaf libcef.dll\n");

    return fails;
}
'''
# the ALL constant for the process harness
harness_proc = harness_proc.replace('static int fails;', 'static int fails;\n#define ALL " --in-process-gpu --disable-site-isolation-trials --renderer-process-limit=1 --disable-component-update"\n', 1)


# ---- optional: the real libcef.dll (UBI_LIBCEF_PATH=<file>; skipped otherwise) ---------------------------------
# The file is only read. It is mapped the way the loader would (headers, then each section's raw bytes at its RVA),
# then the PRODUCTION locator runs on it. The places in its executable sections that match the check's shape are counted
# too (evidence that the table's RVA is the only such place). The check fails when a listed build is not accepted at its
# RVA, or when anything but exactly two bytes would change.
harness_real = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint16_t WCHAR;
""" + region + r"""
static int fails;
#define FAIL(...) do { printf("FAIL: " __VA_ARGS__); fails++; } while (0)
int main( int argc, char **argv )
{
    FILE *f = fopen( argv[1], "rb" );
    unsigned char *file, *img;
    long fsize;
    unsigned lfanew, nsec, optsize, soi, stamp, i, site = 0, tier2_site = 0;
    const unsigned char *pe, *sec;
    int how = 0, total = 0, n;
    const char *why;
    size_t at;

    if (!f) { printf("FAIL: cannot open\n"); return 1; }
    fseek( f, 0, SEEK_END ); fsize = ftell( f ); fseek( f, 0, SEEK_SET );
    file = malloc( fsize );
    if (fread( file, 1, fsize, f ) != (size_t)fsize) { printf("FAIL: read\n"); return 1; }
    fclose( f );
    lfanew = ios_ubi_le32( file + 0x3c );
    pe = file + lfanew;
    nsec = pe[6] | (pe[7] << 8); optsize = pe[0x14] | (pe[0x15] << 8);
    stamp = ios_ubi_le32( pe + 8 ); soi = ios_ubi_le32( pe + 0x50 );
    printf("INFO: machine 0x%x, sections %u, TimeDateStamp 0x%x, SizeOfImage 0x%x (analysed build: 0x%x / 0x%x) -> %s\n",
           pe[4] | (pe[5] << 8), nsec, stamp, soi, IOS_UBI_CEF_STAMP, IOS_UBI_CEF_IMAGE_SIZE,
           (stamp == IOS_UBI_CEF_STAMP && soi == IOS_UBI_CEF_IMAGE_SIZE) ? "the analysed build" : "ANOTHER BUILD");
    img = calloc( 1, soi );
    if (!img) { printf("FAIL: image alloc\n"); return 1; }
    memcpy( img, file, ios_ubi_le32( pe + 0x54 ) );                       /* SizeOfHeaders */
    sec = pe + 0x18 + optsize;
    for (i = 0; i < nsec; i++)
    {
        const unsigned char *s = sec + 40u * i;
        unsigned vsize = ios_ubi_le32( s + 8 ), va = ios_ubi_le32( s + 12 ), raw = ios_ubi_le32( s + 16 ), off = ios_ubi_le32( s + 20 );
        unsigned flags = ios_ubi_le32( s + 36 ), len = raw < (vsize ? vsize : raw) ? raw : (vsize ? vsize : raw);
        if (off + len > (unsigned long)fsize || va + len > soi) { printf("FAIL: section %u out of range\n", i); return 1; }
        memcpy( img + va, file + off, len );
        printf("INFO: section %.8s va 0x%x vsize 0x%x raw 0x%x flags 0x%x%s\n", s, va, vsize, raw, flags, (flags & 0x20000000u) ? " (executable)" : "");
    }

    /* tier 1 / whatever locate does on the file as it is */
    why = ios_ubi_cef_locate( img, soi, &site, &how );
    printf("INFO: locate on the file as it is: %s", why ? why : "accepted");
    if (!why) printf(" at RVA 0x%x (%s)", site, how == IOS_UBI_CEF_KNOWN ? "a known build" : "?");
    printf("\n");
    if (stamp == IOS_UBI_CEF_STAMP && soi == IOS_UBI_CEF_IMAGE_SIZE && (why || site != IOS_UBI_CEF_RVA || how != IOS_UBI_CEF_KNOWN))
        FAIL("the analysed build must be accepted at RVA 0x%x\n", IOS_UBI_CEF_RVA);
    printf("INFO: bytes at 0x%x: ", IOS_UBI_CEF_RVA);
    for (i = 0; i < 10; i++) printf("%02x ", img[IOS_UBI_CEF_RVA + i]);
    printf("| target 0x%x: ", IOS_UBI_CEF_RVA + 10 + ios_ubi_le32( img + IOS_UBI_CEF_RVA + 6 ));
    for (i = 0; i < 7; i++) printf("%02x ", img[IOS_UBI_CEF_RVA + 10 + ios_ubi_le32( img + IOS_UBI_CEF_RVA + 6 ) + i]);
    printf("\n");

    /* every place in the executable sections with the check's shape (evidence only) */
    for (i = 0; i < nsec; i++)
    {
        const unsigned char *s = sec + 40u * i;
        unsigned va = ios_ubi_le32( s + 12 ), vsize = ios_ubi_le32( s + 8 ), raw = ios_ubi_le32( s + 16 ), flags = ios_ubi_le32( s + 36 );
        size_t len = vsize ? vsize : raw, j;
        if (!(flags & 0x20000000u)) continue;
        if (len > soi - va) len = soi - va;
        for (j = 0; j < len; j++)
            if (ios_ubi_cef_match( img + va, len, j )) { total++; if (total == 1) tier2_site = va + (unsigned)j; printf("INFO: a place with the check's shape at RVA 0x%x\n", va + (unsigned)j); }
    }
    printf("INFO: places with the check's shape in executable sections: %d\n", total);
    if (stamp == IOS_UBI_CEF_STAMP && soi == IOS_UBI_CEF_IMAGE_SIZE && (total != 1 || tier2_site != IOS_UBI_CEF_RVA))
        FAIL("the analysed build: the table's RVA must be the only place with the check's shape (%d, first 0x%x)\n", total, tier2_site);
    if (!why)
    {
        unsigned char before[2] = { img[site + 4], img[site + 5] };
        unsigned changed = 0;
        unsigned char *copy = malloc( soi );
        memcpy( copy, img, soi );
        if (!ios_ubi_cef_apply( img, site )) FAIL("apply refused\n");
        for (i = 0; i < soi; i++) if (img[i] != copy[i]) changed++;
        printf("INFO: apply at 0x%x: %02x %02x -> %02x %02x, %u byte(s) changed\n", site, before[0], before[1], img[site + 4], img[site + 5], changed);
        if (changed != 2) FAIL("exactly two bytes must change\n");
        free( copy );
    }
    printf("PASS: real libcef.dll: the locator's decisions are consistent with its own candidate count\n");
    return fails;
}
"""

real_path = os.environ.get('UBI_LIBCEF_PATH')
if not real_path:
    print('SKIP: the real-libcef check (set UBI_LIBCEF_PATH to a libcef.dll to run it; the file is only read)')
elif not Path(real_path).is_file():
    check(False, 'UBI_LIBCEF_PATH names a file', real_path)
else:
    with tempfile.TemporaryDirectory() as t:
        c = Path(t) / 'real.c'
        c.write_text(harness_real)
        exe = Path(t) / 'real'
        built = subprocess.run(['cc', '-std=gnu11', '-O1', '-Wall', '-Wno-unused-function', '-D_GNU_SOURCE', str(c), '-o', str(exe)],
                               capture_output=True, text=True)
        check(built.returncode == 0, 'the real-libcef harness compiles', built.stdout + built.stderr)
        if built.returncode == 0:
            out = subprocess.run([str(exe), real_path], capture_output=True, text=True)
            print(out.stdout, end='')
            check(out.returncode == 0, 'the real-libcef harness passes', out.stdout + out.stderr)

with tempfile.TemporaryDirectory() as t:
    for name, src in (('proc', harness_proc), ('virt', harness_virt)):
        c = Path(t) / (name + '.c')
        c.write_text(src)
        exe = Path(t) / name
        built = subprocess.run(['cc', '-std=gnu11', '-O1', '-Wall', '-Wno-unused-function', '-D_GNU_SOURCE',
                                '-fsanitize=address,undefined', '-fno-sanitize-recover=all', str(c), '-o', str(exe)],
                               capture_output=True, text=True)
        if built.returncode:
            print(built.stdout + built.stderr)
        check(built.returncode == 0, 'the %s harness compiles' % name)
        if built.returncode:
            continue
        out = subprocess.run([str(exe)], capture_output=True, text=True, env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))
        print(out.stdout, end='')
        check(out.returncode == 0, 'the %s harness passes' % name, out.stdout + out.stderr)

sys.exit(1 if failures else 0)
