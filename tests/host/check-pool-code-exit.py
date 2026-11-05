#!/usr/bin/env python3
"""An exited pseudo-process's FEX code buffers go back to the pool (production code).

FEX releases a code buffer when it rotates to a new one, never when its process
exits, so every exited program's last buffer stayed live for the rest of the
session. GTA V Enhanced's first start after the Dock installs (build 514, log
2026-10-12 13:08-13:13) lost 96 MB of region C and a 128 MB tail buffer that
way, and every code buffer the game asked for was then capped at 16 MB.

The C fixture compiles the real retire, readiness, foreign-release and exit
hook functions, the real EC_CODE allocation prefix (budget cap, reuse, region
C) and the real MEM_RELEASE carve block. Fresh tail carves are placed with the
production hole helpers (the ml1039 head-range fallback is not modelled). It
replays that log's code-buffer requests, releases, exits, head cursor and
times: with MADEIRA_POOL_CODE_EXIT_RECLAIM=0 it must reproduce the log (the same
offsets, tail_resv=0x18f38000, the game held to 16 MB); by default the game
gets its 128 MB buffer. Thread scans are stubs: an allocator check, not a
device run.
"""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'build/ntdll-unix/virtual_ios.c').read_text()


def function(signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 2] + '\n'


helpers = ''.join(function(signature) for signature in (
    'static size_t ios_pool_hole_tail_start(',
    'static size_t ios_pool_hole_between(',
    'static size_t ios_pool_code_cap(',
    'static size_t ios_pool_holes_tail_start(',
    'static int ios_pool_skip_pieces(',
    'int ios_jit_low_contains(',
    'static int ios_pool_low_take(',
    'static int ios_tail_carve_in_low(',
    'static int ios_pool_preserve_code_carve(',
    'static int ios_tail_carve_ready(',
    'static unsigned ios_tail_carves_retire_owner(',
    'static int ios_tail_carve_foreign_release(',
    'static void ios_tail_carves_owner_died(',
    'static int ios_pool_fg_held(',
    'static size_t ios_pool_other_max_parse(',
    'static size_t ios_pool_other_max(',
    'static int ios_pool_lift_allowed(',
    'static size_t ios_pool_free_room(',
    'static int ios_pool_fg_keep_size(',
    'static int ios_tail_carve_mergeable(',
    'static unsigned ios_tail_carves_merge(',
    'static unsigned ios_tail_carve_cut(',
    'static int ios_pool_carve_merge_enabled(',
    'static int ios_pool_code_trim_enabled(',
    'void *ios_code_trim_control(',
    'static void ios_code_trim_owner_died(',
    'static int ios_pool_trim_pick(',
    'static time_t ios_pool_trim_asked(',
    'static size_t ios_pool_trim_cap(',
    'static unsigned ios_pool_trim_idle(',
))
# code-trim: the control block, its table and the policy's constants
trim_table = source[source.index('struct ios_code_trim\n{'):source.index('static int ios_pool_code_trim_enabled(void)')]
trim_defines = '\n'.join(line for line in source.splitlines() if line.startswith('#define IOS_POOL_TRIM_'))
assert trim_defines.count('#define') == 5
fg_defines = '\n'.join(line for line in source.splitlines()
                       if line.startswith(('#define IOS_POOL_FG_HOLD_SEC ', '#define IOS_POOL_FG_KEEP_FLOOR ', '#define IOS_POOL_CUT_MIN ',
                                           '#define IOS_POOL_FG_EXITED ', '#define IOS_POOL_FG_EXIT_HOLD_SEC ',
                                           '#define IOS_POOL_OTHER_MAX ')))
assert fg_defines.count('#define') == 6
carve_start = source.index('#define IOS_TAIL_CARVE_MAX ')
carve_table = source[carve_start:source.index('\n\n', carve_start)]
ec = source[source.index('size_t alloc_size = (*size_ptr + 0x3FFF) & ~0x3FFFUL;'):]
ec = ec[:ec.index('size_t reserve_offset, tail_added, tail_skipped = 0;')]
free_start = source.index('    if ((type & MEM_RELEASE) && ios_jit_rx_base_global && ios_jit_pool_size_global &&')
free_end = source.index('\n    }\n', source.index('/* pool address but not a live tail carve', free_start)) + 7
release_block = source[free_start:free_end]

# Where the new rules hook in.
reclaim = function('void ios_jit_reclaim_process( void *peb )')
assert reclaim.count('ios_tail_carves_owner_died( peb );') == 1
assert reclaim.index('ios_tail_carves_owner_died( peb );') > reclaim.rindex('pthread_mutex_unlock( &ios_pool_lock );'), \
    'the carve lock is never taken under the pool lock'
assert source.count('.retired = 1;') == 1, 'only an exit retires a carve'
assert source.count('ios_tail_carves[ios_tail_carve_n].retired = 0;') == 4, 'every new carve starts unretired'
assert source.count('ios_tail_carves[ios_tail_carve_n].peb = carve_peb;') == 3, 'region C, ml1039 and tail carves'
assert source.count('ios_tail_carves[ios_tail_carve_n].peb = NULL;') == 1, 'a skipped piece has no owner'
assert 'ios_tail_carves[best].peb = carve_peb;' in ec and 'ios_tail_carves[best].retired = 0;' in ec
assert ec.count('ios_tail_carve_ready( &ios_tail_carves[') == 2, 'the cap lift and the reuse share one rule'
assert ec.count('!ios_pool_fg_held( carve_fg, ios_tail_carves[') == 2, 'pool-fg-keep: the cap lift and the reuse hold alike'
assert source.count('.fg = carve_fg;') == 4 and source.count('ios_tail_carves[ios_tail_carve_n].fg = 0;') == 1 and \
    'carves[i].fg = 0;' not in source and source.count('carves[i].fg = carves[i].fg ? IOS_POOL_FG_EXITED : 0;') == 1, \
    'pool-fg-keep: every handed carve records the class; a skipped piece clears it, an exit marks it exited'
assert ec.count('if (alloc_size > cap && !trim_held && ios_pool_lift_allowed( ios_pool_fg_policy_on(), carve_fg, alloc_size ))') == 1, \
    'pool-fg-relaunch: the cap lift asks the class rule'
assert ('ios_tail_carve_scan( (char *)ios_jit_rx_base_global + ios_tail_carves[best].off,\n'
        '                                     ios_tail_carves[best].size, 1 )') in ec, 'a strict thread scan'
assert release_block.index('ios_tail_carve_foreign_release(') < release_block.index('ios_tail_carves[i].free = 1;')

fixture = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#define MB ((size_t)1 << 20)
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "failed line %d: %s\n", __LINE__, #c); exit(1); } } while (0)
#define STATUS_SUCCESS 0
#define STATUS_NO_MEMORY -1
#define FALLBACK_TAIL 2
#define FALL_THROUGH 3
#define MEM_RELEASE 0x8000
#define IOS_POOL_LOW_CARVE_MAX 0x8000000u
#define IOS_POOL_REUSE_GRACE_SEC 3
static time_t fake_now;
static time_t fake_time(time_t *t) { if (t) *t = fake_now; return fake_now; }
#define time(t) fake_time(t)
static void *ios_jit_rx_base_global, *ios_jit_rw_base_global;
uintptr_t ios_jit_low_rx_global, ios_jit_low_rw_global;
size_t ios_jit_low_size_global;
static size_t ios_jit_pool_size_global, jit_pool_offset, ios_pool_head_reserve;
static int fixture_fg;   /* pool-fg-keep: the caller is the program being played (check-pool-code-policy.py covers the class) */
static int fixture_policy;   /* pool-fg-relaunch: the classes apply (another program is held to ios_pool_other_max()) */
static int ios_pool_fg_policy_on(void) { return fixture_policy; }
static size_t ios_pool_fg_adjust( size_t budget_cap, size_t head_now, size_t tail_now, int *is_fg_out );
static size_t ios_pool_other_max(void);
static volatile size_t ios_jit_low_reserved, ios_jit_tail_reserved;
static size_t ios_jit_hole_off_eff, ios_jit_hole_end_eff, ios_jit_hole2_off, ios_jit_hole2_end;
static int ios_jit_low_full_logged;
static unsigned ios_tail_carve_n;
static pthread_mutex_t ios_tail_carve_lock = PTHREAD_MUTEX_INITIALIZER;
''' + carve_table + '\n' + fg_defines + '\n' + trim_table + trim_defines + r'''
static size_t ios_pool_fg_adjust( size_t budget_cap, size_t head_now, size_t tail_now, int *is_fg_out )
{
    (void)head_now; (void)tail_now;
    *is_fg_out = fixture_fg;
    return fixture_policy && !fixture_fg && budget_cap > ios_pool_other_max() ? ios_pool_other_max() : budget_cap;
}
static uintptr_t owner;
static int scan_busy, scans, occupied;
static void *ios_jit_current_peb(void) { return (void *)owner; }
static uintptr_t ios_wow_base(void) { return 0; }
static int ios_tail_carve_scan(const void *base, size_t size, int strict)
{ (void)base; (void)size; CHECK(strict == 1); CHECK(++scans < 64); return scan_busy; }   /* < 64: no retry loop */
static int ios_tail_carve_occupied(const void *base, size_t size)
{ (void)base; (void)size; return occupied; }
''' + helpers + r'''
static int allocate(size_t *size_ptr, void **ret)
{
''' + ec + r'''
    return FALLBACK_TAIL;  /* the production tail path starts after this prefix */
}
static int release(void *base, unsigned type, void **addr_ptr, size_t *size_ptr)
{
''' + release_block + r'''
    return FALL_THROUGH;
}

/* The production tail placement (holes, skipped pieces, collision limits). */
static int tail_carve(size_t *size_ptr, void **ret)
{
    size_t total = ios_jit_pool_size_global, size = (*size_ptr + 0x3fff) & ~(size_t)0x3fff;
    size_t cur = ios_jit_tail_reserved, po[3], ps[3];
    size_t start = ios_pool_holes_tail_start(total, cur, size, ios_jit_hole_off_eff, ios_jit_hole_end_eff,
                                             ios_jit_hole2_off, ios_jit_hole2_end);
    int n = 0, k;

    if (start + size > total / 4 * 3 || total - start - size < jit_pool_offset) return STATUS_NO_MEMORY;
    if (start != cur)
        n = ios_pool_skip_pieces(total - start, total - cur, ios_jit_hole_off_eff, ios_jit_hole_end_eff,
                                 ios_jit_hole2_off, ios_jit_hole2_end, po, ps);
    ios_jit_tail_reserved = start + size;
    CHECK(ios_tail_carve_n + 1 + n <= IOS_TAIL_CARVE_MAX);
    ios_tail_carves[ios_tail_carve_n++] = (struct ios_tail_carve){ .off = total - start - size, .size = size,
                                                                   .peb = (void *)owner, .fg = fixture_fg, .granted_at = fake_now };
    for (k = 0; k < n; k++)
        if (ps[k] >= MB)
            ios_tail_carves[ios_tail_carve_n++] = (struct ios_tail_carve){ .off = po[k], .size = ps[k], .free = 1 };
    *ret = (char *)ios_jit_rx_base_global + total - start - size;
    *size_ptr = size;
    return STATUS_SUCCESS;
}

/* FEX's CodeBuffer: ask, halve on refusal. */
static size_t fex_ask(uintptr_t peb, size_t want, void **rx)
{
    owner = peb;
    for (size_t ask = want; ask >= 0x4000; ask >>= 1)
    {
        size_t size = ask;
        int status = allocate(&size, rx);
        if (status == FALLBACK_TAIL) status = tail_carve(&size, rx);
        if (status == STATUS_SUCCESS) return size;
    }
    return 0;
}

static void fex_release(uintptr_t peb, void *rx)
{
    void *addr = NULL;
    size_t size = 0;
    owner = peb;
    CHECK(release(rx, MEM_RELEASE, &addr, &size) == STATUS_SUCCESS && addr == rx && size);
}

struct proc { uintptr_t peb; void *misc, *code; size_t code_size; };
static char *pool, *low;

static size_t off_of(const void *rx) { return (size_t)((const char *)rx - pool); }
static size_t c_off(const void *rx) { return (size_t)((const char *)rx - low); }

static void start(struct proc *p, uintptr_t peb, time_t t, size_t head)
{
    fake_now = t;
    jit_pool_offset = head;
    p->peb = peb;
    CHECK(fex_ask(peb, 0x4000, &p->misc) == 0x4000);
    p->code_size = fex_ask(peb, 16 * MB, &p->code);
    CHECK(p->code_size >= 16 * MB);
}

/* A full buffer: the next generation first, the old one released after. */
static size_t rotate(struct proc *p, time_t t, size_t head)
{
    void *old = p->code;
    fake_now = t;
    jit_pool_offset = head;
    p->code_size = fex_ask(p->peb, 128 * MB, &p->code);
    CHECK(p->code_size);
    fex_release(p->peb, old);
    return p->code_size;
}

/* FEX frees its dispatcher at exit, never its code buffer; then the reclaim. */
static void quit(struct proc *p, time_t t)
{
    fake_now = t;
    fex_release(p->peb, p->misc);
    owner = p->peb;
    ios_tail_carves_owner_died((void *)p->peb);
}

static void reset(void)
{
    ios_jit_rx_base_global = ios_jit_rw_base_global = pool;
    ios_jit_pool_size_global = 0x38000000;
    ios_jit_low_rx_global = ios_jit_low_rw_global = (uintptr_t)low;   /* above the pool: no wrapping offsets */
    ios_jit_low_size_global = 0x71d0000;
    ios_jit_low_reserved = ios_jit_tail_reserved = 0;
    ios_jit_hole_off_eff = 0x270c8000;
    ios_jit_hole_end_eff = 0x277cc000;
    ios_jit_hole2_off = ios_jit_hole2_end = 0;
    ios_pool_head_reserve = 128 * MB;
    ios_jit_low_full_logged = scan_busy = scans = occupied = 0;
    memset(ios_tail_carves, 0, sizeof(ios_tail_carves));
    ios_tail_carve_n = 0;
}

static unsigned retired_count(void)
{
    unsigned i, n = 0;
    for (i = 0; i < ios_tail_carve_n; i++) n += ios_tail_carves[i].free && ios_tail_carves[i].retired;
    return n;
}

/* GTA5_Enhanced.exe, build 514, 2026-10-12: seconds after 13:09:00, the head
 * cursor at each request, peb names the process. Returns the game's second
 * buffer. With the switch off every grant is checked against the log. */
static size_t replay(int fix)
{
    struct proc dock, play, l1, rs1, rs2, rs3, l2, rs4, rs5, sch, gta;
    size_t got;

    reset();
    if (fix) unsetenv("MADEIRA_POOL_CODE_EXIT_RECLAIM");
    else setenv("MADEIRA_POOL_CODE_EXIT_RECLAIM", "0", 1);
    start(&dock, 0x106914000, 20, 0x2ed8000);
    start(&play, 0x106980000, 24, 0x7540000);
    start(&l1, 0x1069ac000, 25, 0x9994000);
    start(&rs1, 0x1069c4000, 27, 0xc524000);
    start(&rs2, 0x1069c8000, 27, 0xe7e0000);
    CHECK(c_off(dock.code) == 0x4000 && c_off(rs2.code) == 0x4014000 && ios_jit_low_reserved == 0x5014000);
    quit(&rs1, 28);
    CHECK(rotate(&rs2, 41, 0x11fb8000) == 128 * MB && off_of(rs2.code) == 0x30000000);
    start(&rs3, 0x106778000, 74, 0x11fb8000);
    CHECK(ios_tail_carve_n == 11);                               /* "free_left=11" */
    if (fix) CHECK(c_off(rs3.code) == 0x3010000 && scans == 1);  /* rs1's buffer, 46 s after its exit */
    else CHECK(c_off(rs3.code) == 0x4014000 && !scans);
    quit(&rs3, 75);
    quit(&l1, 75);
    quit(&play, 75);
    start(&l2, 0x10697c000, 75, 0x132c4000);
    quit(&rs2, 75);
    if (fix) CHECK(retired_count() == 4 && c_off(l2.code) == 0x4014000);   /* rs3 l1 play: 16 MB; rs2: 128 MB */
    else CHECK(!retired_count() && c_off(l2.code) == 0x5014000);
    start(&rs4, 0x1069a8000, 77, 0x15378000);                    /* 2 s after the exits: nothing retired is ready */
    if (fix) CHECK(c_off(rs4.code) == 0x5014000 && scans == 1);
    else CHECK(c_off(rs4.code) == 0x6014000);
    start(&rs5, 0x1069b0000, 78, 0x15cfc000);
    if (fix) CHECK(c_off(rs5.code) == 0x1008000 && scans == 2 && ios_jit_tail_reserved == 128 * MB);
    else CHECK(off_of(rs5.code) == 0x2f000000 && ios_jit_tail_reserved == 0x9000000);
    quit(&rs4, 78);
    start(&sch, 0x1069bc000, 82, 0x16680000);
    if (fix) CHECK(c_off(sch.code) == 0x200c000 && scans == 3);
    else CHECK(off_of(sch.code) == 0x2e000000 && ios_jit_tail_reserved == 0xa000000);
    CHECK(rotate(&sch, 83, 0x17004000) == 128 * MB);
    if (fix) CHECK(off_of(sch.code) == 0x30000000 && scans == 4 && ios_jit_tail_reserved == 128 * MB);  /* rs2's */
    else CHECK(off_of(sch.code) == 0x1f0c8000 && ios_jit_tail_reserved == 0x18f38000);
    got = rotate(&l2, 89, 0x17004000);
    if (fix) CHECK(got == 128 * MB && off_of(l2.code) == 0x28000000 && ios_jit_tail_reserved == 256 * MB);
    else CHECK(got == 0x6834000 && off_of(l2.code) == 0x277cc000);   /* "tail REUSE rx=0x16f7cc000 size=0x6834000" */
    got = rotate(&sch, 95, 0x17004000);
    if (fix) CHECK(got == 128 * MB && off_of(sch.code) == 0x1f0c8000 && ios_jit_tail_reserved == 0x18f38000);
    else
    {   /* the log: a 16 MB generation, full at once, then its old 128 MB one again */
        CHECK(got == 16 * MB && c_off(sch.code) == 0x5014000);
        CHECK(rotate(&sch, 95, 0x17004000) == 128 * MB && off_of(sch.code) == 0x1f0c8000);
    }
    start(&gta, 0x106760000, 128, 0x17304000);
    CHECK(c_off(gta.misc) == 0x4010000);
    CHECK(c_off(gta.code) == (fix ? 0x200c000 : 0x5014000));
    got = rotate(&gta, 142, 0x1b240000);
    if (fix) CHECK(off_of(gta.code) == 0x30000000 && scans == 4);
    else CHECK(got == 16 * MB && off_of(gta.code) == 0x2e000000);
    CHECK(ios_jit_tail_reserved == 0x18f38000);
    return got;
}

static void unit(void)
{
    struct ios_tail_carve c = { .off = 0, .size = 16 * MB, .free = 0 };
    size_t bytes = 1;
    void *addr = NULL, *rx;
    size_t size = 0;

    reset();
    CHECK(!ios_tail_carve_ready(&c, 100));
    c.free = 1; c.freed_at = 100;
    CHECK(ios_tail_carve_ready(&c, 100));                         /* FEX's own release: at once, as before */
    c.retired = 1;
    CHECK(!ios_tail_carve_ready(&c, 102) && ios_tail_carve_ready(&c, 103));
    CHECK(!ios_tail_carve_ready(&c, 99));                         /* a clock step back keeps it waiting */

    ios_tail_carves[0] = (struct ios_tail_carve){ .off = 0x1000000, .size = 16 * MB, .peb = (void *)7 };
    ios_tail_carves[1] = (struct ios_tail_carve){ .off = 0x2000000, .size = 32 * MB, .free = 1, .peb = (void *)7 };
    ios_tail_carves[2] = (struct ios_tail_carve){ .off = 0x4000000, .size = 64 * MB, .peb = (void *)8 };
    ios_tail_carves[3] = (struct ios_tail_carve){ .off = 0x8000000, .size = 0x4000 };
    ios_tail_carves[4] = (struct ios_tail_carve){ .off = 0x8004000, .size = 0x4000, .peb = (void *)7 };
    ios_tail_carve_n = 5;
    CHECK(ios_tail_carves_retire_owner(ios_tail_carves, 5, NULL, 50, &bytes) == 0 && !bytes);
    CHECK(ios_tail_carves_retire_owner(ios_tail_carves, 5, (void *)7, 50, &bytes) == 2 && bytes == 16 * MB + 0x4000);
    CHECK(ios_tail_carves[0].free && ios_tail_carves[0].retired && ios_tail_carves[0].freed_at == 50 && !ios_tail_carves[0].peb);
    CHECK(ios_tail_carves[1].free && !ios_tail_carves[1].retired && ios_tail_carves[1].peb == (void *)7);
    CHECK(!ios_tail_carves[2].free && !ios_tail_carves[3].free && ios_tail_carves[4].retired);
    puts("PASS: an exit retires only its own live buffers; a retired one waits out the 3 s grace, FEX's own releases do not");

    CHECK(ios_tail_carve_foreign_release(&ios_tail_carves[2], (void *)7));
    CHECK(!ios_tail_carve_foreign_release(&ios_tail_carves[2], (void *)8));
    CHECK(!ios_tail_carve_foreign_release(&ios_tail_carves[2], NULL));
    CHECK(!ios_tail_carve_foreign_release(&ios_tail_carves[3], (void *)7));
    setenv("MADEIRA_POOL_CODE_EXIT_RECLAIM", "0", 1);
    ios_tail_carves_owner_died((void *)8);
    CHECK(!ios_tail_carves[2].free);
    setenv("MADEIRA_POOL_CODE_EXIT_RECLAIM", "1", 1);
    fake_now = 60;
    ios_tail_carves_owner_died((void *)8);
    CHECK(ios_tail_carves[2].free && ios_tail_carves[2].retired && ios_tail_carves[2].freed_at == 60);
    unsetenv("MADEIRA_POOL_CODE_EXIT_RECLAIM");
    puts("PASS: MADEIRA_POOL_CODE_EXIT_RECLAIM=0 keeps them live; 1 and unset retire them");

    /* A retired 64 MB buffer, a small budget (the tail and head leave 16 MB). */
    reset();
    ios_jit_low_reserved = ios_jit_low_size_global;               /* region C full */
    ios_jit_tail_reserved = 0x18f38000;
    jit_pool_offset = 0x1b240000;
    ios_tail_carves[0] = (struct ios_tail_carve){ .off = 0x8000000, .size = 64 * MB, .free = 1, .retired = 1, .freed_at = 200 };
    ios_tail_carve_n = 1;
    owner = 9;
    fake_now = 202;
    size = 64 * MB;
    CHECK(allocate(&size, &rx) == STATUS_NO_MEMORY && !scans);   /* in its grace: no cap lift, no reuse */
    fake_now = 203;
    scan_busy = 1;
    size = 64 * MB;
    CHECK(allocate(&size, &rx) == STATUS_NO_MEMORY && scans == 1);
    CHECK(ios_tail_carves[0].free && ios_tail_carves[0].retired && ios_tail_carves[0].freed_at == 203);
    size = 16 * MB;
    CHECK(allocate(&size, &rx) == FALLBACK_TAIL && scans == 1);   /* within budget the normal path goes on */
    scan_busy = 0;
    fake_now = 206;
    size = 32 * MB;
    CHECK(allocate(&size, &rx) == STATUS_SUCCESS && scans == 2 && size == 64 * MB && off_of(rx) == 0x8000000);
    CHECK(!ios_tail_carves[0].free && !ios_tail_carves[0].retired && ios_tail_carves[0].peb == (void *)9);
    CHECK(((volatile uint32_t *)rx)[0] == 0xd503201fu && ((volatile uint32_t *)rx)[16 * MB - 1] == 0xd503201fu);
    puts("PASS: a busy dead buffer restarts its grace and the budget applies; a clean one is NOP-filled and handed on");

    /* Its dead owner's late release must not free the new owner's buffer. */
    owner = 8;
    CHECK(release(rx, MEM_RELEASE, &addr, &size) == FALL_THROUGH && !ios_tail_carves[0].free);
    owner = 0;                                                    /* a thread without a TEB: as before */
    occupied = 1;
    CHECK(release(rx, MEM_RELEASE, &addr, &size) == FALL_THROUGH && !ios_tail_carves[0].free);
    occupied = 0;
    owner = 9;
    CHECK(release(rx, MEM_RELEASE, &addr, &size) == STATUS_SUCCESS && addr == rx && size == 64 * MB);
    CHECK(ios_tail_carves[0].free && !ios_tail_carves[0].retired);
    owner = 8;
    CHECK(release(rx, MEM_RELEASE, &addr, &size) == FALL_THROUGH);  /* already free */
    puts("PASS: a release from another process is refused; the owner's (or a TEB-less thread's) works as before");
}

/* pool-fg-keep: Far Cry 3 behind Ubisoft Connect (2026-11-04): the pool's budget cap is 16 MB, the free room 58 MB (the head
 * reserve is 48 MB), the game and a helper each run on a 32 MB buffer. */
static size_t keep(int fg_on)
{
    struct proc game = { .peb = 0x200 }, helper = { .peb = 0x300 };
    void *rx;
    size_t size, got;

    reset();
    ios_pool_head_reserve = 48 * MB;
    ios_jit_low_reserved = ios_jit_low_size_global;                      /* region C full */
    jit_pool_offset = 0x10000000;
    ios_jit_tail_reserved = 0x24600000;                                  /* 58 MB free between head and tail */
    ios_tail_carves[0] = (struct ios_tail_carve){ .off = 0x13a00000, .size = 32 * MB, .peb = (void *)0x200, .fg = fg_on };
    ios_tail_carves[1] = (struct ios_tail_carve){ .off = 0x15a00000, .size = 32 * MB, .peb = (void *)0x300 };
    ios_tail_carve_n = 2;
    game.code = pool + 0x13a00000; game.code_size = 32 * MB;
    helper.code = pool + 0x15a00000; helper.code_size = 32 * MB;
    fake_now = 10;

    owner = 0x300; fixture_fg = 0;
    size = 32 * MB;
    CHECK(allocate(&size, &rx) == STATUS_NO_MEMORY);                     /* a helper in the same state steps down, as before */
    owner = 0x200; fixture_fg = fg_on;
    size = 64 * MB;
    CHECK(allocate(&size, &rx) == STATUS_NO_MEMORY);                     /* more than the game runs on: the budget applies */

    got = rotate(&game, 10, 0x10000000);                                 /* the game's next generation */
    if (!fg_on)
    {
        CHECK(got == 16 * MB);                                           /* the trap: 16 MB, then 32/16 alternating at best */
        return got;
    }
    CHECK(got == 32 * MB && ios_jit_tail_reserved == 0x26600000 && ios_tail_carves[0].free && ios_tail_carves[0].fg);
    puts("PASS: pool-fg-keep: the program being played keeps its 32 MB size from the head reserve; a helper steps down");

    fixture_fg = 0;                                                      /* the helper rotates: the game's freed buffer is held */
    got = rotate(&helper, 12, 0x10000000);
    CHECK(got == 16 * MB && ios_tail_carves[0].free && ios_jit_tail_reserved == 0x27600000);
    CHECK(ios_tail_carves[1].free && !ios_tail_carves[1].fg);              /* the helper's old one: anyone's ... */
    ios_tail_carves[1].free = 0; ios_tail_carves[1].peb = (void *)0x400; /* ... a third program takes it */
    fixture_fg = 1;                                                      /* 10 MB of room left: no new 32 MB, it takes its own back */
    got = rotate(&game, 14, 0x10000000);
    CHECK(got == 32 * MB && off_of(game.code) == 0x13a00000 && ios_jit_tail_reserved == 0x27600000);
    CHECK(!ios_tail_carves[0].free && ios_tail_carves[0].peb == (void *)0x200 && ios_tail_carves[0].fg);
    ios_tail_carves[2].free = 0;                                         /* without its other buffer free: */
    size = 32 * MB;
    CHECK(allocate(&size, &rx) == STATUS_NO_MEMORY);                     /* the floor: 10 MB room would fall below 16 MB */
    ios_tail_carves[2].free = 1;
    CHECK(ios_pool_fg_keep_size(1, 32 * MB, 32 * MB, 48 * MB) && !ios_pool_fg_keep_size(1, 32 * MB, 32 * MB, 48 * MB - 1) &&
          !ios_pool_fg_keep_size(0, 32 * MB, 32 * MB, 64 * MB) && !ios_pool_fg_keep_size(1, 32 * MB, 16 * MB, 64 * MB) &&
          !ios_pool_fg_keep_size(1, 0, 16 * MB, 64 * MB) && ios_pool_free_room(100, 40, 50, 5) == 5 &&
          !ios_pool_free_room(100, 60, 50, 0) && !ios_pool_free_room(100, 40, 50, 11));
    puts("PASS: pool-fg-keep: the game's freed buffer is held from a helper and its next generation takes it back; the 16 MB floor holds");

    fixture_fg = 0; owner = 0x300;                                       /* the game's other buffer, freed at 14: held for 30 s */
    fake_now = 43;
    size = 32 * MB;
    CHECK(allocate(&size, &rx) == STATUS_NO_MEMORY);
    fake_now = 44;
    size = 32 * MB;
    CHECK(allocate(&size, &rx) == STATUS_SUCCESS && size == 32 * MB && off_of(rx) == ios_tail_carves[2].off &&
          ios_tail_carves[2].peb == (void *)0x300 && !ios_tail_carves[2].fg);
    {   /* an exit clears the class with the owner */
        size_t bytes;
        pthread_mutex_lock( &ios_tail_carve_lock );
        CHECK(ios_tail_carves_retire_owner(ios_tail_carves, ios_tail_carve_n, (void *)0x200, 50, &bytes) == 1);
        pthread_mutex_unlock( &ios_tail_carve_lock );
        CHECK(ios_tail_carves[0].retired && ios_tail_carves[0].fg == IOS_POOL_FG_EXITED);
    }
    puts("PASS: pool-fg-keep: after 30 s another program may have it; an exit marks the class exited (pool-fg-relaunch)");
    fixture_fg = 0;
    return 32 * MB;
}

/* pool-merge (default on): the same allocator path with released carves merging and free carves cut to the size asked. The budget
 * cap is 16 MB (keep()'s numbers), region C is full, so every grant above 16 MB must come from the free-list. */
static unsigned find(size_t off)
{
    unsigned i;
    for (i = 0; i < ios_tail_carve_n; i++) if (ios_tail_carves[i].off == off) return i;
    return ~0u;
}
static void tight(void)
{
    reset();
    ios_pool_head_reserve = 48 * MB;
    ios_jit_low_reserved = ios_jit_low_size_global;
    jit_pool_offset = 0x10000000;
    ios_jit_tail_reserved = 0x24600000;
    fixture_fg = 0;
    fake_now = 100;
}
static void merge_tests(void)
{
    void *rx, *addr;
    size_t size;
    unsigned i;

    /* three adjacent buffers of one process, released in any order, become one 64 MB run; a dead process's free buffer beside
     * them stays apart */
    tight();
    ios_tail_carves[0] = (struct ios_tail_carve){ .off = 0x21000000, .size = 32 * MB, .peb = (void *)0x500 };
    ios_tail_carves[1] = (struct ios_tail_carve){ .off = 0x20000000, .size = 16 * MB, .peb = (void *)0x500 };
    ios_tail_carves[2] = (struct ios_tail_carve){ .off = 0x23000000, .size = 16 * MB, .peb = (void *)0x500, .fg = 1 };
    ios_tail_carves[3] = (struct ios_tail_carve){ .off = 0x24000000, .size = 16 * MB, .free = 1, .retired = 1, .freed_at = 50 };
    ios_tail_carve_n = 4;
    owner = 0x500;
    CHECK(release(pool + 0x21000000, MEM_RELEASE, &addr, &size) == STATUS_SUCCESS && size == 32 * MB && ios_tail_carve_n == 4);
    fake_now = 101;
    CHECK(release(pool + 0x20000000, MEM_RELEASE, &addr, &size) == STATUS_SUCCESS && size == 16 * MB && ios_tail_carve_n == 3);
    fake_now = 102;
    CHECK(release(pool + 0x23000000, MEM_RELEASE, &addr, &size) == STATUS_SUCCESS && size == 16 * MB && ios_tail_carve_n == 2);
    i = find(0x20000000);
    CHECK(i != ~0u && ios_tail_carves[i].size == 64 * MB && ios_tail_carves[i].free && !ios_tail_carves[i].retired);
    CHECK(ios_tail_carves[i].freed_at == 102 && ios_tail_carves[i].fg == 1);       /* the latest release; the game's hold */
    i = find(0x24000000);
    CHECK(i != ~0u && ios_tail_carves[i].retired && ios_tail_carves[i].size == 16 * MB);
    puts("PASS: pool-merge: released neighbours form one run (latest release time, the game's hold kept); a dead process's stays apart");

    /* a 128 MB request is served from a 160 MB run although the budget cap is 16 MB; its release merges the run again */
    tight();
    ios_tail_carves[0] = (struct ios_tail_carve){ .off = 0x20000000, .size = 160 * MB, .free = 1, .freed_at = 90 };
    ios_tail_carve_n = 1;
    owner = 0x600;
    size = 128 * MB;
    CHECK(allocate(&size, &rx) == STATUS_SUCCESS && size == 128 * MB && off_of(rx) == 0x22000000);
    CHECK(ios_tail_carve_n == 2 && ios_tail_carves[0].off == 0x20000000 && ios_tail_carves[0].size == 32 * MB && ios_tail_carves[0].free);
    CHECK(!ios_tail_carves[1].free && ios_tail_carves[1].peb == (void *)0x600 && ios_jit_tail_reserved == 0x24600000);
    CHECK(((volatile uint32_t *)rx)[0] == 0xd503201fu && ((volatile uint32_t *)rx)[32 * MB - 1] == 0xd503201fu);
    CHECK(release(rx, MEM_RELEASE, &addr, &size) == STATUS_SUCCESS && size == 128 * MB);
    CHECK(ios_tail_carve_n == 1 && ios_tail_carves[0].off == 0x20000000 && ios_tail_carves[0].size == 160 * MB);
    puts("PASS: pool-merge: a 128 MB buffer is cut from a free 160 MB run (the tail cursor untouched) and merges back when released");

    /* the 2026-11-04 refusal: two adjacent free 16 MB carves of two processes; FEX's ladder (128, 64, 32) now gets 32 MB */
    tight();
    ios_tail_carves[0] = (struct ios_tail_carve){ .off = 0x20000000, .size = 16 * MB, .peb = (void *)0x700 };
    ios_tail_carves[1] = (struct ios_tail_carve){ .off = 0x21000000, .size = 16 * MB, .peb = (void *)0x701 };
    ios_tail_carve_n = 2;
    owner = 0x700;
    CHECK(release(pool + 0x20000000, MEM_RELEASE, &addr, &size) == STATUS_SUCCESS);
    owner = 0x701;
    CHECK(release(pool + 0x21000000, MEM_RELEASE, &addr, &size) == STATUS_SUCCESS && ios_tail_carve_n == 1);
    CHECK(fex_ask(0x702, 128 * MB, &rx) == 32 * MB && off_of(rx) == 0x20000000 && ios_jit_tail_reserved == 0x24600000);
    puts("PASS: pool-merge: the game's refused 32 MB of 2026-11-04 (two adjacent free 16 MB carves) is granted");

    /* a 16 KB dispatcher request takes 16 KB of a free 32 MB carve, not all of it; its release merges back */
    tight();
    ios_tail_carves[0] = (struct ios_tail_carve){ .off = 0x20000000, .size = 32 * MB, .free = 1 };
    ios_tail_carve_n = 1;
    owner = 0x800;
    size = 0x4000;
    CHECK(allocate(&size, &rx) == STATUS_SUCCESS && size == 0x4000 && off_of(rx) == 0x22000000 - 0x4000);
    CHECK(ios_tail_carves[0].size == 32 * MB - 0x4000 && ios_tail_carves[0].free);
    CHECK(release(rx, MEM_RELEASE, &addr, &size) == STATUS_SUCCESS && ios_tail_carve_n == 1 && ios_tail_carves[0].size == 32 * MB);
    /* a carve less than 1 MB larger is handed out whole */
    ios_tail_carves[0].size = 0x4000 + 0xfc000;
    size = 0x4000;
    CHECK(allocate(&size, &rx) == STATUS_SUCCESS && size == 0x100000 && ios_tail_carve_n == 1);
    puts("PASS: pool-merge: a 16 KB request takes 16 KB of a free 32 MB carve and gives it back; under 1 MB extra is handed out whole");

    /* a full table cuts nothing (the whole carve, as before) */
    tight();
    for (i = 0; i < IOS_TAIL_CARVE_MAX - 1; i++)
        ios_tail_carves[i] = (struct ios_tail_carve){ .off = 0x30000000 + i * 0x4000, .size = 0x4000, .peb = (void *)0x900 };
    ios_tail_carves[i] = (struct ios_tail_carve){ .off = 0x20000000, .size = 32 * MB, .free = 1 };
    ios_tail_carve_n = IOS_TAIL_CARVE_MAX;
    owner = 0x901;
    size = 0x4000;
    CHECK(allocate(&size, &rx) == STATUS_SUCCESS && size == 32 * MB && ios_tail_carve_n == IOS_TAIL_CARVE_MAX);
    puts("PASS: pool-merge: with the carve table full the whole carve is handed out");

    /* a dead process's 64 MB buffer, cut for a 32 MB request after its grace and scan: the rest stays retired and does not merge
     * with the piece when the piece is released */
    tight();
    ios_tail_carves[0] = (struct ios_tail_carve){ .off = 0x20000000, .size = 64 * MB, .free = 1, .retired = 1, .freed_at = 90 };
    ios_tail_carve_n = 1;
    owner = 0xa00;
    scans = 0;
    size = 32 * MB;
    CHECK(allocate(&size, &rx) == STATUS_SUCCESS && size == 32 * MB && scans == 1 && off_of(rx) == 0x22000000);
    CHECK(ios_tail_carves[0].retired && ios_tail_carves[0].size == 32 * MB && !ios_tail_carves[1].retired);
    CHECK(release(rx, MEM_RELEASE, &addr, &size) == STATUS_SUCCESS && ios_tail_carve_n == 2);
    owner = 0xa01;                                              /* another process's late release of the piece: refused */
    CHECK(release(rx, MEM_RELEASE, &addr, &size) == FALL_THROUGH);
    puts("PASS: pool-merge: a dead process's buffer is cut only after its grace and scan; its rest stays retired and apart");

    /* the game's hold covers a merged run: another program may not take it for 30 s */
    tight();
    ios_tail_carves[0] = (struct ios_tail_carve){ .off = 0x20000000, .size = 32 * MB, .free = 1, .freed_at = 100, .fg = 1 };
    ios_tail_carves[1] = (struct ios_tail_carve){ .off = 0x22000000, .size = 32 * MB, .peb = (void *)0xb00 };
    ios_tail_carve_n = 2;
    owner = 0xb00;
    CHECK(release(pool + 0x22000000, MEM_RELEASE, &addr, &size) == STATUS_SUCCESS && ios_tail_carve_n == 1 && ios_tail_carves[0].fg);
    owner = 0xb01;
    size = 32 * MB;
    CHECK(allocate(&size, &rx) == STATUS_NO_MEMORY);
    fixture_fg = 1;
    size = 64 * MB;
    CHECK(allocate(&size, &rx) == STATUS_SUCCESS && size == 64 * MB);
    puts("PASS: pool-merge: a run that holds a buffer the game freed stays held for it");

    /* region C begins where this fixture's pool ends: the pool's top carve and C's first one touch but never merge */
    tight();
    ios_tail_carves[0] = (struct ios_tail_carve){ .off = 0x37000000, .size = 16 * MB, .free = 1 };
    ios_tail_carves[1] = (struct ios_tail_carve){ .off = 0x38000000, .size = 16 * MB, .peb = (void *)0xb10 };
    ios_tail_carve_n = 2;
    owner = 0xb10;
    CHECK(ios_tail_carve_in_low(0x38000000) && !ios_tail_carve_in_low(0x37000000));
    CHECK(release(low, MEM_RELEASE, &addr, &size) == STATUS_SUCCESS && ios_tail_carve_n == 2);
    puts("PASS: pool-merge: a carve of region C and one of the pool never merge, even where they touch");
    fixture_fg = 0;
}

/* code-trim: 2026-11-04 in small. The budget cap is 16 MB; Ubisoft Connect's launcher (0xc00) and a renderer (0xc01) hold 64 MB
 * each and made no buffer for 100 s, a utility (0xc02) holds 16 MB, a busy helper (0xc03) made one 5 s ago; the game (0xd00) runs
 * on 16 MB. All took a control block. */
static void trim_tests(void)
{
    struct ios_code_trim *upc, *ren, *small, *busy, *game;
    void *rx, *addr;
    size_t size;
    unsigned i;

    tight();
    memset(ios_code_trims, 0, sizeof(ios_code_trims));
    fake_now = 200;
    ios_tail_carves[0] = (struct ios_tail_carve){ .off = 0x20000000, .size = 32 * MB, .peb = (void *)0xc00, .granted_at = 100 };
    ios_tail_carves[1] = (struct ios_tail_carve){ .off = 0x22000000, .size = 32 * MB, .peb = (void *)0xc00, .granted_at = 90 };
    ios_tail_carves[2] = (struct ios_tail_carve){ .off = 0x24000000, .size = 32 * MB, .peb = (void *)0xc01, .granted_at = 80 };
    ios_tail_carves[3] = (struct ios_tail_carve){ .off = 0x26000000, .size = 32 * MB, .peb = (void *)0xc01, .granted_at = 85 };
    ios_tail_carves[4] = (struct ios_tail_carve){ .off = 0x28000000, .size = 16 * MB, .peb = (void *)0xc02, .granted_at = 50 };
    ios_tail_carves[5] = (struct ios_tail_carve){ .off = 0x29000000, .size = 32 * MB, .peb = (void *)0xc03, .granted_at = 195 };
    ios_tail_carves[6] = (struct ios_tail_carve){ .off = 0x2b000000, .size = 16 * MB, .peb = (void *)0xd00, .granted_at = 190, .fg = 1 };
    ios_tail_carve_n = 7;
    upc = ios_code_trim_control((void *)0xc00); ren = ios_code_trim_control((void *)0xc01);
    small = ios_code_trim_control((void *)0xc02); busy = ios_code_trim_control((void *)0xc03);
    game = ios_code_trim_control((void *)0xd00);
    CHECK(upc && ren && small && busy && game && upc->magic == IOS_CODE_TRIM_MAGIC);

    /* a helper refused asks nobody; the game refused 128 MB asks the two idle 64 MB holders, for 8 MB each */
    owner = 0xc03; fixture_fg = 0;
    size = 128 * MB;
    CHECK(allocate(&size, &rx) == STATUS_NO_MEMORY && !upc->request && !ren->request);
    owner = 0xd00; fixture_fg = 1;
    size = 128 * MB;
    CHECK(allocate(&size, &rx) == STATUS_NO_MEMORY);
    CHECK(upc->request == 1 && ren->request == 1 && upc->size_mb == 8 && ren->size_mb == 8);
    CHECK(!small->request && !busy->request && !game->request);             /* too small; not idle; the game itself */
    fake_now = 201;
    size = 64 * MB;
    CHECK(allocate(&size, &rx) == STATUS_NO_MEMORY && upc->request == 1 && ren->request == 1);   /* not asked again within 60 s */
    puts("PASS: code-trim: the game's refusal asks the idle programs holding 24 MB or more for 8 MB; not the small, the busy, the game; once a minute");

    /* their FEX trims: the buffers they free merge and are held for the game, which then gets 128 MB */
    fake_now = 205;
    owner = 0xc00;
    CHECK(release(pool + 0x20000000, MEM_RELEASE, &addr, &size) == STATUS_SUCCESS);
    CHECK(release(pool + 0x22000000, MEM_RELEASE, &addr, &size) == STATUS_SUCCESS);
    owner = 0xc01;
    CHECK(release(pool + 0x24000000, MEM_RELEASE, &addr, &size) == STATUS_SUCCESS);
    CHECK(release(pool + 0x26000000, MEM_RELEASE, &addr, &size) == STATUS_SUCCESS);
    i = find(0x20000000);
    CHECK(i != ~0u && ios_tail_carves[i].size == 128 * MB && ios_tail_carves[i].free && ios_tail_carves[i].fg);
    owner = 0xc02; fixture_fg = 0;
    size = 32 * MB;
    CHECK(allocate(&size, &rx) == STATUS_NO_MEMORY);                        /* held: not for another program */
    owner = 0xd00; fixture_fg = 1;
    CHECK(fex_ask(0xd00, 128 * MB, &rx) == 128 * MB && off_of(rx) == 0x20000000);
    puts("PASS: code-trim: what the asked programs free merges into a run held for the game; its next buffer is 128 MB");

    /* an asked program stays at 8 MB while the game runs; once the game's buffers are gone, pool-fg's caps apply again */
    owner = 0xc00; fixture_fg = 0;
    CHECK(ios_pool_trim_cap(32 * MB, 0, (void *)0xc00) == 8 * MB && ios_pool_trim_cap(32 * MB, 1, (void *)0xc00) == 32 * MB);
    CHECK(ios_pool_trim_cap(32 * MB, 0, (void *)0xc02) == 32 * MB);        /* never asked */
    size = 16 * MB;
    CHECK(allocate(&size, &rx) == STATUS_NO_MEMORY);
    size = 8 * MB;
    CHECK(allocate(&size, &rx) == FALLBACK_TAIL);
    /* a free 128 MB run nobody holds lifts no cap for it: 128 MB is refused, 8 MB is cut from the run */
    ios_tail_carves[ios_tail_carve_n++] = (struct ios_tail_carve){ .off = 0x30000000, .size = 128 * MB, .free = 1, .freed_at = 150 };
    size = 128 * MB;
    CHECK(allocate(&size, &rx) == STATUS_NO_MEMORY);
    size = 8 * MB;
    CHECK(allocate(&size, &rx) == STATUS_SUCCESS && size == 8 * MB && off_of(rx) == 0x30000000 + 120 * MB);
    /* what it got after the request (its trim's probe, its new generation) is not held when freed */
    CHECK(release(rx, MEM_RELEASE, &addr, &size) == STATUS_SUCCESS && !ios_tail_carves[find(0x30000000)].fg);
    {
        size_t bytes;
        pthread_mutex_lock(&ios_tail_carve_lock);
        ios_tail_carves_retire_owner(ios_tail_carves, ios_tail_carve_n, (void *)0xd00, 300, &bytes);
        pthread_mutex_unlock(&ios_tail_carve_lock);
    }
    CHECK(ios_pool_trim_cap(32 * MB, 0, (void *)0xc00) == 32 * MB);
    puts("PASS: code-trim: an asked program is held to 8 MB while the game runs, and only then");

    /* a program that ends gives its block back; a request older than 30 s no longer holds what is freed */
    ios_code_trim_owner_died((void *)0xc00);
    CHECK(!ios_pool_trim_asked((void *)0xc00) && ios_code_trim_control((void *)0xe00) == upc && !upc->request);
    for (i = 0; i < IOS_CODE_TRIM_MAX && ios_code_trims[i].peb != (void *)0xc03; i++) ;
    CHECK(i < IOS_CODE_TRIM_MAX);
    ios_code_trims[i].asked_at = 360;                                       /* asked at 360, frees at 400 */
    fake_now = 400;
    owner = 0xc03;
    CHECK(release(pool + 0x29000000, MEM_RELEASE, &addr, &size) == STATUS_SUCCESS && !ios_tail_carves[find(0x29000000)].fg);
    puts("PASS: code-trim: an ended program's block is reused fresh; what is freed long after a request is not held");
    fixture_fg = 0;
}

/* pool-fg-relaunch: Far Cry 4 behind Ubisoft Connect (2026-11-04 18:11, run 29). Steam starts FarCry4.exe as the program being played; it
 * runs on 128 MB, hands over to Ubisoft Connect and exits at 24 s; upc.exe starts and asks FEX's 128 MB; 22 s later Ubisoft Connect
 * starts FarCry4.exe again, for real. On the device upc.exe got the dead game's 128 MB through the cap lift and the real game was
 * capped at 16 MB. */
static void relaunch_tests(void)
{
    struct proc stub, upc, game, late;
    size_t got, dead_off, tail_before;
    unsigned i;

    reset();
    ios_jit_low_reserved = ios_jit_low_size_global;     /* no region C carves in the device's logs */
    ios_pool_head_reserve = 48 * MB;
    fixture_policy = 1;
    fixture_fg = 1;
    start(&stub, 0x200, 10, 0x10000000);
    got = rotate(&stub, 14, 0x10000000);
    CHECK(got == 128 * MB);
    dead_off = off_of(stub.code);
    quit(&stub, 24);
    for (i = 0; i < ios_tail_carve_n && ios_tail_carves[i].off != dead_off; i++) ;
    CHECK(i < ios_tail_carve_n && ios_tail_carves[i].retired && ios_tail_carves[i].fg == IOS_POOL_FG_EXITED);

    fixture_fg = 0;                                     /* upc.exe: another program */
    start(&upc, 0x300, 26, 0x12000000);
    tail_before = ios_jit_tail_reserved;
    got = rotate(&upc, 60, 0x12000000);                 /* 36 s after the exit FEX asks 128 MB; the dead game's buffer is ready */
    if (ios_pool_other_max() == 16 * MB)                /* a free 16 MB run (and 16 KB, handed whole) serves it: no new tail */
        CHECK(got >= 16 * MB && got < 17 * MB && off_of(upc.code) != dead_off && ios_jit_tail_reserved == tail_before);
    else
        CHECK(got == 32 * MB && off_of(upc.code) != dead_off && ios_jit_tail_reserved == tail_before + 32 * MB);
    CHECK(ios_tail_carves[i].free && ios_tail_carves[i].size == 128 * MB && ios_tail_carves[i].fg == IOS_POOL_FG_EXITED);
    if (ios_pool_other_max() == 16 * MB)
    {   /* pool-fg-other: env.MADEIRA_POOL_CODE_OTHER_MB=16: the launcher's next generation is 16 MB too, the old one reused */
        size_t before = ios_jit_tail_reserved;
        got = rotate(&upc, 64, 0x12000000);
        CHECK(got >= 16 * MB && got < 17 * MB && ios_jit_tail_reserved <= before + 16 * MB);
        CHECK(ios_tail_carves[i].free && ios_tail_carves[i].size == 128 * MB && ios_tail_carves[i].fg == IOS_POOL_FG_EXITED);
        /* a free 32 MB buffer nobody holds does not lift it past 16 MB either: it gets a 16 MB piece */
        ios_jit_tail_reserved += 32 * MB;
        ios_tail_carves[ios_tail_carve_n++] = (struct ios_tail_carve){ .off = ios_jit_pool_size_global - ios_jit_tail_reserved,
                                                                       .size = 32 * MB, .free = 1, .freed_at = 1 };
        got = rotate(&upc, 70, 0x12000000);
        CHECK(got >= 16 * MB && got < 17 * MB);
        puts("PASS: pool-fg-other: MADEIRA_POOL_CODE_OTHER_MB=16 holds the launcher to 16 MB buffers; its rotations reuse its own");
        return;
    }
    puts("PASS: pool-fg-relaunch: the launcher gets 32 MB and none of the exited game's 128 MB buffer");

    fixture_fg = 1;                                     /* the real FarCry4.exe, 52 s after the first one ended (17:26 session) */
    start(&game, 0x400, 72, 0x13000000);
    got = rotate(&game, 76, 0x13000000);
    CHECK(got == 128 * MB && off_of(game.code) == dead_off && ios_tail_carves[i].peb == (void *)0x400 && ios_tail_carves[i].fg == 1);
    puts("PASS: pool-fg-relaunch: the game's restart takes its 128 MB buffer back");

    /* the hold ends: 120 s after an exit another program may have a piece of it (32 MB, never all of it) */
    quit(&game, 86);
    fixture_fg = 0;
    start(&late, 0x500, 205, 0x13000000);
    CHECK(late.code_size >= 16 * MB && late.code_size < 17 * MB && off_of(late.code) != dead_off);   /* a free run, whole under 1 MB extra */
    got = rotate(&late, 205, 0x13000000);
    CHECK(got == 32 * MB && off_of(late.code) != dead_off + 96 * MB);
    got = rotate(&late, 207, 0x13000000);
    CHECK(got == 32 * MB && off_of(late.code) == dead_off + 96 * MB);   /* cut from the top of the free run */
    puts("PASS: pool-fg-relaunch: after 120 s another program may have a 32 MB piece, cut");

    /* without the classes (no game folder) the cap lift is unchanged: a free 128 MB buffer is served whole */
    reset();
    ios_jit_low_reserved = ios_jit_low_size_global;
    ios_pool_head_reserve = 48 * MB;
    fixture_policy = 0;
    fixture_fg = 0;
    start(&stub, 0x200, 10, 0x10000000);
    CHECK(rotate(&stub, 14, 0x10000000) == 128 * MB);
    dead_off = off_of(stub.code);
    quit(&stub, 24);
    start(&upc, 0x300, 26, 0x12000000);
    CHECK(rotate(&upc, 30, 0x12000000) == 128 * MB && off_of(upc.code) == dead_off);
    CHECK(ios_pool_lift_allowed(0, 0, 128 * MB) && ios_pool_lift_allowed(1, 1, 128 * MB) && ios_pool_lift_allowed(1, 0, 32 * MB) &&
          !ios_pool_lift_allowed(1, 0, 32 * MB + 0x4000));
    puts("PASS: pool-fg-relaunch: without a game folder nothing changes");
}

int main(int argc, char **argv)
{
    void *p = NULL;
    size_t off, on;

    CHECK(!posix_memalign(&p, 0x4000, 0x38000000 + 0x71d0000));
    pool = p;
    low = pool + 0x38000000;
    if (argc > 1 && !strcmp(argv[1], "trim"))
    {
        if (getenv("MADEIRA_POOL_CODE_TRIM"))
        {   /* = 0: no block, so no request */
            CHECK(!ios_code_trim_control((void *)0xc00));
            puts("PASS: code-trim: MADEIRA_POOL_CODE_TRIM=0 offers no control block");
        }
        else
            trim_tests();
        free(p);
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "relaunch"))
    {
        relaunch_tests();
        free(p);
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "merge"))
    {
        merge_tests();
        free(p);
        return 0;
    }
    unit();
    CHECK(keep(0) == 16 * MB && keep(1) == 32 * MB);
    puts("PASS: pool-fg-keep: without the class (MADEIRA_POOL_CODE_FOREGROUND=0) the game gets 16 MB, as on 2026-11-04");
    off = replay(0);
    printf("PASS: MADEIRA_POOL_CODE_EXIT_RECLAIM=0 replays the 13:11 log: tail_resv 0x18f38000, the game's buffer 0x%zx (16 MB)\n", off);
    on = replay(1);
    CHECK(on == 128 * MB);
    printf("PASS: by default the dead helpers' buffers are reused and the game gets 0x%zx (128 MB)\n", on);
    free(p);
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-pool-code-exit-') as directory:
    cfile = Path(directory) / 'pool-code-exit.c'
    binary = Path(directory) / 'pool-code-exit'
    cfile.write_text(fixture)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-D_POSIX_C_SOURCE=200809L',
                    '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', '-fno-sanitize-recover=undefined',
                    '-fno-omit-frame-pointer', '-pthread', str(cfile), '-o', str(binary)], check=True)
    # The allocator's own log lines go to stderr; show them only on failure. The scenarios above were written before pool-merge:
    # they run with it off (its switch restores exactly that behaviour); pool-merge's own scenarios run with the default.
    for args, env in (([], {'MADEIRA_POOL_CARVE_MERGE': '0'}), (['merge'], {}), (['relaunch'], {}),
                      (['relaunch'], {'MADEIRA_POOL_CODE_OTHER_MB': '16'}), (['trim'], {}),
                      (['trim'], {'MADEIRA_POOL_CODE_TRIM': '0'})):
        completed = subprocess.run([str(binary)] + args, capture_output=True, text=True,
                                   env={**{k: v for k, v in os.environ.items()
                                           if k not in ('MADEIRA_POOL_CARVE_MERGE', 'MADEIRA_POOL_CODE_TRIM',
                                                        'MADEIRA_POOL_CODE_OTHER_MB')}, **env})
        print(completed.stdout, end='')
        if completed.returncode:
            print(completed.stderr, end='')
            completed.check_returncode()
