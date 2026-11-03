#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""env.MADEIRA_SELF_WRITE (on unless 0): NtWriteVirtualMemory of a 32-bit program into its own window.

Why: the server writes another process's memory with its task port, which iOS pseudo-processes do not have
(build/wineserver/mach_ios.c get_process_port), so a program's write into itself failed with
STATUS_ACCESS_DENIED. Ubisoft Connect's upc.exe hooks its own ntdll, user32 and kernelbase with
WriteProcessMemory and ends with 0xdeadc0de. build/ntdll-unix/virtual_ios.c now does that write itself
(ios_self_write), page by page, as a guest store would, and stops where Windows would.

What this checks, by cutting the real functions out of virtual_ios.c by signature (ios_self_write,
its switch, its protect record and log line, NtWriteVirtualMemory, and the Wine helpers they call:
get_unix_prot, check_write_access, mprotect_range, update_write_watches, ios_jit_anon_alias_find_cover
and _lookup) and compiling them with -Wall -Wextra -Werror, then under AddressSanitizer and
UndefinedBehaviorSanitizer, over constructed memory with 4 KB pages in 16 KB host pages: mprotect for the
host protection, a memfd mapped twice for a page aliased to the JIT pool (read-only at the guest address,
read/write in the pool), and a pipe standing in for mach_vm_write / mach_vm_read_overwrite (a page that
cannot be written or read is an error code, not a fault):
  - a writable page is written directly; a page Wine records read-only, no-access, guard or uncommitted is
    not, even inside a host page another 4 KB page makes writable; a write-watched page is written and its
    watch is reset; an aliased page is written through its pool view and its guest address is never made
    writable;
  - a page recorded PAGE_EXECUTE_READ (the emulator's re-armed trap) is written only with this thread's
    last writable protect covering it, once: the record is used up by the next write call, is not cleared
    by a PAGE_EXECUTE_READ protect, is replaced by the next writable one, belongs to its thread, and the
    host page goes back to read-only with Wine's recorded protection unchanged;
  - counts: a write that crosses into a page it may not write stops there (exact count,
    STATUS_PARTIAL_COPY, the rest untouched); a write that stops at its first page takes the server
    request unchanged (STATUS_ACCESS_DENIED as before); an unreadable source the same; random spans
    over many pages are split at every 4 KB boundary and land exactly;
  - the source is read with no lock held, every store happens under virtual_mutex, the pool lock only
    inside it, and both are released; the count pointer is stored after that, so one inside the
    destination ends up holding the count;
  - another process's handle, a destination outside the window, or env.MADEIRA_SELF_WRITE = 0 send the
    write to the server exactly as before;
  - the log: one line for each process's first write, at most 16 lines in all for writes that stopped or
    used the protect record;
  - seven deliberate breakages of the cut code still compile and are each caught.
And, by reading the sources: NtProtectVirtualMemory notes a successful change of its own process with the
rounded range; the server's get_process_port and write_process_memory are untouched; CI runs this check;
the catalog documents the switch.

Not shown here, only on an iPhone: that mach_vm_write writes a writable host page and refuses the rest
whole, on the real JIT pool, image and code-signing mappings; that the emulator re-arms between
WriteProcessMemory's protect and its write the way the lab's logs show; that the emulator runs the new
bytes after WriteProcessMemory's flush; that the 16 KB host page made writable for an instant lets no
neighbouring trap be missed; that Ubisoft Connect gets past its hooks.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import sys
import tempfile

R = Path(__file__).resolve().parents[2]
src = (R / "build/ntdll-unix/virtual_ios.c").read_text()
mach = (R / "build/wineserver/mach_ios.c").read_text()
ok = True


def check(what, cond, detail=""):
    global ok
    print(("ok   " if cond else "FAIL ") + what + (("\n     " + str(detail)[-2500:]) if detail and not cond else ""))
    ok = ok and bool(cond)


def function(source, signature):
    start = source.index(signature)
    return source[start:source.index("\n}\n", start) + 3] + "\n"


grant = re.search(r"^static __thread struct \{ ULONG_PTR begin, end; \} ios_self_write_grant;$", src, re.M).group(0)
alias_struct = src[src.index("#define IOS_JIT_MAX_ANON_ALIASES"):src.index("static volatile int ios_jit_anon_alias_count = 0;")]
vprot = "\n".join(re.findall(r"^#define VPROT_(?:READ|WRITE|EXEC|WRITECOPY|GUARD|COMMITTED|WRITEWATCH) +0x[0-9a-fA-F]+", src, re.M))
CUT = "\n".join([
    function(src, "static int get_unix_prot( BYTE vprot )"),
    function(src, "int ios_jit_anon_alias_find_cover(void *user_va, size_t size, void **rw_out, void **rx_out)"),
    function(src, "uintptr_t ios_jit_anon_alias_lookup(uintptr_t fault_addr)"),
    function(src, "static int mprotect_range( void *base, size_t size, BYTE set, BYTE clear )"),
    function(src, "static void update_write_watches( void *base, size_t size, size_t accessed_size )"),
    function(src, "static NTSTATUS check_write_access( void *base, size_t size, BOOL *has_write_watch )"),
    grant,
    function(src, "static int ios_self_write_enabled(void)"),
    function(src, "static void ios_self_write_note_protect( const char *base, SIZE_T size, ULONG prot )"),
    function(src, "static SIZE_T ios_self_write( char *dst, const char *src, SIZE_T size, unsigned *paths )"),
    function(src, "static void ios_self_write_log( const char *dst, SIZE_T size, SIZE_T done, unsigned paths )"),
    function(src, "NTSTATUS WINAPI NtWriteVirtualMemory( HANDLE process, void *addr, const void *buffer,"),
])
check("the functions, the protect record and the seven VPROT bits are found",
      vprot.count("#define") == 7 and "ios_self_write_grant" in grant)

HEAD = r'''
#define _GNU_SOURCE
#define WINE_IOS 1
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
typedef unsigned char BYTE; typedef int BOOL; typedef size_t SIZE_T; typedef uint32_t ULONG; typedef uintptr_t ULONG_PTR;
typedef uintptr_t UINT_PTR; typedef int32_t NTSTATUS; typedef void *HANDLE;
typedef int kern_return_t; typedef unsigned mach_port_t; typedef uint64_t mach_vm_address_t, mach_vm_size_t; typedef uintptr_t vm_offset_t;
#define TRUE 1
#define FALSE 0
#define WINAPI
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_PARTIAL_COPY ((NTSTATUS)0x8000000D)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022)
#define STATUS_INVALID_USER_BUFFER ((NTSTATUS)0xC00000E8)
#define PAGE_NOACCESS 0x01
#define PAGE_READONLY 0x02
#define PAGE_READWRITE 0x04
#define PAGE_WRITECOPY 0x08
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_WRITECOPY 0x80
#define min(a,b) ((a) < (b) ? (a) : (b))
#define ROUND_ADDR(addr,mask) ((void *)((UINT_PTR)(addr) & ~(UINT_PTR)(mask)))
#define ROUND_SIZE(addr,size,mask) (((SIZE_T)(size) + ((UINT_PTR)(addr) & (mask)) + (mask)) & ~(UINT_PTR)(mask))
#define TRACE(...) do { } while (0)
#define HandleToULong(h) ((ULONG)(ULONG_PTR)(h))
#define NtCurrentProcess() ((HANDLE)~(ULONG_PTR)0)
''' + vprot + r'''
#define PG 0x1000u
#define HPG 0x4000u
#define NPAGES 64                                        /* 16 host pages */
static const UINT_PTR page_mask = PG - 1, host_page_size = HPG, host_page_mask = HPG - 1;
static const unsigned page_shift = 12;
static char *G;                                          /* the constructed window */
static BYTE vp[NPAGES];
static pthread_mutex_t virtual_mutex, ios_pool_lock = PTHREAD_MUTEX_INITIALIZER;
static __thread int depth;
static int pool_taken, pool_outside, read_locked, store_unlocked, n_server, n_mprotect, n_mprotect_alias_w;
static struct { struct { HANDLE UniqueProcess; } ClientId; } teb = { { (HANDLE)0x30 } };
#define NtCurrentTeb() (&teb)

static BYTE get_page_vprot( const void *a )
{
    ULONG_PTR o = (ULONG_PTR)a - (ULONG_PTR)G;
    return o < NPAGES * PG ? vp[o >> page_shift] : 0;
}
static BYTE get_host_page_vprot( const void *a )
{
    const char *h = ROUND_ADDR( a, host_page_mask );
    BYTE v = 0; unsigned i;
    for (i = 0; i < HPG / PG; i++) v |= get_page_vprot( h + i * PG );
    return v;
}
static void set_page_vprot_bits( void *base, size_t size, BYTE set, BYTE clear )
{
    ULONG_PTR o = (ULONG_PTR)base - (ULONG_PTR)G, e = o + size;
    for (o &= ~(ULONG_PTR)page_mask; o < e; o += PG) vp[o >> page_shift] = (vp[o >> page_shift] & ~clear) | set;
}
static char *alias_rw;                                    /* the pool's read/write view of the aliased host page */
static int mprotect_exec( void *base, size_t size, int prot )
{
    n_mprotect++;
    if ((prot & PROT_WRITE) && alias_rw && (char *)base <= G + 8 * HPG && (char *)base + size > G + 8 * HPG) n_mprotect_alias_w++;
    return mprotect( base, size, prot );
}
static void server_enter_uninterrupted_section( pthread_mutex_t *m, sigset_t *s ) { (void)s; pthread_mutex_lock( m ); depth++; }
static void server_leave_uninterrupted_section( pthread_mutex_t *m, sigset_t *s ) { (void)s; depth--; pthread_mutex_unlock( m ); }
#define pthread_mutex_lock(m) (((m) == &ios_pool_lock ? (pool_taken++, pool_outside += !depth) : 0), pthread_mutex_lock(m))
static mach_port_t mach_task_self( void ) { return 1; }
/* the kernel does the copy: a page that cannot be read or written is EFAULT, not a signal */
static int kcopy( void *dst, const void *s, size_t len )
{
    int p[2]; ssize_t w, r;
    if (pipe( p )) abort();
    w = write( p[1], s, len );
    r = w == (ssize_t)len ? read( p[0], dst, len ) : -1;
    close( p[0] ); close( p[1] );
    return r == (ssize_t)len ? 0 : 2;
}
static kern_return_t mach_vm_read_overwrite( mach_port_t t, mach_vm_address_t a, mach_vm_size_t n, mach_vm_address_t d, mach_vm_size_t *got )
{
    (void)t; read_locked += depth != 0;
    if (kcopy( (void *)(uintptr_t)d, (void *)(uintptr_t)a, n )) return 1;
    *got = n; return 0;
}
static kern_return_t mach_vm_write( mach_port_t t, mach_vm_address_t a, vm_offset_t s, unsigned n )
{
    (void)t; store_unlocked += !depth;
    return kcopy( (void *)(uintptr_t)a, (void *)s, n );
}
static int virtual_check_buffer_for_read( const void *p, SIZE_T n ) { (void)p; (void)n; return 1; }
static int ios_wow_in_window( const void *a ) { return (const char *)a >= G && (const char *)a < G + NPAGES * PG; }
#define wine_server_obj_handle(h) ((unsigned)(ULONG_PTR)(h))
#define wine_server_client_ptr(p) ((uint64_t)(ULONG_PTR)(p))
#define wine_server_add_data(r,b,n) ((void)(b), (void)(n))
#define wine_server_call(r) (n_server++, STATUS_ACCESS_DENIED)
#define SERVER_START_REQ(type) do { struct { unsigned handle; uint64_t addr; } req_s, *req = &req_s; struct { SIZE_T written; } reply_s = { 0 }, *reply = &reply_s;
#define SERVER_END_REQ (void)req; } while (0)
''' + alias_struct + r'''
static volatile int ios_jit_anon_alias_count = 0;
'''

TESTS = r'''
static int fails;
#define T(c) do { if (!(c)) { printf( "FAIL line %d: %s\n", __LINE__, #c ); fails++; } } while (0)
#define P(i) (G + (i) * PG)
enum { RW = VPROT_COMMITTED | VPROT_READ | VPROT_WRITE, RO = VPROT_COMMITTED | VPROT_READ,
       RX = VPROT_COMMITTED | VPROT_READ | VPROT_EXEC, RWX = VPROT_COMMITTED | VPROT_READ | VPROT_WRITE | VPROT_EXEC,
       WC = VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY | VPROT_EXEC };

static void host( int hp ) { mprotect_range( G + hp * HPG, HPG, 0, 0 ); }   /* host protection from the table */
static void layout( int first, int n, BYTE v ) { int i; for (i = 0; i < n; i++) vp[first + i] = v; for (i = first / 4; i <= (first + n - 1) / 4; i++) host( i ); }
static int writable( const void *a ) { unsigned char b = *(volatile const unsigned char *)a; return !kcopy( (void *)a, &b, 1 ); }
static SIZE_T sw( void *dst, const void *s, SIZE_T n, unsigned *paths ) { unsigned p; if (!paths) paths = &p; return ios_self_write( dst, s, n, paths ); }
static void protect( const void *base, SIZE_T size, ULONG prot ) { ios_self_write_note_protect( base, size, prot ); }

static void reset( void )
{
    memset( vp, 0, sizeof(vp) );
    mprotect( G, NPAGES * PG, PROT_READ | PROT_WRITE );
    memset( G, 0x11, NPAGES * PG );
    if (alias_rw) memset( alias_rw, 0x11, HPG );
    mprotect( G, NPAGES * PG, PROT_NONE );
    pool_taken = pool_outside = read_locked = store_unlocked = n_server = n_mprotect = n_mprotect_alias_w = 0;
    ios_self_write_grant.begin = ios_self_write_grant.end = 0;
}

static unsigned char data[5 * PG] __attribute__((aligned(4096)));

static void test_pages( void )
{
    unsigned paths;
    int i;

    for (i = 0; i < (int)sizeof(data); i++) data[i] = (unsigned char)(i * 7 + 3);
    reset(); layout( 0, 4, RW );
    T( sw( P(0) + 0xff0, data, 0x20, &paths ) == 0x20 && paths == 1 && !memcmp( P(0) + 0xff0, data, 0x20 ) );
    T( !read_locked && !store_unlocked && !pool_taken && !depth );

    /* WRITECOPY (an image's own pages, writable from the start) and RWX not aliased: direct */
    reset(); layout( 4, 4, WC ); T( sw( P(4) + 3, data, 5, &paths ) == 5 && paths == 1 && !memcmp( P(4) + 3, data, 5 ) );
    reset(); layout( 4, 4, RWX ); T( sw( P(5), data, 6, &paths ) == 6 && paths == 1 );

    /* not writable on Windows: read-only, PAGE_EXECUTE_READ, no access, guard, uncommitted, free */
    {
        static const BYTE no[] = { RO, RX, VPROT_COMMITTED, RW | VPROT_GUARD, VPROT_READ | VPROT_WRITE, 0 };
        for (i = 0; i < (int)sizeof(no); i++)
        {
            reset(); layout( 0, 4, no[i] );
            T( sw( P(1), data, 4, NULL ) == 0 );
        }
    }
    /* Windows' 4 KB rule: a read-only page in a host page another page makes writable is refused */
    reset(); vp[0] = RW; vp[1] = RO; vp[2] = RW; vp[3] = RW; host( 0 );
    T( writable( P(1) ) && sw( P(1), data, 4, NULL ) == 0 && P(1)[0] == 0x11 );
    T( sw( P(0) + 0xffe, data, 4, NULL ) == 2 && P(1)[0] == 0x11 );   /* crossing into it: stops there */

    /* crossing into a host page that is read-only: exact count, the rest untouched */
    reset(); layout( 0, 4, RW ); layout( 4, 4, RO );
    T( sw( P(3) + 0xffd, data, 8, NULL ) == 3 && !memcmp( P(3) + 0xffd, data, 3 ) && P(4)[0] == 0x11 );

    /* write watch: written, the watch of the written page reset, the other one kept, protection restored */
    reset(); vp[0] = vp[1] = RW | VPROT_WRITEWATCH; vp[2] = vp[3] = RW; host( 0 );
    T( !writable( P(1) ) );
    T( sw( P(1) + 8, data, 8, &paths ) == 8 && paths == 1 && !memcmp( P(1) + 8, data, 8 ) );
    T( vp[1] == RW && vp[0] == (RW | VPROT_WRITEWATCH) && !writable( P(0) ) );

    /* aliased to the pool: through the RW view; the guest address is never made writable */
    reset(); layout( 32, 4, RWX );
    T( !writable( P(33) ) );
    T( sw( P(33) + 0x10, data, 0x30, &paths ) == 0x30 && paths == 2 && !memcmp( P(33) + 0x10, data, 0x30 ) );
    T( !memcmp( alias_rw + PG + 0x10, data, 0x30 ) && pool_taken && !pool_outside && !writable( P(33) ) && !n_mprotect_alias_w );
    T( !pthread_mutex_trylock( &ios_pool_lock ) ); pthread_mutex_unlock( &ios_pool_lock );

    /* source: unreadable is the server's case, partly unreadable a partial copy */
    reset(); layout( 0, 8, RW );
    mprotect( data + 2 * PG, PG, PROT_NONE );
    T( sw( P(0), data + 2 * PG, 8, NULL ) == 0 );
    T( sw( P(0) + 0x800, data + PG + 0x800, 0x1000, NULL ) == 0x800 && !memcmp( P(0) + 0x800, data + PG + 0x800, 0x800 ) );
    mprotect( data + 2 * PG, PG, PROT_READ | PROT_WRITE );

    /* overlap inside one page: the staged source gives memmove's result */
    reset(); layout( 0, 4, RW );
    for (i = 0; i < 64; i++) P(0)[i] = (char)i;
    T( sw( P(0) + 8, P(0), 32, NULL ) == 32 );
    for (i = 0; i < 32; i++) T( P(0)[8 + i] == (char)i );
}

static void test_record( void )
{
    unsigned paths;

    /* the emulator's re-armed trap: PAGE_EXECUTE_READ, host page read-only */
    reset(); layout( 8, 4, RX );
    T( !writable( P(9) ) && sw( P(9) + 0xff0, data, 5, NULL ) == 0 );                       /* no record */
    protect( P(9), PG, 0x60000000 | PAGE_EXECUTE_WRITECOPY );                                /* WriteProcessMemory's */
    protect( P(9), PG, PAGE_EXECUTE_READ );                                                  /* the emulator's re-arm */
    T( sw( P(9) + 0xff0, data, 5, &paths ) == 5 && paths == 4 && !memcmp( P(9) + 0xff0, data, 5 ) );
    T( vp[9] == RX && !writable( P(9) ) && !writable( P(8) ) && !depth );                 /* recorded and host protection back */
    T( sw( P(9) + 0xff0, data, 5, NULL ) == 0 );                                             /* used up */

    protect( P(9), PG, PAGE_EXECUTE_READWRITE );
    T( sw( P(10), data, 5, NULL ) == 0 && sw( P(9), data, 5, NULL ) == 0 );                /* another page; and used up by the call */
    protect( P(8), 2 * PG, PAGE_READWRITE ); protect( P(9), PG, PAGE_EXECUTE_WRITECOPY );
    T( sw( P(8), data, 5, NULL ) == 0 );                                                     /* replaced by the later writable one */
    protect( P(9), PG, PAGE_EXECUTE_READWRITE ); protect( P(10), PG, PAGE_READONLY );
    T( sw( P(9), data, 5, NULL ) == 5 );                                                     /* a read-only protect does not replace it */
    protect( P(9), PG, PAGE_EXECUTE_READWRITE );
    T( sw( P(9) + 0xffe, data, 4, NULL ) == 2 && P(10)[0] == 0x11 );                       /* it opens its own pages only */
    protect( P(9), PG, PAGE_READONLY ); T( sw( P(9), data, 5, NULL ) == 0 );               /* a non-writable protect records nothing */

    /* only for PAGE_EXECUTE_READ: a record never opens read-only, no-access or guard pages */
    reset(); layout( 8, 4, RO ); protect( P(9), PG, PAGE_EXECUTE_READWRITE ); T( sw( P(9), data, 5, NULL ) == 0 );
    reset(); layout( 8, 4, RX | VPROT_GUARD ); protect( P(9), PG, PAGE_EXECUTE_READWRITE ); T( sw( P(9), data, 5, NULL ) == 0 );

    /* a re-armed aliased page: through the RW view, no protection change */
    reset(); layout( 32, 4, RX ); protect( P(34), PG, PAGE_EXECUTE_READWRITE );
    T( sw( P(34), data, 7, &paths ) == 7 && paths == 2 && !memcmp( alias_rw + 2 * PG, data, 7 ) && !n_mprotect_alias_w );
}

static void *other_thread( void *arg ) { (void)arg; return (void *)(ULONG_PTR)sw( P(9), data, 5, NULL ); }

static void test_thread( void )
{
    pthread_t t;
    void *r;

    reset(); layout( 8, 4, RX ); protect( P(9), PG, PAGE_EXECUTE_READWRITE );
    pthread_create( &t, NULL, other_thread, NULL ); pthread_join( t, &r );
    T( r == NULL );                                                                         /* another thread's record */
    T( sw( P(9), data, 5, NULL ) == 5 );                                                     /* ours is still there */
}

static void test_split( void )
{
    unsigned k;
    static char want[NPAGES * PG];

    reset(); layout( 0, 32, RW ); layout( 32, 4, RWX ); layout( 36, 28, RW );
    memcpy( want, G, sizeof(want) ); memcpy( want + 32 * PG, alias_rw, HPG );
    srand( 7 );
    for (k = 0; k < 4000; k++)
    {
        SIZE_T off = (SIZE_T)rand() % (NPAGES * PG), n = 1 + (SIZE_T)rand() % (3 * PG);
        if (off + n > NPAGES * PG) n = NPAGES * PG - off;
        if (n > sizeof(data)) n = sizeof(data);
        T( sw( G + off, data, n, NULL ) == n );
        memcpy( want + off, data, n );
    }
    T( !memcmp( G, want, 32 * PG ) && !memcmp( alias_rw, want + 32 * PG, HPG ) && !memcmp( G + 36 * PG, want + 36 * PG, 28 * PG ) );
    T( !read_locked && !store_unlocked && !pool_outside && !depth );
}

static void test_nt( void )
{
    SIZE_T n = 99;

    reset(); layout( 0, 8, RW ); layout( 8, 4, RO );
    T( NtWriteVirtualMemory( NtCurrentProcess(), P(1), data, 16, &n ) == STATUS_SUCCESS && n == 16 && !n_server );
    T( NtWriteVirtualMemory( NtCurrentProcess(), P(7) + 0xffc, data, 16, &n ) == STATUS_PARTIAL_COPY && n == 4 && !n_server );
    T( NtWriteVirtualMemory( NtCurrentProcess(), P(9), data, 16, &n ) == STATUS_ACCESS_DENIED && n == 0 && n_server == 1 );
    T( NtWriteVirtualMemory( (HANDLE)0x44, P(1), data, 16, &n ) == STATUS_ACCESS_DENIED && n == 0 && n_server == 2 );
    T( NtWriteVirtualMemory( NtCurrentProcess(), data, P(1), 16, &n ) == STATUS_ACCESS_DENIED && n_server == 3 );   /* outside the window */
    T( NtWriteVirtualMemory( NtCurrentProcess(), P(1), data, 0, &n ) == STATUS_ACCESS_DENIED && n_server == 4 );
    T( NtWriteVirtualMemory( NtCurrentProcess(), P(7) + 0xff8, data, ~(SIZE_T)0, &n ) == STATUS_ACCESS_DENIED && n_server == 5 );
    T( NtWriteVirtualMemory( NtCurrentProcess(), P(1), data, 16, NULL ) == STATUS_SUCCESS );
    /* the count pointer inside the destination: stored last, so it holds the count */
    T( NtWriteVirtualMemory( NtCurrentProcess(), P(2), data, 32, (SIZE_T *)(P(2) + 8) ) == STATUS_SUCCESS &&
       *(SIZE_T *)(P(2) + 8) == 32 && !memcmp( P(2), data, 8 ) );
}

static void test_log( void )   /* a fresh process: the log's counters start at 0 */
{
    int i;

    reset(); layout( 0, 8, RW ); layout( 8, 4, RO );
    for (i = 0; i < 3; i++) ios_self_write_log( P(0), 4, 4, 1 );
    teb.ClientId.UniqueProcess = (HANDLE)0x31;
    ios_self_write_log( P(0), 4, 4, 2 );
    ios_self_write_log( P(0), 4, 4, 1 );
    for (i = 0; i < 20; i++) ios_self_write_log( P(9), 4, 0, 0 );
}

static void test_off( void )   /* env.MADEIRA_SELF_WRITE = 0 */
{
    SIZE_T n = 99;

    reset(); layout( 0, 8, RW ); layout( 8, 4, RX );
    T( NtWriteVirtualMemory( NtCurrentProcess(), P(1), data, 16, &n ) == STATUS_ACCESS_DENIED && n == 0 && n_server == 1 && P(1)[0] == 0x11 );
    protect( P(9), PG, PAGE_EXECUTE_READWRITE );
    T( !ios_self_write_grant.end );
}

int main( int argc, char **argv )
{
    pthread_mutexattr_t attr;
    int fd = memfd_create( "pool", 0 );

    if (argc > 1 && !strcmp( argv[1], "switch" ))   /* read in a fresh process */
    {
        printf( "%d\n", ios_self_write_enabled() );
        return 0;
    }
    pthread_mutexattr_init( &attr );
    pthread_mutexattr_settype( &attr, PTHREAD_MUTEX_ERRORCHECK );   /* a lock left held is an error, not a hang */
    pthread_mutex_init( &virtual_mutex, &attr );
    G = mmap( NULL, NPAGES * PG + HPG, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
    G = (char *)(((ULONG_PTR)G + HPG - 1) & ~(ULONG_PTR)(HPG - 1));
    if (fd < 0 || ftruncate( fd, HPG ) ||
        mmap( G + 8 * HPG, HPG, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0 ) == MAP_FAILED ||
        (alias_rw = mmap( NULL, HPG, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 )) == MAP_FAILED) abort();
    ios_jit_anon_aliases[0].user_va_end = (ULONG_PTR)G + 9 * HPG;
    ios_jit_anon_aliases[0].jit_rw_alias = (ULONG_PTR)alias_rw;
    ios_jit_anon_aliases[0].jit_rx_alias = (ULONG_PTR)alias_rw;   /* registered; this harness never runs it */
    ios_jit_anon_aliases[0].user_va = (ULONG_PTR)G + 8 * HPG;
    ios_jit_anon_alias_count = 1;
    if (argc > 1 && !strcmp( argv[1], "log" )) test_log();
    else if (argc > 1 && !strcmp( argv[1], "off" )) test_off();
    else { test_pages(); test_record(); test_thread(); test_split(); test_nt(); }
    printf( "%s\n", fails ? "HARNESS FAILED" : "harness ok" );
    return fails != 0;
}
'''

# A deliberate breakage of the cut code must make the harness fail.
BREAKS = [
    ("the record is not used up", [("ios_self_write_grant.begin = ios_self_write_grant.end = 0;   /* one write call per protect */", "")]),
    ("a PAGE_EXECUTE_READ page without a record", [("(ULONG_PTR)at >= grant_begin && (ULONG_PTR)at + len <= grant_end",
                                                    "((ULONG_PTR)at >= grant_begin || 1) && ((ULONG_PTR)at + len <= grant_end || 1)")]),
    ("every protect replaces the record", [("    switch (prot & 0xff)\n    {\n", "    switch (prot & 0xff)\n    {\n    default:\n")]),
    ("the count taken before the store", [("        if (!ok) break;\n        done += len;", "        done += len;\n        if (!ok) break;")]),
    ("the host page's protection instead of the page's", [("        vprot = get_page_vprot( at );", "        vprot = get_host_page_vprot( at );")]),
    ("the host page not put back", [("                mprotect_range( at, len, 0, 0 );\n", "")]),
    ("the source read under the lock", [
        ("got != len) break;\n        server_enter_uninterrupted_section( &virtual_mutex, &sigset );", "got != len) break;"),
        ("        if (mach_vm_read_overwrite(", "        server_enter_uninterrupted_section( &virtual_mutex, &sigset );\n        if (mach_vm_read_overwrite(")]),
]

cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
if not cc:
    print("SKIP host compile: no C compiler")
else:
    with tempfile.TemporaryDirectory() as tmp:
        def build(cut, name, sanitize):
            c = os.path.join(tmp, name + ".c")
            exe = os.path.join(tmp, name)
            Path(c).write_text(HEAD + cut + TESTS)
            flags = [cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function"]
            if sanitize:
                flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=undefined"]
            return subprocess.run(flags + [c, "-o", exe, "-lpthread"], capture_output=True, text=True), exe

        b, exe = build(CUT, "strict", False)
        check("the cut functions compile with -Wall -Wextra -Werror", b.returncode == 0, b.stderr)
        b, exe = build(CUT, "san", True)
        check("and under AddressSanitizer + UndefinedBehaviorSanitizer", b.returncode == 0, b.stderr)
        env = {k: v for k, v in os.environ.items() if k != "MADEIRA_SELF_WRITE"}

        def run(exe, *args, **extra):
            try:
                return subprocess.run([exe, *args], capture_output=True, text=True, env=dict(env, **extra), timeout=120)
            except subprocess.TimeoutExpired as e:
                return subprocess.CompletedProcess(e.cmd, 1, "timeout", "")

        if b.returncode == 0:
            r = run(exe)
            check("pages, write watch, the pool view, the protect record, threads, 4000 random spans, "
                  "NtWriteVirtualMemory", r.returncode == 0 and r.stdout.strip().endswith("harness ok"), r.stdout + r.stderr)
            r = run(exe, "log")
            log = [l for l in r.stderr.splitlines() if l.startswith("[self-write]")]
            check("the log: one line for each process's first write, then at most 16 for writes that stopped",
                  r.returncode == 0 and len(log) == 18 and log[0].startswith("[self-write] pid 0030: ") and "( direct )" in log[0] and
                  log[1].startswith("[self-write] pid 0031: ") and "( rw-view )" in log[1] and
                  all(", 0 written ( ), stopped at " in l and "(page vprot 0x21): server request, as before" in l for l in log[2:]),
                  "\n".join(log))
            seen = {v: run(exe, "switch", **({} if v is None else {"MADEIRA_SELF_WRITE": v})).stdout.strip()
                    for v in (None, "", "1", "yes", "0")}
            check("the switch: unset, '', '1' and 'yes' are on; '0' is off",
                  seen == {None: "1", "": "1", "1": "1", "yes": "1", "0": "0"}, seen)
            r = run(exe, "off", MADEIRA_SELF_WRITE="0")
            check("MADEIRA_SELF_WRITE=0: NtWriteVirtualMemory sends the write to the server and no protect is recorded",
                  r.returncode == 0, r.stdout)
        for what, edits in BREAKS:
            cut = CUT
            hit = all(cut.count(old) == 1 for old, _ in edits)
            for old, new in edits:
                cut = cut.replace(old, new)
            bb, bexe = build(cut, "broken", False) if hit else (None, None)
            check("breakage caught: " + what, hit and bb.returncode == 0 and run(bexe).returncode != 0)

nwvm = function(src, "NTSTATUS WINAPI NtWriteVirtualMemory( HANDLE process, void *addr, const void *buffer,")
check("NtWriteVirtualMemory: the branch is before the server request, which is unchanged",
      nwvm.index("ios_self_write( addr, buffer, size, &paths )") < nwvm.index("SERVER_START_REQ( write_process_memory )") and
      "            req->handle     = wine_server_obj_handle( process );\n"
      "            req->addr       = wine_server_client_ptr( addr );\n"
      "            wine_server_add_data( req, buffer, size );\n"
      "            status = wine_server_call( req );\n"
      "            size = reply->written;\n" in nwvm)
nvp = function(src, "NTSTATUS WINAPI NtProtectVirtualMemory( HANDLE process, PVOID *addr_ptr, SIZE_T *size_ptr,")
note = "        ios_self_write_note_protect( base, size, new_prot );"
check("NtProtectVirtualMemory notes a successful change of its own process, with the rounded range",
      nvp.count(note) == 1 and nvp.index("if (process != NtCurrentProcess())") < nvp.index("base = ROUND_ADDR( addr, page_mask );")
      < nvp.index("status = set_protection( view, base, size, new_prot );") < nvp.index(note) and
      "    if (!status)\n    {\n        __sync_fetch_and_add( &ios_vprotect_seq, 1 );" in nvp[:nvp.index(note)])
check("the switch is read in one place, and the record only by these functions",
      src.count('getenv( "MADEIRA_SELF_WRITE" )') == 1 and src.count("ios_self_write_grant") == 8 and
      src.count("ios_self_write(") == 2 and src.count("ios_self_write_note_protect(") == 2)
check("the server's port and write path are untouched (writes into another process still refused)",
      "    return process->trace_data;\n}" in function(mach, "static mach_port_t get_process_port( struct process *process )") and
      "    mach_port_t process_port = get_process_port( process );\n    mach_vm_offset_t data;\n\n    if (written) *written = 0;\n\n"
      "    if (!process_port)\n    {\n        set_error( STATUS_ACCESS_DENIED );" in mach)
wf = (R / ".github/workflows/build-ipa.yml").read_text()
check("CI runs this check", "run: python3 tests/host/check-self-write.py" in wf)
cat = (R / "app/Madeira/ConfigCatalog.generated.swift").read_text()
gen = (R / "build/tools/gen-config-catalog.py").read_text()
check("the catalog documents env.MADEIRA_SELF_WRITE (on by default) in the generator's overlay and its output",
      '"env.MADEIRA_SELF_WRITE": {"category": "Memory & JIT pool"' in gen and
      'ConfigOption(key: "env.MADEIRA_SELF_WRITE", title: "A 32-bit program writes its own memory", kind: .bool, defaultValue: "1", '
      'category: "Memory & JIT pool"' in cat)

print("PASS: self-write" if ok else "FAILED: self-write")
sys.exit(0 if ok else 1)
