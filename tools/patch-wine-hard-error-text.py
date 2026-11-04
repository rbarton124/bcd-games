#!/usr/bin/env python3
"""madeira-bcd hard-error-text: a 64-bit program's hard error is logged with its message text (log only).

NtRaiseHardError (wine/dlls/ntdll/unix/system.c) is a stub that logs its arguments as numbers and returns
STATUS_NOT_IMPLEMENTED. A program that gives up with a message box it cannot show (STATUS_SERVICE_NOTIFICATION,
0x50000018: parameters 0 and 1 are the text and caption, which params_mask marks as strings) leaves only
"fixme:ntdll:NtRaiseHardError 0x50000018 4 0x3 <pointer> ..." in the log: Far Cry 4's FC64.dll did this before
ending with 0xdeadc0de, and the reason ("Error at hooking", found by other means) was not in the log.

The 32-bit side already has this: dlls/wow64's wow64_NtRaiseHardError logs [ubi-harderror-v1] lines with the text
of a 32-bit program's service notification. With this patch the unix NtRaiseHardError, which only 64-bit callers
reach, logs every parameter params_mask marks as a UNICODE_STRING:

    [harderror] pid=00a8 status=50000018 string 0 (41 chars): L"..."

Every pointer is checked with virtual_check_buffer_for_read before it is read, each descriptor is read once, a
string is shown up to debugstr_wn's limit (about 280 characters, "..." when cut), and at most 8 calls per session
are logged. The return value and *response are unchanged. No switch: it adds log lines only on a call that already
logs a FIXME.

Usage: patch-wine-hard-error-text.py wine/dlls/ntdll/unix/system.c   (idempotent)
"""
from pathlib import Path
import sys

MARKER = "madeira-bcd hard-error-text"

HEAD = """/******************************************************************************
 *              NtRaiseHardError  (NTDLL.@)
 */
NTSTATUS WINAPI NtRaiseHardError( NTSTATUS status, ULONG count,
                                  ULONG params_mask, void **params,
                                  HARDERROR_RESPONSE_OPTION option, HARDERROR_RESPONSE *response )
{
    FIXME( "%#08x %u %#x %p %u %p: stub\\n", status, count, params_mask, params, option, response );
    return STATUS_NOT_IMPLEMENTED;
}
"""

HELPER = """/* madeira-bcd hard-error-text (tools/patch-wine-hard-error-text.py): the strings of a 64-bit program's hard error
 * (the parameters params_mask marks are UNICODE_STRING pointers; a STATUS_SERVICE_NOTIFICATION's are a message box's
 * text and caption), so the log says why the program gave up. The 32-bit counterpart is dlls/wow64's
 * [ubi-harderror-v1] trace; 32-bit callers do not reach this function. Every pointer is checked before it is read,
 * each descriptor is read once, at most 8 calls per session. Log only. */
static void madeira_hard_error_text( NTSTATUS status, ULONG count, ULONG params_mask, void **params )
{
    static LONG calls;
    ULONG i;

    if (!params || !count || !params_mask || InterlockedIncrement( &calls ) > 8) return;
    if (count > 32) count = 32;   /* params_mask has 32 bits */
    if (!virtual_check_buffer_for_read( params, count * sizeof(*params) ))
    {
        ERR( "[harderror] pid=%04x status=%08x parameters unreadable at %p\\n",
             (unsigned)HandleToULong( NtCurrentTeb()->ClientId.UniqueProcess ), (unsigned)status, params );
        return;
    }
    for (i = 0; i < count; i++)
    {
        const UNICODE_STRING *str = params[i];
        UNICODE_STRING copy;

        if (!(params_mask & (1u << i))) continue;
        if (!str || !virtual_check_buffer_for_read( str, sizeof(*str) ) || ((copy = *str).Length &&
            (!copy.Buffer || !virtual_check_buffer_for_read( copy.Buffer, copy.Length ))))
        {
            ERR( "[harderror] pid=%04x status=%08x string %u unreadable at %p\\n",
                 (unsigned)HandleToULong( NtCurrentTeb()->ClientId.UniqueProcess ), (unsigned)status, (unsigned)i, str );
            continue;
        }
        ERR( "[harderror] pid=%04x status=%08x string %u (%u chars): %s\\n",
             (unsigned)HandleToULong( NtCurrentTeb()->ClientId.UniqueProcess ), (unsigned)status, (unsigned)i,
             (unsigned)(copy.Length / sizeof(WCHAR)), debugstr_wn( copy.Buffer, copy.Length / sizeof(WCHAR) ) );
    }
}

"""

CALL_OLD = """    FIXME( "%#08x %u %#x %p %u %p: stub\\n", status, count, params_mask, params, option, response );
    return STATUS_NOT_IMPLEMENTED;
"""
CALL_NEW = """    FIXME( "%#08x %u %#x %p %u %p: stub\\n", status, count, params_mask, params, option, response );
    madeira_hard_error_text( status, count, params_mask, params );   /* madeira-bcd hard-error-text */
    return STATUS_NOT_IMPLEMENTED;
"""


def patch(text):
    if MARKER in text:
        return text
    if text.count(HEAD) != 1 or text.count(CALL_OLD) != 1:
        raise SystemExit("patch-wine-hard-error-text: NtRaiseHardError is not the stub this patch expects "
                         "(found %d times); system.c changed upstream, update the patch" % text.count(HEAD))
    at = text.index(HEAD)
    text = text[:at] + HELPER + text[at:]
    return text.replace(CALL_OLD, CALL_NEW)


def unpatch(text):
    return text.replace(HELPER, "").replace(CALL_NEW, CALL_OLD)


def main(argv):
    if len(argv) != 2:
        raise SystemExit(__doc__.strip().splitlines()[-1])
    path = Path(argv[1])
    old = path.read_text()
    new = patch(old)
    if new != old:
        path.write_text(new)
        print("patch-wine-hard-error-text: patched", path)
    else:
        print("patch-wine-hard-error-text: already patched", path)


if __name__ == "__main__":
    main(sys.argv)
