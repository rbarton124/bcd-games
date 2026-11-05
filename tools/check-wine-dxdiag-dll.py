#!/usr/bin/env python3
"""Require Wine's DxDiag provider and the DirectDraw it imports as opt-in DLLs in the 64-bit farm.

The prefix registers CLSID_DxDiagProvider at system32\\dxdiagn.dll. Without the DLL CoCreateInstance fails, and Far Cry 4's
systemdetection64.dll ("Can't get the IDxDiagProvider") hands the game a null result it reads 33 s into its start
(2026-11-04). tools/build-wine-extra-dlls.sh builds both in OPTIN_WANT (dxdiagn-optin.dll, ddraw-optin.dll; a game lists
"dxdiagn,ddraw" in env.MADEIRA_OPTIN_DLLS and app/Madeira/WineProcessBridge.m links them as <name>.dll) in a step that may
fail without failing the build; this check runs after it, as tools/check-wine-media-dlls.py does for the media reader, and
reuses that script's PE reader. Checks the COM / DirectDraw exports, regular imports only (see UNDELAY in
build/wine-pe/build-modules.sh), that every import is packaged (an opt-in DLL counts for the other's import, as a game lists
both), that neither ships under its own name, and that dxdiagn carries tools/patch-wine-dxdiagn-directshow.py's marker.
"""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

_spec = spec_from_file_location('check_wine_media_dlls', Path(__file__).with_name('check-wine-media-dlls.py'))
_media = module_from_spec(_spec)
_spec.loader.exec_module(_media)
PE = _media.PE
MARKER = 'dxdiagn-directshow-v1 madeira-bcd'   # tools/patch-wine-dxdiagn-directshow.py: Initialize survives a missing devenum.dll

REQUIRED = {
    'dxdiagn-optin.dll': ('DllGetClassObject', 'DllCanUnloadNow'),
    'ddraw-optin.dll': ('DirectDrawCreate', 'DirectDrawCreateEx'),
}


def check(bundle):
    bundle = Path(bundle)
    shipped = {p.name.lower(): p for p in bundle.iterdir() if p.is_file()}
    for plain in ('dxdiagn.dll', 'ddraw.dll'):
        if plain in shipped:
            raise ValueError(plain + ' ships for every game; it is an opt-in DLL (env.MADEIRA_OPTIN_DLLS)')
    linked = {name.replace('-optin.dll', '.dll') for name in REQUIRED}   # what a game that lists both gets as <name>.dll
    for name, functions in REQUIRED.items():
        if name not in shipped:
            raise ValueError('missing required ' + name)
        module = PE(shipped[name])
        exports = module.exports()
        if any(not exports.get(function) for function in functions):
            raise ValueError(name + ': missing exports ' + ', '.join(f for f in functions if not exports.get(f)))
        imports, delayed = module.imports(), module.imports(True)
        if name == 'dxdiagn-optin.dll' and 'ddraw.dll' not in imports:
            raise ValueError('dxdiagn.dll is expected to import ddraw.dll')
        if delayed:
            raise ValueError(name + ': ARM64EC farm DLLs must use regular imports, not ' + ', '.join(sorted(delayed)))
        missing = {dep for dep in imports if dep not in shipped and dep not in linked and
                   not (dep.startswith(('api-ms-', 'ext-ms-')) and 'apisetschema.dll' in shipped)}
        if missing:
            raise ValueError(name + ': missing imports ' + ', '.join(sorted(missing)))
        if name == 'dxdiagn-optin.dll' and MARKER.encode() not in module.data:
            raise ValueError(name + ': not built from the tree tools/patch-wine-dxdiagn-directshow.py patches (no "%s")' % MARKER)
        print(name + ': exports present; all regular imports packaged (with the other opt-in DLL)')


if __name__ == '__main__':
    try:
        if len(sys.argv) != 2:
            raise ValueError('usage: check-wine-dxdiag-dll.py <arm64ec-windows directory>')
        check(sys.argv[1])
    except (OSError, ValueError, UnicodeError) as error:
        sys.exit('Wine DxDiag DLL check failed: ' + str(error))
