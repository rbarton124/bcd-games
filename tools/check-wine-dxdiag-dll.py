#!/usr/bin/env python3
"""Require Wine's DxDiag provider (dxdiagn.dll) and its imports in the 64-bit farm.

The prefix registers CLSID_DxDiagProvider at system32\\dxdiagn.dll. Without the DLL CoCreateInstance fails, and Far Cry 4's
systemdetection64.dll ("Can't get the IDxDiagProvider") hands the game a null result it reads 33 s into its start
(2026-11-04). tools/build-wine-extra-dlls.sh builds dxdiagn.dll and the ddraw.dll it imports in a step that may fail
without failing the build; this check runs after it, as tools/check-wine-media-dlls.py does for the media reader, and
reuses that script's PE reader. Checks the COM exports, regular imports only (see UNDELAY in build/wine-pe/build-modules.sh)
and that every import is packaged.
"""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

_spec = spec_from_file_location('check_wine_media_dlls', Path(__file__).with_name('check-wine-media-dlls.py'))
_media = module_from_spec(_spec)
_spec.loader.exec_module(_media)
PE = _media.PE

REQUIRED = {
    'dxdiagn.dll': ('DllGetClassObject', 'DllCanUnloadNow'),
    'ddraw.dll': ('DirectDrawCreate', 'DirectDrawCreateEx'),
}


def check(bundle):
    bundle = Path(bundle)
    shipped = {p.name.lower(): p for p in bundle.iterdir() if p.is_file()}
    for name, functions in REQUIRED.items():
        if name not in shipped:
            raise ValueError('missing required ' + name)
        module = PE(shipped[name])
        exports = module.exports()
        if any(not exports.get(function) for function in functions):
            raise ValueError(name + ': missing exports ' + ', '.join(f for f in functions if not exports.get(f)))
        imports, delayed = module.imports(), module.imports(True)
        if name == 'dxdiagn.dll' and 'ddraw.dll' not in imports:
            raise ValueError('dxdiagn.dll is expected to import ddraw.dll')
        if delayed:
            raise ValueError(name + ': ARM64EC farm DLLs must use regular imports, not ' + ', '.join(sorted(delayed)))
        missing = {dep for dep in imports if dep not in shipped and
                   not (dep.startswith(('api-ms-', 'ext-ms-')) and 'apisetschema.dll' in shipped)}
        if missing:
            raise ValueError(name + ': missing imports ' + ', '.join(sorted(missing)))
        print(name + ': COM/ddraw exports present; all regular imports packaged')


if __name__ == '__main__':
    try:
        if len(sys.argv) != 2:
            raise ValueError('usage: check-wine-dxdiag-dll.py <arm64ec-windows directory>')
        check(sys.argv[1])
    except (OSError, ValueError, UnicodeError) as error:
        sys.exit('Wine DxDiag DLL check failed: ' + str(error))
