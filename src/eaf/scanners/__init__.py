"""Scanner adapter registry."""
from __future__ import annotations

from importlib import metadata

from eaf.scanners.base import ScannerAdapter
from eaf.scanners.c_cpp_tools import CppcheckAdapter, FlawfinderAdapter
from eaf.scanners.hygiene import (CiConfigCheck, DependencyPinningCheck, GitignoreCheck,
                                  LargeFilesCheck, LicenseCheck, ReadmeCheck, TestsPresentCheck)
from eaf.scanners.js_tools import EslintJsAdapter, EslintTsAdapter, NpmAuditAdapter
from eaf.scanners.python_tools import BanditAdapter, PipAuditAdapter, RuffAdapter
from eaf.scanners.secrets import DetectSecretsAdapter, SensitiveFilesAdapter

BUILTIN_ADAPTERS: list[type[ScannerAdapter]] = [
    RuffAdapter, CppcheckAdapter, EslintJsAdapter, EslintTsAdapter,
    BanditAdapter, FlawfinderAdapter,
    DetectSecretsAdapter, SensitiveFilesAdapter,
    DependencyPinningCheck, PipAuditAdapter, NpmAuditAdapter,
    ReadmeCheck, LicenseCheck, GitignoreCheck, TestsPresentCheck, CiConfigCheck, LargeFilesCheck,
]


def all_adapters() -> list[ScannerAdapter]:
    """Built-in adapters plus any registered under the 'eaf.scanners' entry-point group."""
    classes = list(BUILTIN_ADAPTERS)
    for ep in metadata.entry_points(group="eaf.scanners"):
        classes.append(ep.load())
    seen, out = set(), []
    for cls in classes:
        if cls.id in seen:
            raise RuntimeError(f"Duplicate scanner adapter id: {cls.id}")
        seen.add(cls.id)
        out.append(cls())
    return out
