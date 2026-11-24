"""
Parser Index
============
Curated map of forensically relevant file formats to their best
available structural validators.

Each ParserEntry covers one format and knows:
  - How to identify it (MIME types + description keywords)
  - What Python library or CLI tool validates it
  - How to check if the tool is installed
  - How to build a Validator callable from the installed tool
  - What to tell the user if the tool is not installed

Scope decision
--------------
Only formats that:
  (a) appear regularly in digital forensics casework, AND
  (b) have a Python library or standard Kali tool available
are included. Everything else falls through to the SuggestionEngine.

Adding a new format
-------------------
Create a ParserEntry and add it to _ENTRIES at the bottom.
The match() method handles all lookup logic — no changes needed elsewhere.
"""

from __future__ import annotations

import importlib
import io
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Callable

from .probes.base_probe import Validator


# ─────────────────────────────────────────────────────────────────────────────
# Validator factories
# Each returns a Validator callable; only called after is_available() = True.
# ─────────────────────────────────────────────────────────────────────────────

def _elf_validator() -> Validator:
    def validate(data: bytes) -> tuple[bool, str]:
        try:
            from elftools.elf.elffile import ELFFile
            elf = ELFFile(io.BytesIO(data))
            return True, (
                f"pyelftools: {elf.get_machine_arch()} "
                f"{elf.header['e_type']}"
            )
        except Exception as exc:
            return False, f"pyelftools: {exc}"
    return validate


def _pe_validator() -> Validator:
    def validate(data: bytes) -> tuple[bool, str]:
        try:
            import pefile
            pe = pefile.PE(data=data, fast_load=True)
            machine = hex(pe.FILE_HEADER.Machine)
            return True, f"pefile: machine={machine}"
        except Exception as exc:
            return False, f"pefile: {exc}"
    return validate


def _macho_validator() -> Validator:
    def validate(data: bytes) -> tuple[bool, str]:
        try:
            from macholib.MachO import MachO
            tmp = _write_tmp(data)
            try:
                m = MachO(tmp)
                return True, f"macholib: {len(m.headers)} header(s)"
            finally:
                _rm_tmp(tmp)
        except Exception as exc:
            return False, f"macholib: {exc}"
    return validate


def _sqlite_validator() -> Validator:
    def validate(data: bytes) -> tuple[bool, str]:
        try:
            import sqlite3
            tmp = _write_tmp(data, suffix=".db")
            try:
                conn = sqlite3.connect(tmp)
                conn.execute("SELECT name FROM sqlite_master LIMIT 1")
                conn.close()
                return True, "sqlite3 (stdlib): database opened successfully"
            finally:
                _rm_tmp(tmp)
        except Exception as exc:
            return False, f"sqlite3: {exc}"
    return validate


def _gzip_validator() -> Validator:
    def validate(data: bytes) -> tuple[bool, str]:
        try:
            import gzip
            with gzip.open(io.BytesIO(data)) as f:
                f.read(256)
            return True, "gzip (stdlib): decompresses successfully"
        except Exception as exc:
            return False, f"gzip: {exc}"
    return validate


def _bzip2_validator() -> Validator:
    def validate(data: bytes) -> tuple[bool, str]:
        try:
            import bz2
            d = bz2.BZ2Decompressor()
            d.decompress(data)
            return True, "bz2 (stdlib): valid bzip2 stream"
        except Exception as exc:
            return False, f"bz2: {exc}"
    return validate


def _sevenz_validator() -> Validator:
    def validate(data: bytes) -> tuple[bool, str]:
        try:
            import py7zr
            with py7zr.SevenZipFile(io.BytesIO(data)) as z:
                names = z.getnames()
            return True, f"py7zr: {len(names)} entr(ies)"
        except Exception as exc:
            return False, f"py7zr: {exc}"
    return validate


def _rar_validator() -> Validator:
    def validate(data: bytes) -> tuple[bool, str]:
        try:
            import rarfile
            rf = rarfile.RarFile(io.BytesIO(data))
            names = rf.namelist()
            return True, f"rarfile: {len(names)} entr(ies)"
        except Exception as exc:
            return False, f"rarfile: {exc}"
    return validate


def _pcap_validator() -> Validator:
    def validate(data: bytes) -> tuple[bool, str]:
        try:
            import dpkt
            reader = dpkt.pcap.Reader(io.BytesIO(data))
            count = sum(1 for _ in reader)
            return True, f"dpkt: {count} packet(s)"
        except Exception as exc:
            return False, f"dpkt: {exc}"
    return validate


def _dex_validator() -> Validator:
    def validate(data: bytes) -> tuple[bool, str]:
        try:
            from androguard.core.bytecodes.dvm import DalvikVMFormat
            dex = DalvikVMFormat(data)
            return True, f"androguard: DEX {dex.get_version_name()}"
        except Exception as exc:
            return False, f"androguard: {exc}"
    return validate


# ─────────────────────────────────────────────────────────────────────────────
# Temp file helpers
# ─────────────────────────────────────────────────────────────────────────────

def _write_tmp(data: bytes, suffix: str = "") -> str:
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as f:
        f.write(data)
        return f.name


def _rm_tmp(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# ParserEntry
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ParserEntry:
    """
    Describes how to validate one file format.

    Fields
    ------
    fmt_hint            Short name used as format hint (e.g. "elf").
    display_name        Human-readable name.
    mime_types          MIME types emitted by libmagic for this format.
    description_keywords  Keywords present in libmagic description strings.
    python_lib          Python library name (None if stdlib or CLI-only).
    import_path         Dotted import path to check availability.
    stdlib              True if the validator uses only stdlib modules.
    validator_factory   Callable that returns a Validator when invoked.
    install_cmd         How to install the library.
    cli_tool            Optional CLI tool name (checked via shutil.which).
    cli_validator_cmd   --validator-cmd template using {file} placeholder.
    cli_install_hint    How to install the CLI tool.
    """

    fmt_hint: str
    display_name: str
    mime_types: tuple[str, ...]
    description_keywords: tuple[str, ...]
    validator_factory: Callable[[], Validator]
    stdlib: bool = False
    python_lib: str | None = None
    import_path: str | None = None
    install_cmd: str | None = None
    cli_tool: str | None = None
    cli_validator_cmd: str | None = None
    cli_install_hint: str | None = None

    def match(
        self,
        fmt_hint: str,
        mime_type: str,
        description: str,
    ) -> bool:
        """
        Return True if this entry matches the given identification signals.
        Matches on any of: user hint, MIME type, or description keyword.
        """
        hint_lower = fmt_hint.lower()
        mime_lower = mime_type.lower()
        desc_lower  = description.lower()

        if hint_lower == self.fmt_hint:
            return True
        if any(m in mime_lower for m in self.mime_types):
            return True
        if any(k in desc_lower for k in self.description_keywords):
            return True
        return False

    def is_available(self) -> bool:
        """
        Return True if the Python library or CLI tool is installed
        and ready to use as a validator.
        """
        if self.stdlib:
            return True
        if self.import_path:
            try:
                importlib.import_module(self.import_path)
                return True
            except ImportError:
                pass
        if self.cli_tool and shutil.which(self.cli_tool):
            return True
        return False

    def make_validator(self) -> Validator:
        """Build and return the Validator callable. Only call after is_available()."""
        return self.validator_factory()

    def install_hint(self) -> str:
        """Return a human-readable install instruction."""
        parts = []
        if self.install_cmd:
            parts.append(f"Python library: {self.install_cmd}")
        if self.cli_tool and self.cli_install_hint:
            parts.append(f"CLI tool: {self.cli_install_hint}")
        return "  \n".join(parts) if parts else "No install hint available."


# ─────────────────────────────────────────────────────────────────────────────
# ParserIndex
# ─────────────────────────────────────────────────────────────────────────────

class ParserIndex:
    """
    Lookup interface over the curated list of ParserEntry objects.
    All public methods return None / empty when no match is found.
    """

    @classmethod
    def find(
        cls,
        fmt_hint: str,
        mime_type: str,
        description: str,
    ) -> ParserEntry | None:
        """
        Return the first ParserEntry that matches the given signals,
        or None if the format is completely unknown to the index.
        """
        for entry in _ENTRIES:
            if entry.match(fmt_hint, mime_type, description):
                return entry
        return None

    @classmethod
    def all_entries(cls) -> list[ParserEntry]:
        return list(_ENTRIES)


# ─────────────────────────────────────────────────────────────────────────────
# Curated entries
# ─────────────────────────────────────────────────────────────────────────────

_ENTRIES: list[ParserEntry] = [

    ParserEntry(
        fmt_hint="elf",
        display_name="ELF (Executable and Linkable Format)",
        mime_types=("application/x-elf", "application/x-executable",
                    "application/x-sharedlib", "application/x-object"),
        description_keywords=("elf",),
        python_lib="pyelftools",
        import_path="elftools.elf.elffile",
        validator_factory=_elf_validator,
        install_cmd="pip install pyelftools",
        cli_tool="readelf",
        cli_validator_cmd="readelf -h {file}",
        cli_install_hint="apt install binutils",
    ),

    ParserEntry(
        fmt_hint="pe",
        display_name="PE (Portable Executable — Windows)",
        mime_types=("application/x-dosexec", "application/x-msdownload",
                    "application/vnd.microsoft.portable-executable"),
        description_keywords=("pe32", "pe32+", "dos executable",
                               "ms-dos executable"),
        python_lib="pefile",
        import_path="pefile",
        validator_factory=_pe_validator,
        install_cmd="pip install pefile",
        cli_tool="objdump",
        cli_validator_cmd="objdump -f {file}",
        cli_install_hint="apt install binutils",
    ),

    ParserEntry(
        fmt_hint="macho",
        display_name="Mach-O (macOS/iOS Executable)",
        mime_types=("application/x-mach-binary",),
        description_keywords=("mach-o", "macho"),
        python_lib="macholib",
        import_path="macholib.MachO",
        validator_factory=_macho_validator,
        install_cmd="pip install macholib",
    ),

    ParserEntry(
        fmt_hint="sqlite",
        display_name="SQLite Database",
        mime_types=("application/x-sqlite3", "application/vnd.sqlite3"),
        description_keywords=("sqlite",),
        stdlib=True,
        import_path="sqlite3",
        validator_factory=_sqlite_validator,
    ),

    ParserEntry(
        fmt_hint="gzip",
        display_name="gzip Compressed Data",
        mime_types=("application/gzip", "application/x-gzip"),
        description_keywords=("gzip",),
        stdlib=True,
        import_path="gzip",
        validator_factory=_gzip_validator,
        cli_tool="gzip",
        cli_validator_cmd="gzip -t {file}",
        cli_install_hint="apt install gzip",
    ),

    ParserEntry(
        fmt_hint="bzip2",
        display_name="bzip2 Compressed Data",
        mime_types=("application/x-bzip2",),
        description_keywords=("bzip2",),
        stdlib=True,
        import_path="bz2",
        validator_factory=_bzip2_validator,
        cli_tool="bzip2",
        cli_validator_cmd="bzip2 -t {file}",
        cli_install_hint="apt install bzip2",
    ),

    ParserEntry(
        fmt_hint="7zip",
        display_name="7-Zip Archive",
        mime_types=("application/x-7z-compressed",),
        description_keywords=("7-zip", "7zip"),
        python_lib="py7zr",
        import_path="py7zr",
        validator_factory=_sevenz_validator,
        install_cmd="pip install py7zr",
        cli_tool="7z",
        cli_validator_cmd="7z t {file}",
        cli_install_hint="apt install p7zip-full",
    ),

    ParserEntry(
        fmt_hint="rar",
        display_name="RAR Archive",
        mime_types=("application/x-rar-compressed", "application/vnd.rar"),
        description_keywords=("rar archive",),
        python_lib="rarfile",
        import_path="rarfile",
        validator_factory=_rar_validator,
        install_cmd="pip install rarfile",
        cli_tool="unrar",
        cli_validator_cmd="unrar t {file}",
        cli_install_hint="apt install unrar",
    ),

    ParserEntry(
        fmt_hint="pcap",
        display_name="PCAP Network Capture",
        mime_types=("application/vnd.tcpdump.pcap",
                    "application/x-pcap"),
        description_keywords=("pcap", "tcpdump", "wireshark"),
        python_lib="dpkt",
        import_path="dpkt",
        validator_factory=_pcap_validator,
        install_cmd="pip install dpkt",
        cli_tool="tcpdump",
        cli_validator_cmd="tcpdump -r {file} -c 1",
        cli_install_hint="apt install tcpdump",
    ),

    ParserEntry(
        fmt_hint="dex",
        display_name="Dalvik DEX (Android Bytecode)",
        mime_types=("application/x-dex",),
        description_keywords=("dalvik", "dex"),
        python_lib="androguard",
        import_path="androguard.core.bytecodes.dvm",
        validator_factory=_dex_validator,
        install_cmd="pip install androguard",
        cli_tool="dexdump",
        cli_validator_cmd="dexdump {file}",
        cli_install_hint="apt install android-tools-adb",
    ),
]
