#!/usr/bin/env python3
"""
ARC Extractor GUI

Nuova GUI dedicata all'estrazione ARC0.

Comportamento:
  - La cartella degli ARC viene scelta dalla GUI.
  - I .database vengono cercati esclusivamente nella directory del programma.
  - Se esiste un database associato/selezionato, la GUI costruisce un albero
    gerarchico SECTION_START/SECTION_END con checkbox per sezioni e file.
  - In modalita database vengono estratti solo i file selezionati.
  - Se non esiste un database valido, o se l'utente forza la modalita lenta,
    viene usata la modalita ARC completa: parsing ARC0 + name trie + CRC +
    estrazione concorrente.

Il parser e le routine di sicurezza dell'ARC extractor sono mantenuti qui come
motore indipendente dalla vecchia GUI fornita dall'utente.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import mmap
import os
import re
import shutil
import stat
import struct
import locale
import json
import sys
import tempfile
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Iterable

from PyQt6 import QtCore, QtWidgets


MAGIC = b"ARC0"

# Directory del programma quando eseguito come .py.
BASE_DIR = Path(__file__).resolve().parent


def _translation_roots() -> list[Path]:
    roots: list[Path] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        roots.append(Path(meipass))
    if getattr(sys, "frozen", False):
        roots.append(Path(sys.executable).resolve().parent)
    roots.append(BASE_DIR)
    unique: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        key = os.path.normcase(os.path.abspath(root))
        if key not in seen and root.is_dir():
            seen.add(key)
            unique.append(root)
    return unique


def _get_requested_language() -> str:
    """Resolve the requested UI language.

    Priority:
      1. ``--lang LANGUAGE`` or ``--lang=LANGUAGE`` from the CLI
      2. ``ARC_EXTRACTOR_LANG`` environment variable
      3. system locale
    """
    args = sys.argv[1:]
    for index, arg in enumerate(args):
        if arg == "--lang":
            if index + 1 < len(args):
                value = args[index + 1].strip().lower()
                if value:
                    return value
            continue
        if arg.startswith("--lang="):
            value = arg.split("=", 1)[1].strip().lower()
            if value:
                return value

    value = os.environ.get("ARC_EXTRACTOR_LANG", "").strip().lower()
    if value:
        return value

    return (locale.getlocale()[0] or "it").split("_")[0].lower()


def _load_translation_catalog() -> dict[str, str]:
    lang = _get_requested_language()

    candidates: list[Path] = []
    for root in _translation_roots():
        candidates.extend([
            root / "translations" / f"{lang}.json",
            root / f"{lang}.json",
        ])

    catalog: dict[str, str] = {}
    for path in candidates:
        try:
            if not path.is_file():
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                catalog.update({str(k): str(v) for k, v in data.items()})
        except (OSError, ValueError, TypeError):
            continue
    return catalog


_TRANSLATIONS = _load_translation_catalog()


def T(text: str, **kwargs) -> str:
    value = _TRANSLATIONS.get(text, text)
    return value.format(**kwargs) if kwargs else value

# ---------------------------------------------------------------------------
# DATABASE EMBEDDED / SHA256
# ---------------------------------------------------------------------------
#
# Inserire qui le coppie:
#
#     SHA256_DELL_ARC: NOME_DEL_DATABASE
#
# Esempio:
#
#     "0123456789abcdef...": "game.database",
#
# Un database viene considerato valido SOLO quando lo SHA256 dell'ARC
# corrisponde a una chiave presente qui. In caso contrario il database non
# viene mostrato/usato e l'interfaccia resta nella modalita ARC lenta.
#
# Lo stesso meccanismo funziona con:
#   - database accanto allo script
#   - database accanto all'EXE
#   - database embedded in un EXE PyInstaller (--add-data)
#
KNOWN_ARC_DATABASES: dict[str, str] = {
    "533bec451452c8377a2ae4daf20af45d318d94bd6d5696b4ed9545498387c775": "partition_data_win.database",
    "17354a24e762ed6a982828406b1bdb6746abc8b636464bb8a6efa9a26fe4fc71": "partition_data_win_us.database",
    "eb2549bc4ab2def9b9a903faa76c9f46fd596d328d0ae7fbce9c505970369280": "partition_resident_win.database",
    "3272c879d848a05ff08bb3aa0dcaa4732d2f7a2573440a1fc2a718d36bf2fcaf": "partition_data_win_zh.database",
    "fd5e58a2b87b05f06689d9e28daf9df07acd3e60cf7003842ea38b1347ec75f5": "partition_data_win_jp.database",
}

# ARC names known to this tool. These are used only for preset discovery
# and informational logging; they are not treated as an exhaustive archive list.
KNOWN_ARC_STEMS: tuple[str, ...] = (
    "partition_data_win",
    "partition_data_win_us",
    "partition_resident_win",
    "partition_data_win_zh",
    "partition_data_win_jp",
)

TRANSLATION_ARC_STEMS: tuple[str, ...] = (
    "partition_data_win_us",
    "partition_resident_win",
)

RELEVANT_ARC_STEMS: tuple[str, ...] = (
    "partition_data_win",
    "partition_data_win_us",
    "partition_resident_win",
)


_WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
_WINDOWS_FORBIDDEN_CHARS = set('<>:"/\\|?*')


# ============================================================================
# COMMON WINDOWS / OUTPUT SECURITY
# ============================================================================


def _is_reparse_point(path: Path) -> bool:
    try:
        st = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return False

    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
    attrs = getattr(st, "st_file_attributes", 0)
    try:
        symlink = path.is_symlink()
    except OSError:
        symlink = False
    return bool(attrs & reparse_flag) or symlink


def _validate_component(component: str) -> None:
    if not component or component in {".", ".."}:
        raise ValueError(f"nome componente non valido: {component!r}")
    if len(component) > 255:
        raise ValueError(f"componente troppo lungo: {component!r}")
    if component[-1] in {".", " "}:
        raise ValueError("un nome Windows non puo terminare con punto/spazio")
    if any(ord(ch) < 32 for ch in component):
        raise ValueError("carattere di controllo nel percorso")
    if any(ch in _WINDOWS_FORBIDDEN_CHARS for ch in component):
        raise ValueError(f"carattere non valido nel percorso Windows: {component!r}")
    if component.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES:
        raise ValueError(f"nome riservato da Windows: {component!r}")


def _validate_relative_name(fname: str):
    raw = fname.strip()
    if not raw:
        raise ValueError("filename vuoto")
    if "\x00" in raw:
        raise ValueError("NUL byte nel filename")

    raw_parts = raw.replace("/", "\\").split("\\")
    if any(p in {".", ".."} for p in raw_parts):
        raise ValueError("'.' e '..' non sono ammessi")
    if any(p == "" for p in raw_parts):
        raise ValueError("separatori duplicati/percorso assoluto non consentiti")

    p = PureWindowsPath(raw)
    if p.is_absolute() or p.drive or p.root or p.anchor:
        raise ValueError(f"percorso assoluto/UNC/device non consentito: {fname!r}")
    if not p.parts or len(p.parts) != len(raw_parts):
        raise ValueError(f"percorso ambiguo/non canonico: {fname!r}")

    for part in p.parts:
        _validate_component(part)
    return p.parts


def _prepare_output_root(outdir: Path, create: bool) -> Path:
    if create:
        outdir.mkdir(parents=True, exist_ok=True)

    if outdir.exists() and not outdir.is_dir():
        raise NotADirectoryError(f"output non e una directory: {outdir}")

    root = outdir.resolve(strict=False)
    if create and (not root.exists() or not root.is_dir()):
        raise NotADirectoryError(f"output non disponibile: {root}")
    if _is_reparse_point(root):
        raise RuntimeError(f"output root e un reparse point/symlink: {root}")
    return root


def _secure_output_path(root: Path, fname: str, create_parents: bool) -> Path:
    parts = _validate_relative_name(fname)

    parent = root
    for part in parts[:-1]:
        parent = parent / part
        if parent.exists():
            if not parent.is_dir():
                raise NotADirectoryError(f"non e una directory: {parent}")
            if _is_reparse_point(parent):
                raise RuntimeError(f"reparse point/symlink non consentito: {parent}")
        elif create_parents:
            parent.mkdir(exist_ok=True)
            if not parent.is_dir() or _is_reparse_point(parent):
                raise RuntimeError(f"directory non sicura: {parent}")

    resolved_parent = parent.resolve(strict=False)
    try:
        resolved_parent.relative_to(root)
    except ValueError as exc:
        raise RuntimeError("il percorso esce dalla cartella di output") from exc

    target = parent / parts[-1]
    if target.exists() and _is_reparse_point(target):
        raise RuntimeError(f"destinazione reparse point/symlink non consentita: {target}")
    return target


def _same_file(path_a: Path, path_b: Path) -> bool:
    try:
        return os.path.samefile(path_a, path_b)
    except (FileNotFoundError, OSError):
        try:
            return path_a.resolve(strict=False) == path_b.resolve(strict=False)
        except OSError:
            return False


def _reject_source_overwrite(out_path: Path, source_paths: Iterable[Path]) -> None:
    for source_path in source_paths:
        if source_path is not None and _same_file(out_path, source_path):
            raise RuntimeError(f"destinazione coincide con sorgente: {out_path}")


def _write_segment_atomically(
    input_file,
    input_path: Path,
    out_path: Path,
    offset: int,
    length: int,
    protected_paths=(),
):
    _reject_source_overwrite(out_path, protected_paths)

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=".extract-",
            suffix=".tmp",
            dir=str(out_path.parent),
            delete=False,
        ) as out_f:
            temp_path = Path(out_f.name)
            input_file.seek(offset)
            remaining = length
            chunk_size = 16 * 1024 * 1024

            while remaining > 0:
                data = input_file.read(min(chunk_size, remaining))
                if not data:
                    raise IOError(
                        f"EOF inatteso durante la lettura di {input_path} a 0x{offset:X}"
                    )
                out_f.write(data)
                remaining -= len(data)

            out_f.flush()
            os.fsync(out_f.fileno())

        if out_path.exists() and _is_reparse_point(out_path):
            raise RuntimeError(f"destinazione reparse point/symlink: {out_path}")
        os.replace(str(temp_path), str(out_path))
        temp_path = None
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


# ============================================================================
# DATABASE PARSER
# ============================================================================


def parse_number(value: str) -> int:
    value = value.strip()
    return int(value, 16) if value.lower().startswith("0x") else int(value, 10)


def parse_database_line(line: str):
    low = line.lower()
    off_match = re.search(r"offset\s+(0x[0-9a-f]+|\d+)", low)
    len_match = re.search(r"length\s+(0x[0-9a-f]+|\d+)", low)
    is_pos = low.find(" is ")

    if not off_match or not len_match:
        return None

    try:
        offset = parse_number(off_match.group(1))
        length = parse_number(len_match.group(1))
    except ValueError:
        return None

    if is_pos != -1:
        fname = line[is_pos + 4:].strip()
    else:
        m = re.search(r"\)\s*(.+)$", line)
        fname = m.group(1).strip() if m else ""

    fname = fname.strip().strip('"').strip("'")
    if not fname:
        return None

    return offset, length, fname


@dataclass
class DatabaseEntry:
    offset: int
    length: int
    path: str
    line_no: int = 0
    source_archive: Path | None = None


@dataclass
class DatabaseSection:
    name: str
    children: list["DatabaseSection"] = field(default_factory=list)
    entries: list[DatabaseEntry] = field(default_factory=list)


@dataclass
class DatabaseDocument:
    sections: list[DatabaseSection] = field(default_factory=list)
    root_entries: list[DatabaseEntry] = field(default_factory=list)


def _comment_payload(line: str) -> str:
    return line[1:].strip() if line.startswith("#") else ""


def parse_database_file(path: Path) -> DatabaseDocument:
    """Parse sectioned, mixed, or completely raw .database files.

    Raw entries remain top-level entries; they are never wrapped in a fake
    ``Database`` section.
    """
    document = DatabaseDocument()
    stack: list[DatabaseSection] = []
    pending_section_name: str | None = None

    with path.open("r", encoding="utf-8", errors="replace") as dbf:
        for line_no, raw in enumerate(dbf, start=1):
            line = raw.rstrip("\r\n").strip()
            if not line:
                # Blank lines are formatting only; they have no semantic
                # meaning in the database format.
                continue

            if line.startswith("#"):
                payload = _comment_payload(line)
                upper = payload.upper()

                if upper.startswith("FILE_TOP") or upper.startswith("FILE_BOTTOM"):
                    pending_section_name = None
                    continue

                if upper.startswith("SECTION_END"):
                    if stack:
                        stack.pop()
                    pending_section_name = None
                    continue

                if upper.startswith("SECTION_START"):
                    # The comment immediately above SECTION_START is the
                    # section name. SECTION_START can also carry its own name
                    # after the marker as a fallback.
                    name = pending_section_name
                    marker = payload[len("SECTION_START"):].strip()
                    if not name:
                        if marker.startswith("//"):
                            name = marker[2:].strip()
                        elif marker:
                            name = marker
                    name = name or T("Sezione senza nome")
                    section = DatabaseSection(name=name)
                    if stack:
                        stack[-1].children.append(section)
                    else:
                        document.sections.append(section)
                    stack.append(section)
                    pending_section_name = None
                    continue

                # Ordinary comments are candidates for the next
                # SECTION_START. If an actual database entry follows instead,
                # the pending comment is cleared below, so decorative comments
                # such as "# NEW: ..." can never leak forward and become a
                # section name later in the file.
                pending_section_name = payload
                continue

            entry = parse_database_line(line)
            if entry is None:
                pending_section_name = None
                continue

            offset, length, fname = entry
            db_entry = DatabaseEntry(offset=offset, length=length, path=fname, line_no=line_no)
            if stack:
                stack[-1].entries.append(db_entry)
            else:
                document.root_entries.append(db_entry)
            pending_section_name = None

    return document



# ============================================================================
# ARC0 PARSER
# ============================================================================


class ParseError(Exception):
    pass


def read_u32(buf, off):
    if off + 4 > len(buf):
        raise ParseError(f"unexpected EOF reading u32 at 0x{off:X}")
    return struct.unpack_from("<I", buf, off)[0], off + 4


def read_u64(buf, off):
    if off + 8 > len(buf):
        raise ParseError(f"unexpected EOF reading u64 at 0x{off:X}")
    return struct.unpack_from("<Q", buf, off)[0], off + 8


def parse_trie_block(buf, off, verbose=False):
    n1, off = read_u32(buf, off)
    total_bits, off = read_u32(buf, off)
    n2, off = read_u32(buf, off)
    n3, off = read_u32(buf, off)

    remaining = len(buf) - off
    bytes_needed = (n1 + n2 + n3) * 4
    if bytes_needed > remaining:
        raise ParseError("trie block runs past end of header")

    if total_bits > n1 * 32:
        raise ParseError(
            f"trie total_bits={total_bits} exceeds capacity {n1 * 32}"
        )

    bitvector_off = off
    off += n1 * 4
    rank1_off = off
    off += n2 * 4
    rank2_off = off
    off += n3 * 4

    if verbose:
        print(f"    [trie] n1={n1} total_bits={total_bits} n2={n2} n3={n3}")

    return {
        "n1": n1,
        "total_bits": total_bits,
        "n2": n2,
        "n3": n3,
        "bitvector": buf[bitvector_off:bitvector_off + n1 * 4],
        "rank1": buf[rank1_off:rank1_off + n2 * 4],
        "rank2": buf[rank2_off:rank2_off + n3 * 4],
    }, off


def parse_name_index(buf, off, verbose=False):
    node_count, off = read_u32(buf, off)
    trie, off = parse_trie_block(buf, off, verbose=verbose)
    label_len, off = read_u32(buf, off)

    if label_len > len(buf) - off:
        raise ParseError("label data runs past end of header")

    labels = buf[off:off + label_len]
    off += label_len
    root_extra, off = read_u32(buf, off)

    if verbose:
        print(
            f"    [names] node_count={node_count} "
            f"label_len={label_len} root_extra={root_extra}"
        )

    return {
        "node_count": node_count,
        "trie": trie,
        "labels": labels,
        "root_extra": root_extra,
    }, off


def parse_header(buf, verbose=False):
    off = 0
    name_index_size, off = read_u32(buf, off)
    name_index_start = off
    name_index, off = parse_name_index(buf, off, verbose=verbose)
    name_index_actual = off - name_index_start

    if verbose:
        mark = "" if name_index_actual == name_index_size else "  <-- MISMATCH"
        print(f"  name_index_size = {name_index_size}{mark}")
        print(f"    actual bytes consumed = {name_index_actual}")

    leaf_index_size, off = read_u32(buf, off)
    leaf_index_start = off
    leaf_index, off = parse_trie_block(buf, off, verbose=verbose)
    leaf_index_actual = off - leaf_index_start

    if verbose:
        mark = "" if leaf_index_actual == leaf_index_size else "  <-- MISMATCH"
        print(f"  leaf_index_size = {leaf_index_size}{mark}")
        print(f"    actual bytes consumed = {leaf_index_actual}")

    file_count, off = read_u32(buf, off)
    remaining = len(buf) - off
    if file_count > remaining // 20:
        raise ParseError(
            f"file_count={file_count} cannot fit in remaining header bytes ({remaining})"
        )

    entries = []
    for index in range(file_count):
        size, off = read_u64(buf, off)
        offset, off = read_u64(buf, off)
        crc32, off = read_u32(buf, off)
        entries.append({
            "index": index,
            "offset": offset,
            "size": size,
            "crc32": crc32,
        })

    trailing = len(buf) - off

    if verbose:
        print(f"  parsed {len(entries)} entries")
        print(f"  trailing bytes = {trailing}")

    return {
        "name_index": name_index,
        "leaf_index": leaf_index,
        "file_count": file_count,
        "entries": entries,
        "trailing_bytes": trailing,
    }


class BitRank:
    def __init__(self, n1_words, total_bits, bitvector_bytes):
        self.total_bits = total_bits
        self.words = struct.unpack(
            f"<{n1_words}I", bitvector_bytes
        ) if n1_words else ()
        prefix = [0] * (total_bits + 1)
        zero_positions = []
        cnt1 = 0

        for pos in range(total_bits):
            bit = (self.words[pos >> 5] >> (pos & 31)) & 1
            if bit:
                cnt1 += 1
            else:
                zero_positions.append(pos)
            prefix[pos + 1] = cnt1

        self.prefix = prefix
        self.zero_positions = zero_positions

    def bit(self, pos):
        if pos < 0 or pos >= self.total_bits:
            return 0
        return (self.words[pos >> 5] >> (pos & 31)) & 1

    def rank1_incl(self, pos):
        if pos < 0:
            return 0
        if pos >= self.total_bits:
            pos = self.total_bits - 1
        return self.prefix[pos + 1]

    def select0(self, k):
        if k <= 0 or k > len(self.zero_positions):
            return None
        return self.zero_positions[k - 1]

    def children(self, node, gap=2):
        term = self.select0(node)
        if term is None:
            return []

        pos = term + gap
        children = []
        while self.bit(pos) == 1:
            children.append(self.rank1_incl(pos))
            pos += 1
        return children


def _count_reachable(names_bits, gap, cap):
    visited = set()
    stack = [1]

    while stack:
        node = stack.pop()
        if node in visited:
            continue
        visited.add(node)
        if len(visited) > cap:
            break
        for child in names_bits.children(node, gap=gap):
            if child not in visited:
                stack.append(child)
    return visited


def build_name_map(name_index, leaf_index, verbose=False):
    trie_data = name_index["trie"]
    names_bits = BitRank(
        trie_data["n1"], trie_data["total_bits"], trie_data["bitvector"]
    )
    leaf_bits = BitRank(
        leaf_index["n1"], leaf_index["total_bits"], leaf_index["bitvector"]
    )
    labels = name_index["labels"]
    expected_nodes = name_index["root_extra"] + 1
    cap = expected_nodes * 3 + 100
    candidates = [2, 1, 3, 0, 4, 5]
    best_gap = candidates[0]
    best_reached = set()

    for gap in candidates:
        reached = _count_reachable(names_bits, gap, cap)
        if len(reached) > len(best_reached):
            best_gap = gap
            best_reached = reached
        if len(reached) >= expected_nodes:
            break

    if verbose:
        print(f"  [names] expected nodes = {expected_nodes}")
        print(f"  [names] selected gap = {best_gap}")

    result = {}
    max_label_idx = len(labels) - 1
    stack = [(1, b"")]
    visited = set()

    while stack:
        node, prefix = stack.pop()
        if node in visited:
            continue
        visited.add(node)

        if leaf_bits.bit(node):
            result[leaf_bits.rank1_incl(node) - 1] = prefix

        for child in names_bits.children(node, gap=best_gap):
            if child in visited:
                continue
            new_prefix = (
                prefix + bytes([labels[child]])
                if 0 <= child <= max_label_idx
                else prefix
            )
            stack.append((child, new_prefix))

    return result


def sanitize_arc_path(raw_bytes):
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        text = raw_bytes.decode("latin-1")

    text = text.replace("\\", "/").lstrip("/")
    parts = [p for p in text.split("/") if p not in ("", ".", "..")]
    if not parts:
        return None

    candidate = "/".join(parts)
    try:
        safe_parts = _validate_relative_name(candidate)
    except ValueError:
        return None
    return "/".join(safe_parts)


def arc_crc32(mm, offset, size):
    crc = 0
    pos = 0
    while pos < size:
        length = min(0x400, size - pos)
        start = offset + pos
        chunk = mm[start:start + length]
        if len(chunk) != length:
            raise ParseError(f"unexpected EOF while calculating CRC at 0x{start:X}")
        crc = zlib.crc32(chunk, crc) & 0xFFFFFFFF
        pos += 0x200000
    return crc


def validate_entries(entries, archive_size):
    for entry in entries:
        offset, size = entry["offset"], entry["size"]
        if offset > archive_size:
            raise ParseError(
                f"entry {entry['index']} offset 0x{offset:X} is outside archive"
            )
        if size > archive_size - offset:
            raise ParseError(f"entry {entry['index']} exceeds archive")


# ============================================================================
# GUI WORKERS
# ============================================================================


def _atomic_text_replace(path: Path, text: str, root: Path):
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", prefix=".gui-", suffix=".tmp", dir=str(root), delete=False
        ) as f:
            tmp = Path(f.name)
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        if path.exists() and _is_reparse_point(path):
            raise RuntimeError(f"destinazione reparse point/symlink: {path}")
        os.replace(str(tmp), str(path))
        tmp = None
    finally:
        if tmp is not None:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass


class BaseWorker(QtCore.QObject):
    message = QtCore.pyqtSignal(str)
    # Floating-point byte counters avoid the signed 32-bit Qt int limit for
    # multi-GB extractions.
    progress = QtCore.pyqtSignal(float, float, str)
    finished = QtCore.pyqtSignal(bool, str)


class Sha256Worker(QtCore.QObject):
    progress = QtCore.pyqtSignal(float, str)
    finished = QtCore.pyqtSignal(object, str)

    def __init__(self, archive_paths: list[Path]):
        super().__init__()
        self.archive_paths = list(archive_paths)

    @QtCore.pyqtSlot()
    def run(self):
        results: dict[str, str] = {}
        try:
            total_bytes = sum(path.stat().st_size for path in self.archive_paths)
            processed_total = 0
            if total_bytes <= 0:
                self.progress.emit(100.0, T("SHA256 100% | nessun byte da leggere"))

            for archive_index, archive in enumerate(self.archive_paths, start=1):
                archive_size = archive.stat().st_size
                processed_file = 0
                digest = hashlib.sha256()
                self.progress.emit(
                    (processed_total / total_bytes * 100.0) if total_bytes else 100.0,
                    f"SHA256 {(processed_total / total_bytes * 100.0) if total_bytes else 100.0:.1f}% | "
                    f"{archive.name} ({archive_index}/{len(self.archive_paths)})",
                )

                with archive.open("rb") as f:
                    while True:
                        chunk = f.read(16 * 1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                        processed_file += len(chunk)
                        processed_total += len(chunk)
                        percent = (processed_total / total_bytes * 100.0) if total_bytes else 100.0
                        self.progress.emit(
                            percent,
                            f"SHA256 {percent:.1f}% | "
                            f"{processed_total / (1024 * 1024):,.0f} / "
                            f"{total_bytes / (1024 * 1024):,.0f} MiB | "
                            f"{archive.name} {processed_file / (1024 * 1024):,.0f}/"
                            f"{archive_size / (1024 * 1024):,.0f} MiB",
                        )

                results[os.path.normcase(os.path.abspath(archive))] = digest.hexdigest().lower()

            self.progress.emit(100.0, T("SHA256 100% | verifiche completate: {count:,} ARC", count=len(results)))
            self.finished.emit(results, "")
        except Exception as exc:
            self.finished.emit(results, str(exc))


class DatabaseWorker(BaseWorker):
    """Fast database-driven extractor.

    The database already gives us the physical offset and exact length of each
    file, so the extractor avoids the old per-file open/mmap/fsync pipeline.
    Entries are sorted by physical offset inside each ARC and processed in
    moderately large batches. Each batch keeps the ARC open for all of its
    files, reducing handle churn and seeks. Different ARC files and batches are
    scheduled through the same worker pool so the disks can stay busy.
    """

    IO_CHUNK_SIZE = 16 * 1024 * 1024
    BATCH_TARGET_SPAN = 512 * 1024 * 1024
    BATCH_MAX_FILES = 512
    PROGRESS_INTERVAL = 0.10

    def __init__(self, output_dir: Path, entries: list[DatabaseEntry], move_archives: bool = False):
        super().__init__()
        self.output_dir = output_dir
        self.entries = entries
        self.move_archives = move_archives
        self._progress_lock = __import__("threading").Lock()
        self._processed_bytes = 0
        self._processed_files = 0
        self._progress_started = 0.0
        self._last_progress_emit = 0.0
        self._total_bytes = 0
        self._total_files = len(entries)

    @staticmethod
    def _recommended_workers() -> int:
        cpu = os.cpu_count() or 1
        return max(1, cpu if cpu <= 2 else cpu - 2)

    @classmethod
    def _build_batches(cls, grouped: dict[str, list[DatabaseEntry]], archive_objects: dict[str, Path]):
        """Split each ARC into large offset-ordered batches, then interleave them."""
        per_archive: dict[str, list[list[DatabaseEntry]]] = {}

        for key, bucket in grouped.items():
            bucket.sort(key=lambda e: (e.offset, e.length, e.path.casefold()))
            batches: list[list[DatabaseEntry]] = []
            current: list[DatabaseEntry] = []
            batch_start = None

            for entry in bucket:
                if not current:
                    current = [entry]
                    batch_start = entry.offset
                    continue

                batch_end = max(
                    current[-1].offset + current[-1].length,
                    entry.offset + entry.length,
                )
                span = batch_end - int(batch_start)

                if span > cls.BATCH_TARGET_SPAN or len(current) >= cls.BATCH_MAX_FILES:
                    batches.append(current)
                    current = [entry]
                    batch_start = entry.offset
                else:
                    current.append(entry)

            if current:
                batches.append(current)

            per_archive[key] = batches

        ordered_keys = sorted(
            per_archive,
            key=lambda key: (str(archive_objects[key]).casefold(), key),
        )

        interleaved: list[list[DatabaseEntry]] = []
        position = 0
        while True:
            added = False
            for key in ordered_keys:
                batches = per_archive[key]
                if position < len(batches):
                    interleaved.append(batches[position])
                    added = True
            if not added:
                break
            position += 1

        return interleaved

    @staticmethod
    def _validate_entry(entry: DatabaseEntry, archive_size: int) -> None:
        if entry.offset < 0 or entry.length <= 0:
            raise ValueError("offset/length non validi")
        if entry.offset >= archive_size:
            raise ValueError(f"offset 0x{entry.offset:X} oltre EOF 0x{archive_size:X}")
        if entry.length > archive_size - entry.offset:
            raise ValueError(
                f"offset+length 0x{entry.offset + entry.length:X} oltre EOF 0x{archive_size:X}"
            )

    def _emit_progress(self, force: bool = False, label: str = ""):
        now = time.perf_counter()
        with self._progress_lock:
            if not force and (now - self._last_progress_emit) < self.PROGRESS_INTERVAL:
                return
            self._last_progress_emit = now
            processed = self._processed_bytes
            files = self._processed_files
            total = self._total_bytes
            total_files = self._total_files
            elapsed = max(0.001, now - self._progress_started)
            speed_mib = processed / (1024 * 1024) / elapsed

        text = T(
            "{done_gib:.2f}/{total_gib:.2f} GiB | {files:,}/{total_files:,} file | {speed:.0f} MiB/s",
            done_gib=processed / (1024 ** 3),
            total_gib=total / (1024 ** 3),
            files=files,
            total_files=total_files,
            speed=speed_mib,
        )
        if label:
            text += " | " + label
        self.progress.emit(float(processed), float(max(1, total)), text)

    def _record_progress(self, byte_count: int, file_count: int, label: str):
        with self._progress_lock:
            self._processed_bytes += byte_count
            self._processed_files += file_count
        self._emit_progress(label=label)

    def _copy_exact(self, source, destination, length: int, label: str) -> None:
        remaining = length
        while remaining:
            chunk = source.read(min(self.IO_CHUNK_SIZE, remaining))
            if not chunk:
                raise IOError("EOF inatteso durante l'estrazione")
            destination.write(chunk)
            remaining -= len(chunk)
            # Report bytes as they are actually copied. This keeps the GUI
            # moving even when one individual file is very large.
            self._record_progress(len(chunk), 0, label)

    def _extract_batch(self, batch: list[DatabaseEntry], root: Path, archive_size: int):
        archive = batch[0].source_archive
        if archive is None:
            raise ValueError("batch senza ARC sorgente")

        ok = 0
        failed = 0
        errors: list[str] = []

        # A batch opens the source once and then walks forward through the
        # selected entries in physical offset order.
        with archive.open("rb", buffering=self.IO_CHUNK_SIZE) as source:
            current_position = None

            for entry in batch:
                try:
                    self._validate_entry(entry, archive_size)
                    out_path = _secure_output_path(root, entry.path, create_parents=True)
                    if out_path.is_dir():
                        raise IsADirectoryError(f"destinazione directory: {out_path}")
                    _reject_source_overwrite(out_path, (archive,))

                    if current_position != entry.offset:
                        source.seek(entry.offset, os.SEEK_SET)

                    # Direct final-file writes are intentional here. The old
                    # temp-file + fsync + replace sequence caused a very large
                    # amount of metadata/storage overhead for tens of thousands
                    # of already-validated segments.
                    label = T(
                        "{archive} | 0x{offset:X} | {path}",
                        archive=archive.name,
                        offset=entry.offset,
                        path=entry.path,
                    )
                    with open(out_path, "wb", buffering=self.IO_CHUNK_SIZE) as destination:
                        self._copy_exact(source, destination, entry.length, label)
                        destination.flush()

                    current_position = entry.offset + entry.length
                    ok += 1
                    self._record_progress(0, 1, label)
                except Exception as exc:
                    failed += 1
                    errors.append(f"[{archive.name}] {entry.path}: {exc}")
                    self._record_progress(0, 1, T("ERRORE | {archive} | {path}", archive=archive.name, path=entry.path))
                    current_position = None

        return ok, failed, errors

    @staticmethod
    def _move_archives_to_parent(archives: set[Path], message):
        for archive in sorted(archives, key=lambda p: str(p).casefold()):
            destination = archive.parent.parent / archive.name
            if _same_file(archive, destination):
                continue
            if destination.exists():
                raise FileExistsError(f"destinazione gia esistente: {destination}")
            shutil.move(str(archive), str(destination))
            message(T("Spostato {name} in {dest}", name=archive.name, dest=destination))

    @QtCore.pyqtSlot()
    def run(self):
        start_time = time.perf_counter()
        try:
            root = _prepare_output_root(self.output_dir, create=True)

            grouped: dict[str, list[DatabaseEntry]] = {}
            archive_objects: dict[str, Path] = {}
            archive_sizes: dict[str, int] = {}

            for entry in self.entries:
                archive = entry.source_archive
                if archive is None:
                    raise ValueError("entry senza ARC sorgente")
                key = os.path.normcase(os.path.abspath(archive))
                if key not in archive_objects:
                    archive_objects[key] = archive
                    archive_sizes[key] = archive.stat().st_size
                self._validate_entry(entry, archive_sizes[key])
                grouped.setdefault(key, []).append(entry)

            # Pre-create/check output parents once before launching the workers.
            # This removes directory creation races from the hot I/O path.
            total_bytes = 0
            for entry in self.entries:
                out_path = _secure_output_path(root, entry.path, create_parents=True)
                if out_path.is_dir():
                    raise IsADirectoryError(f"destinazione directory: {out_path}")
                _reject_source_overwrite(out_path, tuple(archive_objects.values()))
                total_bytes += entry.length

            self._total_bytes = total_bytes
            self._total_files = len(self.entries)
            self._progress_started = time.perf_counter()
            self._last_progress_emit = 0.0
            self._processed_bytes = 0
            self._processed_files = 0

            batches = self._build_batches(grouped, archive_objects)
            workers = min(self._recommended_workers(), max(1, len(batches)))
            self.message.emit(
                T(
                    "Modalita DATABASE | {files:,} file | {gib:.2f} GiB | {workers} thread | {batches} batch | letture offset-ordinate",
                    files=len(self.entries),
                    gib=total_bytes / (1024 ** 3),
                    workers=workers,
                    batches=len(batches),
                )
            )
            self._emit_progress(force=True, label=T("Avvio estrazione database"))

            ok = 0
            failed = 0
            error_logs: list[str] = []
            archives_used: set[Path] = set(archive_objects.values())

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                future_map = {
                    executor.submit(
                        self._extract_batch,
                        batch,
                        root,
                        archive_sizes[os.path.normcase(os.path.abspath(batch[0].source_archive))],
                    ): batch
                    for batch in batches
                }

                for future in concurrent.futures.as_completed(future_map):
                    batch = future_map[future]
                    try:
                        batch_ok, batch_failed, batch_errors = future.result()
                        ok += batch_ok
                        failed += batch_failed
                        error_logs.extend(batch_errors)
                    except Exception as exc:
                        failed += len(batch)
                        archive_name = batch[0].source_archive.name if batch and batch[0].source_archive else "?"
                        error_logs.append(f"[{archive_name}] batch error: {exc}")
                        self.message.emit(T("[ERROR] {archive}: batch fallito: {error}", archive=archive_name, error=exc))

            self._emit_progress(force=True, label=T("Estrazione database completata"))

            if error_logs:
                error_path = _secure_output_path(root, "errors.log", create_parents=False)
                _reject_source_overwrite(error_path, tuple(archives_used))
                _atomic_text_replace(error_path, "\n".join(error_logs) + "\n", root)
                self.message.emit(
                    T("[WARN] Salvati {count:,} errori in {path}", count=len(error_logs), path=error_path.name)
                )

            moved = False
            if failed == 0 and self.move_archives and archives_used:
                known_current = {a.stem.lower() for a in archives_used}
                parent = next(iter(archives_used)).parent.parent if archives_used else None
                if parent is not None:
                    parent_present = [
                        stem for stem in KNOWN_ARC_STEMS
                        if stem not in known_current and (parent / f"{stem}.arc").is_file()
                    ]
                    if parent_present:
                        self.message.emit(
                            T(
                                "ARC conosciuti gia presenti nella cartella superiore (NON verranno spostati): {files}",
                                files=", ".join(stem + ".arc" for stem in parent_present),
                            )
                        )
                self._move_archives_to_parent(archives_used, self.message.emit)
                moved = True

            elapsed = time.perf_counter() - start_time
            mib_per_sec = total_bytes / (1024 * 1024) / max(0.001, elapsed)
            summary = T(
                "Completato in {elapsed:.2f}s | {gib:.2f} GiB | {speed:.0f} MiB/s | {ok:,} estratti, {failed:,} falliti.",
                elapsed=elapsed,
                gib=total_bytes / (1024 ** 3),
                speed=mib_per_sec,
                ok=ok,
                failed=failed,
            )
            if moved:
                summary += " " + T("ARC spostati nella cartella superiore.")
            self.finished.emit(failed == 0, summary)
        except Exception as exc:
            self.finished.emit(False, T("Errore database: {error}", error=exc))


class ArcSlowWorker(BaseWorker):
    def __init__(self, archive_paths: list[Path], output_dir: Path, verify_crc: bool, workers: int | None, move_archives: bool = False):
        super().__init__()
        self.archive_paths = list(archive_paths)
        self.output_dir = output_dir
        self.verify_crc = verify_crc
        self.workers = workers
        self.move_archives = move_archives

    @staticmethod
    def _move_archives_to_parent(archives: list[Path], message):
        for archive in sorted(archives, key=lambda p: str(p).lower()):
            destination = archive.parent.parent / archive.name
            if destination.exists():
                raise FileExistsError(f"destinazione gia esistente: {destination}")
            shutil.move(str(archive), str(destination))
            message(T("Spostato {name} in {dest}", name=archive.name, dest=destination))

    def _extract_single_file(self, task):
        archive_path, entry, root = task
        index = entry["index"]
        offset = entry["offset"]
        size = entry["size"]
        stored_crc = entry["crc32"]
        rel_name = entry["rel_name"]

        try:
            out_path = _secure_output_path(root, rel_name, create_parents=True)
            if out_path.is_dir():
                raise IsADirectoryError(f"destinazione gia presente come directory: {out_path}")

            with archive_path.open("rb") as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    if self.verify_crc:
                        calc_crc = arc_crc32(mm, offset, size)
                        if calc_crc != stored_crc:
                            return index, False, (
                                f"CRC mismatch: expected {stored_crc:08X}, got {calc_crc:08X}"
                            )

                    temp_path = None
                    try:
                        with tempfile.NamedTemporaryFile(
                            mode="wb",
                            prefix=".extract-",
                            suffix=".tmp",
                            dir=str(out_path.parent),
                            delete=False,
                        ) as out_f:
                            temp_path = Path(out_f.name)
                            pos = offset
                            remaining = size
                            while remaining:
                                chunk_size = min(remaining, 16 * 1024 * 1024)
                                out_f.write(mm[pos:pos + chunk_size])
                                pos += chunk_size
                                remaining -= chunk_size
                            out_f.flush()
                            os.fsync(out_f.fileno())

                        if out_path.exists() and _is_reparse_point(out_path):
                            raise RuntimeError(
                                f"destinazione reparse point/symlink: {out_path}"
                            )
                        _reject_source_overwrite(out_path, (archive_path,))
                        os.replace(str(temp_path), str(out_path))
                        temp_path = None
                    finally:
                        if temp_path is not None:
                            try:
                                temp_path.unlink(missing_ok=True)
                            except OSError:
                                pass

            return index, True, None
        except Exception as exc:
            return index, False, str(exc)

    @QtCore.pyqtSlot()
    def run(self):
        start_time = time.perf_counter()
        try:
            root = _prepare_output_root(self.output_dir, create=True)
            task_data = []
            filelist_lines = ["archive\tindex\toffset\tsize\tcrc32\tpath"]

            for archive_index, archive_path in enumerate(self.archive_paths, start=1):
                file_size = archive_path.stat().st_size
                self.message.emit(
                    T("Modalita ARC lenta | {index}/{total} | {archive} | {size:.2f} MB", index=archive_index, total=len(self.archive_paths), archive=archive_path.name, size=file_size / (1024 * 1024))
                )
                with archive_path.open("rb") as f, mmap.mmap(
                    f.fileno(), 0, access=mmap.ACCESS_READ
                ) as mm:
                    if len(mm) < 8:
                        raise ParseError(f"{archive_path.name}: file piu piccolo dell'header ARC")
                    if mm[:4] != MAGIC:
                        raise ParseError(f"{archive_path.name}: bad magic: {mm[:4]!r}")

                    header_size = struct.unpack_from("<I", mm, 4)[0]
                    header_end = 8 + header_size
                    if header_end > len(mm):
                        raise ParseError(f"{archive_path.name}: header oltre EOF")

                    header = parse_header(mm[8:header_end])
                    entries = header["entries"]
                    validate_entries(entries, len(mm))

                    try:
                        names = build_name_map(
                            header["name_index"], header["leaf_index"]
                        )
                    except Exception as exc:
                        self.message.emit(
                            T("[WARN] {archive}: errore parsing albero: {error}; uso entry ID", archive=archive_path.name, error=repr(exc))
                        )
                        names = {}

                    for entry in entries:
                        index = entry["index"]
                        rel_name = (
                            sanitize_arc_path(names[index])
                            if index in names else None
                        )
                        if not rel_name:
                            rel_name = f"_unnamed/entry_{index:05d}.bin"
                        entry["rel_name"] = rel_name
                        filelist_lines.append(
                            f"{archive_path.name}\t{index}\t{entry['offset']}\t{entry['size']}\t{entry['crc32']}\t{rel_name}"
                        )
                        task_data.append((archive_path, entry, root))

            filelist_path = _secure_output_path(root, "filelist.txt", create_parents=False)
            error_log_path = _secure_output_path(root, "errors.log", create_parents=False)
            _reject_source_overwrite(filelist_path, self.archive_paths)
            _reject_source_overwrite(error_log_path, self.archive_paths)
            self._atomic_text_replace(filelist_path, "\n".join(filelist_lines) + "\n", root)

            total_files = len(task_data)
            self.progress.emit(0, max(1, total_files), T("Preparazione estrazione: 0/{count:,}", count=total_files))
            max_workers = self.workers if self.workers and self.workers > 0 else None
            self.message.emit(
                T("Estrazione di {files:,} file con {workers} thread...", files=total_files, workers=max_workers or T("automatici"))
            )

            ok = 0
            fail = 0
            error_logs = []

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(self._extract_single_file, task) for task in task_data]
                completed = 0
                for future in concurrent.futures.as_completed(futures):
                    completed += 1
                    idx, success, err_msg = future.result()
                    if success:
                        ok += 1
                    else:
                        fail += 1
                        error_logs.append(f"[{idx}] {err_msg}")

                    self.progress.emit(
                        completed,
                        total_files,
                        f"{completed:,}/{total_files:,}",
                    )

            if error_logs:
                self._atomic_text_replace(
                    error_log_path,
                    "\n".join(error_logs) + "\n",
                    root,
                )
                self.message.emit(
                    T("[WARN] Salvati {count:,} errori in {path}", count=len(error_logs), path=error_log_path.name)
                )

            moved = False
            if fail == 0 and self.move_archives and self.archive_paths:
                known_current = {a.stem.lower() for a in self.archive_paths}
                if self.archive_paths:
                    parent = self.archive_paths[0].parent.parent
                    parent_present = [
                        stem for stem in KNOWN_ARC_STEMS
                        if stem not in known_current and (parent / f"{stem}.arc").is_file()
                    ]
                    if parent_present:
                        self.message.emit(
                            T(
                                "ARC conosciuti gia presenti nella cartella superiore (NON verranno spostati): {files}",
                                files=", ".join(stem + ".arc" for stem in parent_present),
                            )
                        )
                self._move_archives_to_parent(self.archive_paths, self.message.emit)
                moved = True

            elapsed = time.perf_counter() - start_time
            summary = T(
                "Completato in {elapsed:.2f}s | OK: {ok:,} | Falliti: {fail:,}",
                elapsed=elapsed, ok=ok, fail=fail,
            )
            if moved:
                summary += " " + T("ARC spostati nella cartella superiore.")
            self.finished.emit(fail == 0, summary)
        except Exception as exc:
            self.finished.emit(False, T("Errore ARC: {error}", error=exc))

    @staticmethod
    def _atomic_text_replace(path: Path, text: str, root: Path):
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="\n",
                prefix=".gui-",
                suffix=".tmp",
                dir=str(root),
                delete=False,
            ) as f:
                tmp = Path(f.name)
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            if path.exists() and _is_reparse_point(path):
                raise RuntimeError(f"destinazione reparse point/symlink: {path}")
            os.replace(str(tmp), str(path))
            tmp = None
        finally:
            if tmp is not None:
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:
                    pass

# ============================================================================
# GUI TREE HELPERS
# ============================================================================


class TreeItem(QtWidgets.QTreeWidgetItem):
    def __init__(self, text: str, item_type: str, payload=None):
        super().__init__([text])
        self.item_type = item_type
        self.payload = payload
        self.setFlags(
            self.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable
        )
        self.setCheckState(0, QtCore.Qt.CheckState.Unchecked)


# ============================================================================
# MAIN WINDOW
# ============================================================================


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(T("ARC Extractor GUI"))
        self.resize(1200, 800)

        self.current_sections: list[DatabaseSection] = []
        self.current_root_entries: list[DatabaseEntry] = []
        self.current_databases: dict[str, Path] = {}
        self.current_archive: Path | None = None
        self.current_archives: list[Path] = []
        self.current_arc_sha256: str = ""
        self.selection_mode: str = "none"  # none / single / all / translation / relevant
        self.current_document = DatabaseDocument()
        self.custom_database_path: Path | None = None

        self.worker_thread: QtCore.QThread | None = None
        self.worker: BaseWorker | None = None
        self.sha_thread: QtCore.QThread | None = None
        self.sha_worker: Sha256Worker | None = None
        self.sha_cache: dict[str, tuple[int, int, str]] = {}

        self._tree_updating = False
        self._selected_count = 0
        self._total_entries = 0
        self._sha_verifying = False
        self._verification_generation = 0

        self._tree_state_timer = QtCore.QTimer(self)
        self._tree_state_timer.setSingleShot(True)
        self._tree_state_timer.timeout.connect(self._refresh_tree_state_controls)

        self.force_slow = False
        self._database_candidates = self._discover_database_files()

        self._build_ui()

        self.statusBar().showMessage(T("Database disponibili: {count:,}", count=len(self._database_candidates)))
        self.info_label.setText(
            "Seleziona la cartella degli ARC. Per un singolo ARC, se il suo SHA256 "
            "non e registrato, verra usata automaticamente l'estrazione ARC lenta. "
            "Le modalita multiple richiedono invece tutti i database autorizzati."
        )

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        layout = QtWidgets.QVBoxLayout(central)

        row = QtWidgets.QHBoxLayout()
        row.addWidget(QtWidgets.QLabel(T("Cartella ARC:")))
        self.arc_dir_edit = QtWidgets.QLineEdit()
        row.addWidget(self.arc_dir_edit, 1)
        self.btn_arc_dir = QtWidgets.QPushButton(T("Scegli..."))
        self.btn_arc_dir.clicked.connect(self.choose_arc_dir)
        row.addWidget(self.btn_arc_dir)
        layout.addLayout(row)

        row = QtWidgets.QHBoxLayout()
        row.addWidget(QtWidgets.QLabel(T("ARC:")))
        self.arc_combo = QtWidgets.QComboBox()
        self.arc_combo.currentIndexChanged.connect(self.on_arc_changed)
        row.addWidget(self.arc_combo, 1)
        self.btn_custom_db = QtWidgets.QPushButton(T("Database personalizzato..."))
        self.btn_custom_db.setToolTip(T("Usa un database scelto manualmente per un singolo ARC, a tuo rischio e pericolo."))
        self.btn_custom_db.clicked.connect(self.choose_custom_database)
        row.addWidget(self.btn_custom_db)
        layout.addLayout(row)

        row = QtWidgets.QHBoxLayout()
        row.addWidget(QtWidgets.QLabel(T("Output:")))
        self.output_edit = QtWidgets.QLineEdit()
        row.addWidget(self.output_edit, 1)
        self.btn_output = QtWidgets.QPushButton(T("Scegli..."))
        self.btn_output.clicked.connect(self.choose_output_dir)
        row.addWidget(self.btn_output)
        layout.addLayout(row)

        self.info_label = QtWidgets.QLabel()
        self.info_label.setWordWrap(True)
        layout.addWidget(self.info_label)

        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderLabels([T("Sezioni / File")])
        self.tree.setColumnCount(1)
        self.tree.itemChanged.connect(self.on_item_changed)
        self.tree.setAlternatingRowColors(True)
        layout.addWidget(self.tree, 1)

        row = QtWidgets.QHBoxLayout()
        self.btn_select_all = QtWidgets.QPushButton(T("Seleziona tutto"))
        self.btn_clear_all = QtWidgets.QPushButton(T("Deseleziona tutto"))
        self.btn_expand = QtWidgets.QPushButton(T("Espandi tutto"))
        self.btn_collapse = QtWidgets.QPushButton(T("Comprimi tutto"))
        self.btn_extract = QtWidgets.QPushButton(T("Estrai selezionati"))

        self.force_slow_checkbox = QtWidgets.QCheckBox(
            T("Forza estrazione lenta (senza database)")
        )
        self.force_slow_checkbox.setToolTip(
            T("Ignora i database caricati e usa il parser ARC completo lento su tutti gli ARC della selezione corrente.")
        )
        self.force_slow_checkbox.setEnabled(False)
        self.force_slow_checkbox.stateChanged.connect(self._on_force_slow_changed)

        self.move_arcs_checkbox = QtWidgets.QCheckBox(T("Sposta gli ARC nella cartella superiore dopo l'estrazione"))
        self.move_arcs_checkbox.setToolTip(T("Al termine di un'estrazione completata senza errori, sposta gli ARC sorgente nella cartella padre (..)."))
        self.move_arcs_checkbox.setChecked(False)

        self.btn_select_all.clicked.connect(
            lambda: self.set_all(QtCore.Qt.CheckState.Checked)
        )
        self.btn_clear_all.clicked.connect(
            lambda: self.set_all(QtCore.Qt.CheckState.Unchecked)
        )
        self.btn_expand.clicked.connect(self.expand_all)
        self.btn_collapse.clicked.connect(self.collapse_all)
        self.tree.itemExpanded.connect(self._schedule_tree_state_refresh)
        self.tree.itemCollapsed.connect(self._schedule_tree_state_refresh)
        self.btn_extract.clicked.connect(self.extract_current_mode)

        for widget in (
            self.btn_select_all,
            self.btn_clear_all,
            self.btn_expand,
            self.btn_collapse,
            self.btn_extract,
        ):
            row.addWidget(widget)
        layout.addWidget(self.force_slow_checkbox)
        layout.addWidget(self.move_arcs_checkbox)
        layout.addLayout(row)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFormat(T("%p%"))
        layout.addWidget(self.progress)

        self.selection_label = QtWidgets.QLabel(T("Selezionati: 0"))
        layout.addWidget(self.selection_label)

        self.log = QtWidgets.QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(3000)
        layout.addWidget(self.log, 1)

        self._update_mode_controls()

    def _all_sections_expanded(self) -> bool:
        has_section = False
        for i in range(self.tree.topLevelItemCount()):
            for current in self._iter_subtree_nodes(self.tree.topLevelItem(i)):
                if current.item_type != "section":
                    continue
                has_section = True
                if not current.isExpanded():
                    return False
        return has_section

    def _all_sections_collapsed(self) -> bool:
        has_section = False
        for i in range(self.tree.topLevelItemCount()):
            for current in self._iter_subtree_nodes(self.tree.topLevelItem(i)):
                if current.item_type != "section":
                    continue
                has_section = True
                if current.isExpanded():
                    return False
        return has_section

    def _schedule_tree_state_refresh(self, *_args):
        if self._tree_updating:
            return
        self._tree_state_timer.start(75)

    def _refresh_tree_state_controls(self):
        self._update_mode_controls()

    def expand_all(self):
        self._tree_updating = True
        self.tree.blockSignals(True)
        self.tree.setUpdatesEnabled(False)
        try:
            self.tree.expandAll()
        finally:
            self.tree.setUpdatesEnabled(True)
            self.tree.blockSignals(False)
            self._tree_updating = False
        self.tree.viewport().update()
        self._update_mode_controls()

    def collapse_all(self):
        self._tree_updating = True
        self.tree.blockSignals(True)
        self.tree.setUpdatesEnabled(False)
        try:
            self.tree.collapseAll()
        finally:
            self.tree.setUpdatesEnabled(True)
            self.tree.blockSignals(False)
            self._tree_updating = False
        self.tree.viewport().update()
        self._update_mode_controls()

    def _on_force_slow_changed(self, state):
        # Il segnale stateChanged di QCheckBox arriva come intero. Usiamo
        # esplicitamente il valore dell'enum Qt per evitare ambiguita tra
        # int e Qt.CheckState. Questo stato e la fonte di verita della
        # modalita lenta: _update_mode_controls non lo riscrive piu.
        self.force_slow = int(state) == QtCore.Qt.CheckState.Checked.value

        if self.force_slow:
            # La modalita ARC lenta ignora completamente la selezione del
            # database: tutti i file visibili nella treeview vengono marcati
            # come selezionati e la tree viene subito resa non modificabile.
            self._force_select_all_tree()

        self._update_mode_controls()

    def _force_select_all_tree(self):
        self._tree_updating = True
        self.tree.blockSignals(True)
        self.tree.setUpdatesEnabled(False)
        try:
            for i in range(self.tree.topLevelItemCount()):
                self._set_subtree_state(
                    self.tree.topLevelItem(i),
                    QtCore.Qt.CheckState.Checked,
                )
            self._sync_selection_count_from_tree()
        finally:
            self.tree.setUpdatesEnabled(True)
            self.tree.blockSignals(False)
            self._tree_updating = False

        self.tree.viewport().update()
        self._update_selection_counter()

    def _count_all_entry_nodes(self) -> int:
        total = 0
        for i in range(self.tree.topLevelItemCount()):
            total += self._count_entry_nodes_in_subtree(self.tree.topLevelItem(i))
        return total

    def _sync_selection_count_from_tree(self) -> int:
        """Ricalcola il numero di file selezionati direttamente dalla treeview."""
        count = 0
        for item in self._iter_entry_items():
            if item.checkState(0) == QtCore.Qt.CheckState.Checked:
                count += 1
        self._selected_count = count
        return count

    def _tree_has_sections(self) -> bool:
        for i in range(self.tree.topLevelItemCount()):
            for current in self._iter_subtree_nodes(self.tree.topLevelItem(i)):
                if current.item_type == "section":
                    return True
        return False

    def _update_mode_controls(self):
        has_archive = bool(self.current_archives)
        has_database = bool(self.current_databases) and self._total_entries > 0
        extracting = self.worker_thread is not None and self.worker_thread.isRunning()
        verifying = bool(self._sha_verifying)
        all_selected = has_database and self._selected_count == self._total_entries
        tree_locked = extracting or verifying or self.force_slow

        # Non riscrivere setChecked() qui: _update_mode_controls viene
        # richiamato anche durante la gestione del click del checkbox e
        # sovrascrivere lo stato in quel punto puo costringere l'utente a
        # fare un secondo click. Lo stato viene aggiornato esclusivamente
        # da _on_force_slow_changed e dai reset espliciti della modalita.
        self.force_slow_checkbox.setEnabled(
            has_database and not extracting and not verifying
        )

        self.btn_custom_db.setEnabled(
            self.selection_mode == "single" and has_archive and not extracting and not verifying
        )
        self.tree.setEnabled(not tree_locked)
        selection_enabled = has_database and not self.force_slow and not extracting and not verifying
        self.btn_select_all.setEnabled(selection_enabled and not all_selected)
        self.btn_clear_all.setEnabled(selection_enabled and self._selected_count > 0)

        has_tree = self.tree.topLevelItemCount() > 0
        has_sections = self._tree_has_sections()
        self.btn_expand.setEnabled(
            has_tree and has_sections and not tree_locked and not self._all_sections_expanded()
        )
        self.btn_collapse.setEnabled(
            has_tree and has_sections and not tree_locked and not self._all_sections_collapsed()
        )

        self.move_arcs_checkbox.setEnabled(
            has_archive and not extracting and not verifying and
            (self.force_slow or not has_database or all_selected)
        )

        multi_arc_mode = self.selection_mode in {
            "preset_all",
            "preset_translation",
            "preset_relevant",
        } and len(self.current_archives) > 1

        if not has_database or self.force_slow:
            self.btn_extract.setText(
                T("Estrai ARC completi") if multi_arc_mode else T("Estrai ARC completo")
            )
            can_extract = has_archive and not extracting and not verifying
        else:
            if all_selected:
                self.btn_extract.setText(
                    T("Estrai ARC completi") if multi_arc_mode else T("Estrai ARC completo")
                )
            else:
                self.btn_extract.setText(T("Estrai selezionati"))
            can_extract = has_archive and self._selected_count > 0 and not extracting and not verifying
        self.btn_extract.setEnabled(can_extract)

    # ------------------------------------------------------------------
    # DIRECTORIES / DISCOVERY
    # ------------------------------------------------------------------

    @staticmethod
    def _resource_roots() -> list[Path]:
        roots: list[Path] = []

        # Database/resource priority when running as a PyInstaller EXE:
        #   1. external files next to the EXE
        #   2. resources embedded in the EXE and extracted to _MEIPASS
        #
        # When running the .py directly, BASE_DIR is used.
        if getattr(sys, "frozen", False):
            roots.append(Path(sys.executable).resolve().parent)

            meipass = getattr(sys, "_MEIPASS", None)
            if meipass:
                roots.append(Path(meipass))
        else:
            roots.append(BASE_DIR)

        unique: list[Path] = []
        seen: set[str] = set()
        for root in roots:
            key = os.path.normcase(os.path.abspath(root))
            if key not in seen and root.is_dir():
                seen.add(key)
                unique.append(root)
        return unique

    def _discover_database_files(self) -> list[Path]:
        found: list[Path] = []
        seen: set[str] = set()

        # Do NOT sort the final list globally: _resource_roots() is ordered
        # intentionally so that an external database next to the EXE has
        # priority over the embedded copy with the same filename.
        for root in self._resource_roots():
            try:
                candidates = root.rglob("*.database")
            except OSError:
                continue

            for path in candidates:
                if not path.is_file():
                    continue

                key = os.path.normcase(os.path.abspath(path))
                if key in seen:
                    continue

                seen.add(key)
                found.append(path)

        return found

    def choose_arc_dir(self):
        current = self.arc_dir_edit.text().strip() or str(BASE_DIR)
        directory = QtWidgets.QFileDialog.getExistingDirectory(
            self, T("Seleziona cartella contenente gli ARC"), current
        )
        if not directory:
            return
        self.arc_dir_edit.setText(directory)
        self.output_edit.setText(directory)
        self.scan_arc_dir()

    def choose_output_dir(self):
        current = self.output_edit.text().strip() or self.arc_dir_edit.text().strip() or str(BASE_DIR)
        directory = QtWidgets.QFileDialog.getExistingDirectory(
            self, T("Seleziona cartella di output"), current
        )
        if directory:
            self.output_edit.setText(directory)

    def scan_arc_dir(self):
        directory = Path(self.arc_dir_edit.text().strip())
        if not directory.is_dir():
            QtWidgets.QMessageBox.warning(
                self, T("Cartella ARC"), T("Seleziona una cartella valida contenente i file .arc.")
            )
            return

        arcs = sorted(
            [p for p in directory.iterdir() if p.is_file() and p.suffix.lower() == ".arc"],
            key=lambda p: p.name.lower(),
        )

        self._cancel_sha_verification()
        self.current_archive = None
        self.current_archives = []
        self._reset_database_mode()
        self.selection_mode = "none"

        present_by_stem = {p.stem.lower(): p for p in arcs}
        known_present = [stem for stem in KNOWN_ARC_STEMS if stem in present_by_stem]
        known_missing = [stem for stem in KNOWN_ARC_STEMS if stem not in present_by_stem]

        parent_present: list[str] = []
        parent = directory.parent
        for stem in known_missing:
            candidate = parent / f"{stem}.arc"
            if candidate.is_file():
                parent_present.append(stem)

        self.arc_combo.blockSignals(True)
        try:
            self.arc_combo.clear()
            self.arc_combo.addItem(T("— seleziona un'operazione —"), userData=None)
            if arcs:
                self.arc_combo.addItem(T("Estrai tutti gli ARC"), userData=("preset_all", None))

                translation_ready = all(stem in present_by_stem for stem in TRANSLATION_ARC_STEMS)
                if translation_ready:
                    self.arc_combo.addItem(
                        T("Estrai per traduzione"),
                        userData=("preset_translation", None),
                    )

                relevant_ready = all(stem in present_by_stem for stem in RELEVANT_ARC_STEMS)
                if relevant_ready:
                    self.arc_combo.addItem(
                        T("Estrai rilevanti"),
                        userData=("preset_relevant", None),
                    )

                for arc in arcs:
                    self.arc_combo.addItem(arc.name, userData=("single", str(arc)))
            self.arc_combo.setCurrentIndex(0)
        finally:
            self.arc_combo.blockSignals(False)

        if arcs:
            self.log_message(
                T("Trovati {count:,} ARC in {directory}", count=len(arcs), directory=directory)
            )
            self.log_message(
                T(
                    "ARC conosciuti presenti: {present}",
                    present=", ".join(stem + ".arc" for stem in known_present) if known_present else T("nessuno"),
                )
            )
            if known_missing:
                self.log_message(
                    T(
                        "ARC conosciuti mancanti nella cartella: {missing}",
                        missing=", ".join(stem + ".arc" for stem in known_missing),
                    )
                )
                if parent_present:
                    self.log_message(
                        T(
                            "ARC mancanti trovati nella cartella superiore (NON verranno spostati): {files}",
                            files=", ".join(stem + ".arc" for stem in parent_present),
                        )
                    )
            else:
                self.log_message(T("Tutti gli ARC conosciuti sono presenti nella cartella."))

            if not all(stem in present_by_stem for stem in TRANSLATION_ARC_STEMS):
                missing = [stem for stem in TRANSLATION_ARC_STEMS if stem not in present_by_stem]
                self.log_message(
                    T(
                        "Modalita traduzione non disponibile: mancano nella cartella {files}",
                        files=", ".join(stem + ".arc" for stem in missing),
                    )
                )
            if not all(stem in present_by_stem for stem in RELEVANT_ARC_STEMS):
                missing = [stem for stem in RELEVANT_ARC_STEMS if stem not in present_by_stem]
                self.log_message(
                    T(
                        "Modalita rilevanti non disponibile: mancano nella cartella {files}",
                        files=", ".join(stem + ".arc" for stem in missing),
                    )
                )

            self.info_label.setText(
                T(
                    "Trovati {count:,} ARC. Le modalita multiple sono disponibili solo quando gli ARC richiesti sono presenti.",
                    count=len(arcs),
                )
            )
        else:
            self.tree.clear()
            self.info_label.setText(T("Nessun file .arc trovato."))
            self.log_message(T("Nessun .arc trovato in {directory}", directory=directory))

        self._update_mode_controls()

    @staticmethod
    def _find_named_arc(arcs: list[Path], stem: str) -> Path | None:
        target = stem.lower()
        for arc in arcs:
            if arc.stem.lower() == target:
                return arc
        return None

    def _set_output_default(self):
        if not self.current_archives:
            return
        current = self.output_edit.text().strip()
        arc_dir = str(self.current_archives[0].parent)
        if not current or current == self.arc_dir_edit.text().strip():
            self.output_edit.setText(arc_dir)

    def _reset_database_mode(self):
        self.current_sections = []
        self.current_root_entries = []
        self.current_document = DatabaseDocument()
        self.current_databases = {}
        self.current_arc_sha256 = ""
        self.force_slow = False
        if hasattr(self, "force_slow_checkbox"):
            self.force_slow_checkbox.blockSignals(True)
            self.force_slow_checkbox.setChecked(False)
            self.force_slow_checkbox.blockSignals(False)
        self.current_database = None
        self.custom_database_path = None
        self.tree.clear()
        self._selected_count = 0
        self._total_entries = 0
        self._update_selection_counter()

    def _cancel_sha_verification(self):
        self._verification_generation += 1
        if self.sha_thread is not None:
            self.sha_thread.quit()
            self.sha_thread.wait(1500)
            self.sha_thread = None
            self.sha_worker = None
        self._sha_verifying = False

    def _begin_archive_verification(self, archives: list[Path], mode: str):
        self._cancel_sha_verification()
        self._reset_database_mode()
        self.selection_mode = mode
        self.current_archives = list(archives)
        self.current_archive = archives[0] if len(archives) == 1 else None
        self._sha_verifying = True
        self._pending_cached_shas = {}
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFormat(T("SHA256 0.0%"))
        self.statusBar().showMessage(
            T("SHA256 0.0% | verifica di {count:,} ARC...", count=len(archives))
        )
        self.info_label.setText(
            T("Verifica SHA256 in corso per {count:,} ARC...", count=len(archives))
        )
        self._update_mode_controls()

        to_hash: list[Path] = []
        cached_results: dict[str, str] = {}
        for archive in archives:
            try:
                st = archive.stat()
            except OSError as exc:
                self._handle_verification_failure(
                    T("Impossibile leggere {archive}: {error}", archive=archive.name, error=exc),
                    strict=(mode != "single"),
                )
                return
            key = os.path.normcase(os.path.abspath(archive))
            cached = self.sha_cache.get(key)
            if cached and cached[0] == st.st_size and cached[1] == st.st_mtime_ns:
                cached_results[key] = cached[2]
            else:
                to_hash.append(archive)

        if not to_hash:
            self.log_message(
                T("[SHA256] Nessun nuovo controllo da eseguire: SHA gia in cache per {count:,} ARC.", count=len(cached_results))
            )
            self.progress.setValue(100)
            self.progress.setFormat(T("SHA256 100%"))
            self._apply_archive_verification(cached_results)
            return

        self.log_message(
            T("[SHA256] Avvio controllo SHA-256 per {count:,} ARC...", count=len(to_hash))
        )
        for archive in to_hash:
            self.log_message(T("[SHA256] Controllo: {archive}", archive=archive.name))

        self.sha_worker = Sha256Worker(to_hash)
        self.sha_thread = QtCore.QThread(self)
        self.sha_worker.moveToThread(self.sha_thread)
        self.sha_worker.progress.connect(self.on_sha_progress)
        self.sha_worker.finished.connect(self._on_sha_finished)
        self.sha_worker.finished.connect(self.sha_thread.quit)
        self.sha_thread.finished.connect(self._cleanup_sha_worker)
        self.sha_thread.started.connect(self.sha_worker.run)
        self.sha_thread.start()

        # Keep cached results around while the worker hashes the remaining ARC(s).
        self._pending_cached_shas = cached_results

    @QtCore.pyqtSlot(float, str)
    def on_sha_progress(self, percent: float, text: str):
        if self.sender() is not self.sha_worker:
            return
        percent = max(0.0, min(100.0, float(percent)))
        self.progress.setRange(0, 100)
        self.progress.setValue(int(round(percent)))
        self.progress.setFormat(T("SHA256 {percent:.1f}%", percent=percent))
        self.statusBar().showMessage(text)

    @QtCore.pyqtSlot(object, str)
    def _on_sha_finished(self, results: dict[str, str], error: str):
        if self.sender() is not self.sha_worker:
            return
        if error:
            self._handle_verification_failure(
                T("Errore durante il calcolo SHA256: {error}", error=error),
                strict=(self.selection_mode != "single"),
            )
            return

        merged = dict(getattr(self, "_pending_cached_shas", {}))
        merged.update(results)
        for key, digest in merged.items():
            try:
                st = Path(key).stat()
                self.sha_cache[key] = (st.st_size, st.st_mtime_ns, digest)
            except OSError:
                pass

        self.progress.setValue(100)
        self.progress.setFormat(T("SHA256 100%"))
        self.statusBar().showMessage(
            T("SHA256 100% | verifiche completate: {count:,} ARC", count=len(merged))
        )
        self._apply_archive_verification(merged)

    def _cleanup_sha_worker(self):
        thread = self.sha_thread
        self.sha_thread = None
        self.sha_worker = None
        if thread is not None:
            thread.deleteLater()

    def _handle_verification_failure(self, message: str, strict: bool):
        self._sha_verifying = False
        self.log_message(f"[ERROR] {message}")
        if strict:
            QtWidgets.QMessageBox.warning(
                self,
                "Operazione non disponibile",
                message + "\n\nPer questa operazione multipla tutti gli ARC devono avere un database autorizzato. Seleziona nuovamente un'operazione ARC.",
            )
            self._select_no_operation()
            return
        self.progress.setValue(100 if self.current_archives else 0)
        self.progress.setFormat("SHA256: errore")
        self.info_label.setText(
            f"{message}\nL'estrazione lenta ARC resta disponibile per il singolo ARC."
        )
        self._update_mode_controls()

    def _select_no_operation(self):
        self._cancel_sha_verification()
        self._reset_database_mode()
        self.current_archive = None
        self.current_archives = []
        self.selection_mode = "none"
        self.arc_combo.blockSignals(True)
        try:
            self.arc_combo.setCurrentIndex(0)
        finally:
            self.arc_combo.blockSignals(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFormat(T("0%"))
        self.info_label.setText(T("Operazione annullata: seleziona nuovamente un ARC o una modalita multipla."))
        self._update_mode_controls()

    def _apply_archive_verification(self, digests: dict[str, str]):
        if not self.current_archives:
            self._sha_verifying = False
            return

        strict = self.selection_mode != "single"
        valid_databases: dict[str, Path] = {}
        loaded_documents: list[DatabaseDocument] = []
        failures: list[str] = []

        for archive in self.current_archives:
            key = os.path.normcase(os.path.abspath(archive))
            digest = digests.get(key, "")
            if not digest:
                failures.append(T("{archive}: SHA256 non disponibile", archive=archive.name))
                continue

            db_name = KNOWN_ARC_DATABASES.get(digest.lower())
            if not db_name:
                failures.append(
                    T("{archive}: SHA256 non registrato ({digest})", archive=archive.name, digest=digest)
                )
                continue

            database = self._find_database_resource(db_name)
            if database is None:
                failures.append(
                    T("{archive}: database previsto '{database}' non trovato", archive=archive.name, database=db_name)
                )
                continue

            try:
                document = parse_database_file(database)
            except OSError as exc:
                failures.append(T("{archive}: impossibile leggere {database}: {error}", archive=archive.name, database=database.name, error=exc))
                continue

            total = self._document_entry_count(document)
            if total <= 0:
                failures.append(T("{archive}: database {database} vuoto/non valido", archive=archive.name, database=database.name))
                continue

            self._assign_source_archive(document, archive)
            valid_databases[key] = database
            loaded_documents.append(document)

            self.log_message(
                T("[OK] SHA256 verificato: {archive} {digest} -> {database}", archive=archive.name, digest=digest, database=database.name)
            )

        self._sha_verifying = False

        if failures:
            if strict:
                details = "\n".join(T("• {item}", item=item) for item in failures)
                self.log_message(
                    T("[ERROR] Operazione multipla non disponibile; mancano database autorizzati:\n") +
                    details
                )
                QtWidgets.QMessageBox.warning(
                    self,
                    T("Database mancanti"),
                    T("L'operazione richiesta non e possibile perche uno o piu ARC non hanno un database autorizzato.\n\n")
                    + details
                    + "\n\nRiseleziona l'ARC o l'operazione.",
                )
                self._select_no_operation()
                return

            archive = self.current_archives[0]
            digest = digests.get(os.path.normcase(os.path.abspath(archive)), "")
            self.current_arc_sha256 = digest
            self.current_databases = {}
            self.current_sections = []
            self.tree.clear()
            self._selected_count = 0
            self._total_entries = 0
            self.progress.setValue(100)
            self.progress.setFormat(T("SHA256 100%"))
            self.info_label.setText(
                f"ARC: {archive.name} | SHA256 verificato | database non disponibile. "
                "Modalita ARC lenta."
            )
            self.statusBar().showMessage(
                T("SHA256 verificato | database non disponibile | modalita ARC lenta | {archive}", archive=archive.name)
            )
            self.log_message(
                T("[WARN] {archive}: database non disponibile; verra usata l'estrazione ARC lenta", archive=archive.name)
            )
            self._update_selection_counter()
            self._update_mode_controls()
            return

        self.current_databases = valid_databases
        self.current_document = self._merge_documents(loaded_documents)
        self.current_sections = self.current_document.sections
        self.current_root_entries = self.current_document.root_entries
        self.force_slow = False
        self.populate_tree(self.current_document)
        self._total_entries = self._document_entry_count(self.current_document)
        if self.selection_mode in {"preset_translation", "preset_relevant"}:
            self.set_all(QtCore.Qt.CheckState.Checked)

        db_names = ", ".join(path.name for path in valid_databases.values())
        if strict:
            self.info_label.setText(
                T("Modalita multipla: {arcs:,} ARC | Database: {databases} | File uniti: {files:,} | selezione dai database validati attiva.", arcs=len(self.current_archives), databases=db_names, files=self._total_entries)
            )
            self.statusBar().showMessage(
                T("SHA256 verificati | {arcs:,} ARC | database uniti | {files:,} file", arcs=len(self.current_archives), files=self._total_entries)
            )
        else:
            archive = self.current_archives[0]
            digest = digests.get(os.path.normcase(os.path.abspath(archive)), "")
            self.current_arc_sha256 = digest
            self.current_archive = archive
            self.current_database = next(iter(valid_databases.values())) if valid_databases else None
            db_name = self.current_database.name if self.current_database else "?"
            self.info_label.setText(
                T("ARC: {archive} | SHA256 verificato | Database: {database} | File: {files:,} | modalita selettiva attiva.", archive=archive.name, database=db_name, files=self._total_entries)
            )
            self.statusBar().showMessage(
                T("SHA256 verificato | database: {database} | modalita selettiva | {archive}", database=db_name, archive=archive.name)
            )

        self._update_mode_controls()

    def _assign_source_archive(self, document: DatabaseDocument, archive: Path):
        for entry in document.root_entries:
            entry.source_archive = archive
        def visit(sections: list[DatabaseSection]):
            for section in sections:
                for entry in section.entries:
                    entry.source_archive = archive
                visit(section.children)
        visit(document.sections)

    @staticmethod
    def _merge_documents(documents: list[DatabaseDocument]) -> DatabaseDocument:
        merged = DatabaseDocument()
        root_map: dict[str, DatabaseSection] = {}

        def merge_sections(target_list: list[DatabaseSection], target_map: dict[str, DatabaseSection], incoming: list[DatabaseSection]):
            for source in incoming:
                target = target_map.get(source.name)
                if target is None:
                    target = DatabaseSection(name=source.name)
                    target_list.append(target)
                    target_map[source.name] = target
                target.entries.extend(source.entries)
                child_map = {child.name: child for child in target.children}
                merge_sections(target.children, child_map, source.children)

        for document in documents:
            merged.root_entries.extend(document.root_entries)
            merge_sections(merged.sections, root_map, document.sections)
        return merged

    @staticmethod
    def _document_entry_count(document: DatabaseDocument) -> int:
        return len(document.root_entries) + MainWindow._count_entries(document.sections)

    def _find_database_resource(self, database_name: str) -> Path | None:
        normalized = os.path.normcase(database_name)
        for path in self._database_candidates:
            if os.path.normcase(path.name) == normalized:
                return path
        return None

    def choose_custom_database(self):
        if self.selection_mode != "single" or not self.current_archives or self._sha_verifying:
            return
        archive = self.current_archives[0]
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            T("Seleziona database personalizzato"),
            str(archive.parent),
            T("Database (*.database);;Tutti i file (*.*)"),
        )
        if not path:
            return

        reply = QtWidgets.QMessageBox.warning(
            self,
            T("Database personalizzato"),
            T(
                "Stai per usare un database scelto manualmente per {archive}. "
                "Non verra verificato tramite SHA256. Usalo solo se sai cosa stai facendo.",
                archive=archive.name,
            ),
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
            QtWidgets.QMessageBox.StandardButton.No,
        )
        if reply != QtWidgets.QMessageBox.StandardButton.Yes:
            return

        try:
            document = parse_database_file(Path(path))
        except Exception as exc:
            QtWidgets.QMessageBox.critical(
                self, T("Database"), T("Impossibile leggere il database: {error}", error=exc)
            )
            return

        total = self._document_entry_count(document)
        if total <= 0:
            QtWidgets.QMessageBox.warning(
                self, T("Database"), T("Il database non contiene entry valide.")
            )
            return

        self._cancel_sha_verification()
        self.custom_database_path = Path(path)
        self.current_document = document
        self._assign_source_archive(document, archive)
        self.current_sections = document.sections
        self.current_root_entries = document.root_entries
        self.current_databases = {os.path.normcase(os.path.abspath(archive)): self.custom_database_path}
        self.current_archive = archive
        self.current_arc_sha256 = ""
        self.force_slow = False
        self.populate_tree(document)
        self._total_entries = total
        self.progress.setValue(100)
        self.progress.setFormat(T("Database personalizzato"))
        self.info_label.setText(
            T("ARC: {archive} | Database personalizzato | File: {total:,} | verifica SHA ignorata.", archive=archive.name, total=total)
        )
        self.statusBar().showMessage(T("Database personalizzato caricato | {file_count:,} file", file_count=total))
        self.log_message(T("[WARN] Database personalizzato caricato per {archive}: {database}", archive=archive.name, database=path))
        self._update_mode_controls()

    # ------------------------------------------------------------------
    # ARC SELECTION
    # ------------------------------------------------------------------

    def on_arc_changed(self, _index):
        data = self.arc_combo.currentData()
        if not data:
            self._cancel_sha_verification()
            self.current_archive = None
            self.current_archives = []
            self.selection_mode = "none"
            self._reset_database_mode()
            self._update_mode_controls()
            return

        mode, raw = data
        directory = Path(self.arc_dir_edit.text().strip())
        arcs = [
            p for p in directory.iterdir()
            if p.is_file() and p.suffix.lower() == ".arc"
        ] if directory.is_dir() else []

        if mode == "single":
            archives = [Path(raw)]
        elif mode == "preset_all":
            archives = sorted(arcs, key=lambda p: p.name.lower())
        elif mode == "preset_translation":
            required = TRANSLATION_ARC_STEMS
            missing = [stem for stem in required if self._find_named_arc(arcs, stem) is None]
            if missing:
                parent = directory.parent
                parent_found = [stem for stem in missing if (parent / f"{stem}.arc").is_file()]
                msg = T(
                    "L'operazione non e possibile. Mancano nella cartella: {files}",
                    files=", ".join(name + ".arc" for name in missing),
                )
                if parent_found:
                    msg += "\n\n" + T(
                        "Sono presenti nella cartella superiore e non verranno spostati: {files}",
                        files=", ".join(name + ".arc" for name in parent_found),
                    )
                    self.log_message(
                        T(
                            "ARC mancanti trovati nella cartella superiore (NON verranno spostati): {files}",
                            files=", ".join(name + ".arc" for name in parent_found),
                        )
                    )
                QtWidgets.QMessageBox.warning(self, T("ARC mancanti"), msg)
                self._select_no_operation()
                return
            archives = [self._find_named_arc(arcs, stem) for stem in required]
        elif mode == "preset_relevant":
            required = RELEVANT_ARC_STEMS
            missing = [stem for stem in required if self._find_named_arc(arcs, stem) is None]
            if missing:
                parent = directory.parent
                parent_found = [stem for stem in missing if (parent / f"{stem}.arc").is_file()]
                msg = T(
                    "L'operazione non e possibile. Mancano nella cartella: {files}",
                    files=", ".join(name + ".arc" for name in missing),
                )
                if parent_found:
                    msg += "\n\n" + T(
                        "Sono presenti nella cartella superiore e non verranno spostati: {files}",
                        files=", ".join(name + ".arc" for name in parent_found),
                    )
                    self.log_message(
                        T(
                            "ARC mancanti trovati nella cartella superiore (NON verranno spostati): {files}",
                            files=", ".join(name + ".arc" for name in parent_found),
                        )
                    )
                QtWidgets.QMessageBox.warning(self, T("ARC mancanti"), msg)
                self._select_no_operation()
                return
            archives = [self._find_named_arc(arcs, stem) for stem in required]
        else:
            archives = []

        if not archives:
            QtWidgets.QMessageBox.warning(
                self,
                "ARC",
                "Non sono disponibili gli ARC richiesti per questa operazione.",
            )
            self._select_no_operation()
            return

        self.current_archives = archives
        self.current_archive = archives[0] if len(archives) == 1 else None
        self.selection_mode = mode
        self.move_arcs_checkbox.blockSignals(True)
        self.move_arcs_checkbox.setChecked(mode in {"preset_translation", "preset_relevant"})
        self.move_arcs_checkbox.blockSignals(False)
        self._set_output_default()
        self.log_message(
            T("Selezione: {operation} | ARC coinvolti: {count:,}", operation=self.arc_combo.currentText(), count=len(archives))
        )
        self._begin_archive_verification(archives, mode)

    # ------------------------------------------------------------------
    # TREE
    # ------------------------------------------------------------------

    def populate_tree(self, document: DatabaseDocument):
        self._tree_updating = True
        self.tree.blockSignals(True)
        self.tree.setUpdatesEnabled(False)
        try:
            self.tree.clear()
            # Folders/sections always precede files, regardless of name.
            for section in sorted(document.sections, key=lambda x: x.name.casefold()):
                self._add_section_item(None, section)

            # Raw/orphan database entries live directly at the same tree level,
            # after all sections. There is deliberately no fake "Database" node.
            for entry in sorted(document.root_entries, key=lambda e: Path(e.path.replace('\\', '/')).name.casefold()):
                self._add_entry_item(None, entry)
        finally:
            self.tree.setUpdatesEnabled(True)
            self.tree.blockSignals(False)
            self._tree_updating = False

        self._selected_count = 0
        self._update_selection_counter()
        self.tree.viewport().update()

    def _entry_label(self, entry: DatabaseEntry) -> str:
        filename = Path(entry.path.replace("\\", "/")).name
        if len(self.current_archives) > 1 and entry.source_archive is not None:
            return (
                f"{filename} [{entry.source_archive.name}]    "
                f"[0x{entry.offset:X}, 0x{entry.length:X}]"
            )
        return f"{filename}    [0x{entry.offset:X}, 0x{entry.length:X}]"

    def _add_entry_item(self, parent_item, entry: DatabaseEntry):
        child = TreeItem(self._entry_label(entry), "entry", entry)
        if parent_item is None:
            self.tree.addTopLevelItem(child)
        else:
            parent_item.addChild(child)

    def _add_section_item(self, parent_item, section: DatabaseSection):
        item = TreeItem(section.name, "section", section)
        if parent_item is None:
            self.tree.addTopLevelItem(item)
        else:
            parent_item.addChild(item)

        # Sections first, then files. This ordering is independent of names.
        for child_section in sorted(section.children, key=lambda x: x.name.casefold()):
            self._add_section_item(item, child_section)

        for entry in sorted(
            section.entries,
            key=lambda e: Path(e.path.replace('\\', '/')).name.casefold(),
        ):
            self._add_entry_item(item, entry)

    def on_item_changed(self, item, column):
        if self._tree_updating or column != 0:
            return

        state = item.checkState(0)
        self.tree.blockSignals(True)
        self.tree.setUpdatesEnabled(False)
        try:
            self._set_subtree_state(item, state)
            self._update_ancestors_from(item)
        finally:
            self.tree.setUpdatesEnabled(True)
            self.tree.blockSignals(False)

        # Il conteggio e derivato dalla treeview reale. Non manteniamo piu
        # incrementi/decrementi manuali, che possono diventare incoerenti
        # quando Qt aggiorna anche gli antenati o piu nodi insieme.
        self._sync_selection_count_from_tree()
        self._update_selection_counter()
        self._update_mode_controls()

    @staticmethod
    def _iter_subtree_nodes(item):
        stack = [item]
        while stack:
            current = stack.pop()
            yield current
            for i in range(current.childCount() - 1, -1, -1):
                stack.append(current.child(i))

    def _set_subtree_state(self, item, state):
        for current in self._iter_subtree_nodes(item):
            if current.checkState(0) != state:
                current.setCheckState(0, state)

    def _count_checked_entries_in_subtree(self, item) -> int:
        return sum(
            1 for current in self._iter_subtree_nodes(item)
            if current.item_type == "entry"
            and current.checkState(0) == QtCore.Qt.CheckState.Checked
        )

    def _count_entry_nodes_in_subtree(self, item) -> int:
        return sum(
            1 for current in self._iter_subtree_nodes(item)
            if current.item_type == "entry"
        )

    def _update_ancestors_from(self, item):
        parent = item.parent()
        while parent is not None:
            checked = 0
            unchecked = 0
            for i in range(parent.childCount()):
                state = parent.child(i).checkState(0)
                if state == QtCore.Qt.CheckState.Checked:
                    checked += 1
                elif state == QtCore.Qt.CheckState.Unchecked:
                    unchecked += 1
                else:
                    checked = 1
                    unchecked = 1
                    break

            if unchecked == 0 and checked > 0:
                new_state = QtCore.Qt.CheckState.Checked
            elif checked == 0 and unchecked > 0:
                new_state = QtCore.Qt.CheckState.Unchecked
            else:
                new_state = QtCore.Qt.CheckState.PartiallyChecked

            if parent.checkState(0) != new_state:
                parent.setCheckState(0, new_state)
            parent = parent.parent()

    def set_all(self, state):
        if not self.current_databases:
            return

        self._tree_updating = True
        self.tree.blockSignals(True)
        self.tree.setUpdatesEnabled(False)
        try:
            for i in range(self.tree.topLevelItemCount()):
                self._set_subtree_state(self.tree.topLevelItem(i), state)
        finally:
            self.tree.setUpdatesEnabled(True)
            self.tree.blockSignals(False)
            self._tree_updating = False

        self._sync_selection_count_from_tree()
        self.tree.viewport().update()
        self._update_selection_counter()
        self._update_mode_controls()

    def _iter_entry_items(self):
        for i in range(self.tree.topLevelItemCount()):
            for current in self._iter_subtree_nodes(self.tree.topLevelItem(i)):
                if current.item_type == "entry":
                    yield current

    def _update_selection_counter(self):
        self.selection_label.setText(T("Selezionati: {count:,}", count=self._selected_count))

    @staticmethod
    def _count_entries(sections: list[DatabaseSection]) -> int:
        total = 0
        for section in sections:
            total += len(section.entries)
            total += MainWindow._count_entries(section.children)
        return total

    def _selected_entries(self) -> list[DatabaseEntry]:
        return [
            item.payload for item in self._iter_entry_items()
            if item.checkState(0) == QtCore.Qt.CheckState.Checked
        ]

    # ------------------------------------------------------------------
    # EXTRACTION
    # ------------------------------------------------------------------

    def extract_current_mode(self):
        if not self.current_archives:
            return

        output = Path(self.output_edit.text().strip())
        if not str(output).strip():
            QtWidgets.QMessageBox.warning(self, T("Output"), T("Specifica una cartella di output."))
            return

        if self.current_databases and not self.force_slow:
            entries = self._selected_entries()
            if not entries:
                QtWidgets.QMessageBox.information(self, T("Estrazione"), T("Non hai selezionato alcun file."))
                return

            entries = sorted(
                entries,
                key=lambda e: (str(e.source_archive or "").lower(), e.offset, e.length, e.path.lower()),
            )
            all_selected = len(entries) == self._total_entries
            move_arcs = self.move_arcs_checkbox.isChecked()
            if move_arcs and not all_selected:
                QtWidgets.QMessageBox.warning(
                    self, T("Spostamento ARC"),
                    T("Non posso spostare gli ARC dopo un'estrazione parziale. Seleziona tutto oppure disattiva l'opzione."),
                )
                return
            self.log_message(
                T(
                    "Avvio {mode}: {selected:,}/{total:,} file | {arcs:,} ARC",
                    mode=T("estrazione completa tramite database") if all_selected else T("estrazione selettiva"),
                    selected=len(entries), total=self._total_entries, arcs=len(self.current_archives),
                )
            )
            worker = DatabaseWorker(output, entries, move_archives=move_arcs)
            self._start_worker(worker)
            return

        reason = T("forzata dall'utente") if self.force_slow else T("database non disponibile")
        move_arcs = self.move_arcs_checkbox.isChecked()
        self.log_message(
            T("Avvio estrazione ARC lenta completa ({reason}): {archives}", reason=reason, archives=", ".join(a.name for a in self.current_archives))
        )
        worker = ArcSlowWorker(self.current_archives, output, verify_crc=True, workers=None, move_archives=move_arcs)
        self._start_worker(worker)

    def _start_worker(self, worker: BaseWorker):
        if self.worker_thread is not None:
            QtWidgets.QMessageBox.warning(
                self, T("Estrazione"), T("Un'estrazione e gia in corso.")
            )
            return

        self.worker = worker
        self._refresh_arc_list_after_move = bool(self.move_arcs_checkbox.isChecked())
        self.worker_thread = QtCore.QThread(self)
        self.worker.moveToThread(self.worker_thread)

        self.worker.message.connect(self.log_message)
        self.worker.progress.connect(self.on_progress)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.finished.connect(self.worker_thread.quit)
        self.worker_thread.finished.connect(self._cleanup_worker)

        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFormat(T("0%"))
        self.btn_extract.setEnabled(False)
        self.worker_thread.started.connect(self.worker.run)
        self.worker_thread.start()
        self._update_mode_controls()

    @QtCore.pyqtSlot(float, float, str)
    def on_progress(self, current: float, total: float, text: str):
        percent = (current * 100.0 / total) if total else 100.0
        percent = max(0.0, min(100.0, percent))
        self.progress.setRange(0, 100)
        self.progress.setValue(int(round(percent)))
        self.progress.setFormat(f"{percent:.1f}%")
        self.statusBar().showMessage(text)

    @QtCore.pyqtSlot(bool, str)
    def on_worker_finished(self, success: bool, summary: str):
        self._last_worker_success = bool(success)
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        self.progress.setFormat(T("100%"))
        self.log_message(summary)
        self.statusBar().showMessage(summary)

    def _cleanup_worker(self):
        thread = self.worker_thread
        self.worker_thread = None
        self.worker = None

        if thread is not None:
            thread.deleteLater()

        refresh_arc_list = (
            getattr(self, "_refresh_arc_list_after_move", False)
            and getattr(self, "_last_worker_success", False)
        )
        self._refresh_arc_list_after_move = False
        self._last_worker_success = False

        if refresh_arc_list:
            self.log_message(
                T("ARC spostati: ricostruisco l'elenco degli ARC presenti nella cartella.")
            )
            self.scan_arc_dir()
            # scan_arc_dir() resets the combo to its default placeholder.
            self.statusBar().showMessage(
                T("Elenco ARC aggiornato. Seleziona una nuova operazione.")
            )
        else:
            self._update_mode_controls()

    # ------------------------------------------------------------------
    # LOG / CLOSE
    # ------------------------------------------------------------------

    def log_message(self, text: str):
        timestamp = time.strftime("%H:%M:%S")
        self.log.appendPlainText(f"[{timestamp}] {text}")

    def closeEvent(self, event):
        if self.worker_thread is not None and self.worker_thread.isRunning():
            QtWidgets.QMessageBox.information(
                self,
                T("Estrazione in corso"),
                T("L'estrazione e ancora in corso. Attendi la fine prima di chiudere il programma."),
            )
            event.ignore()
            return

        self._cancel_sha_verification()
        event.accept()


# ============================================================================
# MAIN
# ============================================================================


def main() -> int:
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("ARC Extractor GUI")
    window = MainWindow()
    window.showMaximized()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
