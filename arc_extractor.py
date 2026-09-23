#!/usr/bin/env python3
"""
Unified secure extractor for Windows systems.

The code is primarily designed and validated for Windows 10/11, but it does not
artificially block older Windows versions at runtime.

Two modes:

1) Database mode (when -d/--database is supplied):
       extract_package_unified_secure.py -i game.bin -d files.database -o extracted

2) ARC mode (when no database is supplied):
       extract_package_unified_secure.py game.arc
       extract_package_unified_secure.py -i game.arc

Database mode keeps the original offset/length/path parsing behaviour.
ARC mode keeps the ARC0 parser/trie/CRC/concurrent extraction behaviour.
Security hardening applies to both modes, especially all output paths.
"""

import argparse
import concurrent.futures
import mmap
import os
import re
import stat
import struct
import sys
import tempfile
import time
import zlib
from pathlib import Path, PureWindowsPath

MAGIC = b"ARC0"

_WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
_WINDOWS_FORBIDDEN_CHARS = set('<>:"/\\|?*')


# ---------------------------------------------------------------------------
# Common Windows/output-path security helpers
# ---------------------------------------------------------------------------


def _is_reparse_point(path: Path) -> bool:
    """Detect symlinks/junctions/reparse points without following them."""
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
        raise ValueError(f"componente di percorso non valido: {component!r}")
    if len(component) > 255:
        raise ValueError(f"componente di percorso troppo lungo: {component!r}")
    if component[-1] in {".", " "}:
        raise ValueError("un nome Windows non può terminare con punto o spazio")
    if any(ord(ch) < 32 for ch in component):
        raise ValueError("carattere di controllo nel percorso")
    if any(ch in _WINDOWS_FORBIDDEN_CHARS for ch in component):
        raise ValueError(f"carattere non valido nel percorso Windows: {component!r}")
    # Windows reserves these names even when they have an extension.
    if component.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES:
        raise ValueError(f"nome riservato da Windows: {component!r}")


def _validate_relative_name(fname: str):
    """Return path components for a safe, relative Windows path."""
    raw = fname.strip()
    if not raw:
        raise ValueError("filename vuoto")
    if "\x00" in raw:
        raise ValueError("NUL byte nel filename")

    # Inspect the raw spelling before pathlib normalisation: '..' may not be
    # hidden behind repeated separators or alternate slash styles.
    raw_parts = raw.replace("/", "\\").split("\\")
    if any(p in {".", ".."} for p in raw_parts):
        raise ValueError("'.' e '..' non sono ammessi nei filename")
    if any(p == "" for p in raw_parts):
        raise ValueError("percorso assoluto o separatori duplicati non consentiti")

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
        raise NotADirectoryError(f"la cartella di output non è una directory: {outdir}")

    root = outdir.resolve(strict=False)
    if create:
        if not root.exists() or not root.is_dir():
            raise NotADirectoryError(f"cartella di output non disponibile: {root}")
    if _is_reparse_point(root):
        raise RuntimeError(f"la cartella radice di output è un reparse point/symlink: {root}")
    return root


def _secure_output_path(root: Path, fname: str, create_parents: bool) -> Path:
    parts = _validate_relative_name(fname)

    parent = root
    for part in parts[:-1]:
        parent = parent / part
        if parent.exists():
            if not parent.is_dir():
                raise NotADirectoryError(f"non è una directory: {parent}")
            if _is_reparse_point(parent):
                raise RuntimeError(f"reparse point/symlink non consentito: {parent}")
        elif create_parents:
            # Several ARC extraction threads may create the same directory
            # concurrently; exist_ok avoids a harmless FileExistsError race.
            parent.mkdir(exist_ok=True)
            if not parent.is_dir() or _is_reparse_point(parent):
                raise RuntimeError(f"directory non sicura: {parent}")

    resolved_parent = parent.resolve(strict=False)
    try:
        resolved_parent.relative_to(root)
    except ValueError as exc:
        raise RuntimeError("il percorso di output esce dalla cartella consentita") from exc

    target = parent / parts[-1]
    if target.exists() and _is_reparse_point(target):
        raise RuntimeError(f"destinazione reparse point/symlink non consentita: {target}")
    return target


def _same_file(path_a: Path, path_b: Path) -> bool:
    """Return True when two paths refer to the same existing file."""
    try:
        return os.path.samefile(path_a, path_b)
    except (FileNotFoundError, OSError):
        try:
            return path_a.resolve(strict=False) == path_b.resolve(strict=False)
        except OSError:
            return False


def _reject_source_overwrite(out_path: Path, source_paths) -> None:
    """Prevent extracted output from replacing a source/control file."""
    for source_path in source_paths:
        if source_path is not None and _same_file(out_path, source_path):
            raise RuntimeError(f"destinazione coincide con un file sorgente: {out_path}")


def _write_segment_atomically(
    input_file,
    input_path: Path,
    out_path: Path,
    offset: int,
    length: int,
    protected_paths=(),
):
    """Write to an exclusive temporary file, fsync it, then replace target."""
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
                        f"Unexpected EOF while reading {input_path} at offset {offset}"
                    )
                out_f.write(data)
                remaining -= len(data)

            out_f.flush()
            os.fsync(out_f.fileno())

        # Re-check before replacing in case the destination appeared meanwhile.
        if out_path.exists() and _is_reparse_point(out_path):
            raise RuntimeError(f"destinazione reparse point/symlink non consentita: {out_path}")
        os.replace(str(temp_path), str(out_path))
        temp_path = None
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Database mode -- original logic, hardened paths/write handling
# ---------------------------------------------------------------------------


def parse_number(s: str) -> int:
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s, 10)


def parse_database_line(line: str):
    """Parse offset, length and everything after 'is' as the filename."""
    low = line.lower()
    off_match = re.search(r'offset\s+(0x[0-9a-f]+|\d+)', low)
    len_match = re.search(r'length\s+(0x[0-9a-f]+|\d+)', low)
    is_pos = low.find(' is ')

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
        m = re.search(r'\)\s*(.+)$', line)
        fname = m.group(1).strip() if m else ''

    fname = fname.strip().strip('"').strip("'")
    return (offset, length, fname) if fname else None


def load_database(db_path: Path, verbose=False):
    entries = []
    with db_path.open("r", encoding="utf-8", errors="replace") as dbf:
        for lineno, raw in enumerate(dbf, start=1):
            line = raw.rstrip("\r\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parsed = parse_database_line(line)
            if parsed is None:
                print(f"[WARN] non parseabile linea {lineno}: {line}")
                continue
            entries.append(parsed)
    return entries


def extract_segments(
    input_path: Path,
    entries,
    outdir: Path,
    dry_run=False,
    verbose=False,
    truncate_on_eof=False,
):
    file_size = input_path.stat().st_size
    root = _prepare_output_root(outdir, create=not dry_run)

    with input_path.open("rb") as f:
        for idx, (offset, length, fname) in enumerate(entries, start=1):
            if offset < 0 or length < 0:
                print(
                    f"[WARN] voce {idx}: offset/length non validi: "
                    f"offset={offset} length={length} -> {fname}"
                )
                continue
            if length == 0:
                print(f"[WARN] voce {idx}: length == 0, salto estrazione -> {fname}")
                continue
            if offset >= file_size:
                print(
                    f"[ERROR] voce {idx}: offset {offset} oltre EOF "
                    f"(file size {file_size}), salto -> {fname}"
                )
                continue

            end_pos = offset + length
            if end_pos > file_size:
                if truncate_on_eof:
                    length = file_size - offset
                    print(
                        f"[WARN] voce {idx}: offset+length supera EOF, "
                        f"tronco length a {length} -> {fname}"
                    )
                else:
                    print(
                        f"[ERROR] voce {idx}: offset+length ({end_pos}) supera "
                        f"EOF ({file_size}), salto -> {fname}"
                    )
                    continue

            try:
                out_path = _secure_output_path(root, fname, create_parents=not dry_run)
            except Exception as exc:
                print(
                    f"[ERROR] voce {idx}: percorso di output non consentito "
                    f"({fname!r}): {exc}"
                )
                continue

            if verbose or dry_run:
                print(
                    f"{'DRY ' if dry_run else ''}Extracting: "
                    f"offset=0x{offset:X} length=0x{length:X} -> {out_path}"
                )
            if dry_run:
                continue

            try:
                if out_path.is_dir():
                    raise IsADirectoryError(
                        f"destinazione già presente come directory: {out_path}"
                    )
                _write_segment_atomically(
                    f, input_path, out_path, offset, length,
                    protected_paths=(input_path, db_path),
                )
            except Exception as exc:
                print(f"[ERROR] extracting {fname}: {exc}")


# ---------------------------------------------------------------------------
# ARC mode -- based on the supplied ARC0 extractor, with hardening
# ---------------------------------------------------------------------------


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

    # Consistency check prevents a forged total_bits from indexing outside the
    # supplied bitvector later.
    if total_bits > n1 * 32:
        raise ParseError(
            f"trie total_bits={total_bits} exceeds bitvector capacity {n1 * 32}"
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

    if verbose:
        print(f"  file_count = {file_count}")
        print(f"  bytes remaining for entries = {remaining}")

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
    calibration_log = []

    for gap in candidates:
        reached = _count_reachable(names_bits, gap, cap)
        calibration_log.append((gap, len(reached)))
        if len(reached) > len(best_reached):
            best_gap = gap
            best_reached = reached
        if len(reached) >= expected_nodes:
            break

    if verbose:
        print(f"  [names] expected nodes = {expected_nodes}")
        print(f"  [names] calibration = {calibration_log}")
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
            new_prefix = prefix + bytes([labels[child]]) if 0 <= child <= max_label_idx else prefix
            stack.append((child, new_prefix))

    return result


def sanitize_arc_path(raw_bytes):
    """Keep the original ARC path normalisation, then validate as Windows path."""
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        text = raw_bytes.decode("latin-1")

    text = text.replace("\\", "/").lstrip("/")
    # Same functional behaviour as the supplied extractor: discard empty,
    # '.' and '..' components rather than allowing traversal.
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


def extract_single_file(args_tuple):
    entry, root, verify_crc, mm_file_path, file_size = args_tuple
    index = entry["index"]
    offset = entry["offset"]
    size = entry["size"]
    stored_crc = entry["crc32"]
    rel_name = entry["rel_name"]

    try:
        out_path = _secure_output_path(root, rel_name, create_parents=True)
        if out_path.is_dir():
            raise IsADirectoryError(f"destinazione già presente come directory: {out_path}")

        # Open mmap per thread for thread-safe concurrent reading.
        with open(mm_file_path, "rb") as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                if verify_crc:
                    calc_crc = arc_crc32(mm, offset, size)
                    if calc_crc != stored_crc:
                        return (
                            index,
                            False,
                            f"CRC mismatch: expected {stored_crc:08X}, got {calc_crc:08X}",
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
                            f"destinazione reparse point/symlink non consentita: {out_path}"
                        )
                    _reject_source_overwrite(out_path, (Path(mm_file_path),))
                    os.replace(str(temp_path), str(out_path))
                    temp_path = None
                finally:
                    if temp_path is not None:
                        try:
                            temp_path.unlink(missing_ok=True)
                        except OSError:
                            pass

        return index, True, None
    except Exception as e:
        return index, False, str(e)


def _arc_database_lines(entries):
    """Build a .database ordered strictly by physical archive offset."""
    ordered = sorted(
        entries,
        key=lambda entry: (
            entry["offset"],
            entry["size"],
            entry["index"],
        ),
    )

    return [
        f"offset 0x{entry['offset']:X} "
        f"(length 0x{entry['size']:X}) "
        f"is {entry['rel_name']}"
        for entry in ordered
    ]


def write_arc_database(root: Path, archive_path: Path, entries) -> Path:
    """Write an ARC-derived .database next to/inside the chosen output root."""
    database_name = archive_path.stem + ".database"
    database_path = _secure_output_path(root, database_name, create_parents=False)
    _reject_source_overwrite(database_path, (archive_path,))
    lines = _arc_database_lines(entries)

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=".database-",
            suffix=".tmp",
            dir=str(root),
            delete=False,
        ) as f:
            temp_path = Path(f.name)
            f.write("\n".join(lines))
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())

        if database_path.exists() and _is_reparse_point(database_path):
            raise RuntimeError(
                f"destinazione reparse point/symlink non consentita: {database_path}"
            )
        os.replace(str(temp_path), str(database_path))
        temp_path = None
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass

    return database_path


def process_arc(path, outdir, verify_crc=True, verbose=False, workers=None):
    file_size = os.path.getsize(path)
    print(f"📦 Archive: {path} ({file_size / (1024*1024):.2f} MB)")

    start_time = time.time()

    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        if len(mm) < 8:
            raise ParseError("file is smaller than ARC header")
        if mm[:4] != MAGIC:
            raise ParseError(f"bad magic: {mm[:4]!r}")

        header_size = struct.unpack_from("<I", mm, 4)[0]
        header_end = 8 + header_size
        if header_end > len(mm):
            raise ParseError("header runs past EOF")

        header = parse_header(mm[8:header_end], verbose=verbose)
        entries = header["entries"]
        validate_entries(entries, len(mm))

        try:
            names = build_name_map(
                header["name_index"], header["leaf_index"], verbose=verbose
            )
        except Exception as e:
            print(f"⚠️ Tree parsing error: {e!r}\n🔄 Falling back to entry IDs.")
            names = {}

        root = _prepare_output_root(Path(outdir), create=True)
        filelist_path = _secure_output_path(root, "filelist.txt", create_parents=False)
        error_log_path = _secure_output_path(root, "errors.log", create_parents=False)
        _reject_source_overwrite(filelist_path, (path,))
        _reject_source_overwrite(error_log_path, (path,))
        task_data = []
        filelist_lines = ["index\toffset\tsize\tcrc32\tpath"]

        for entry in entries:
            index = entry["index"]
            rel_name = sanitize_arc_path(names[index]) if index in names else None
            if not rel_name:
                rel_name = f"_unnamed/entry_{index:05d}.bin"
            entry["rel_name"] = rel_name
            filelist_lines.append(
                f"{index}\t{entry['offset']}\t{entry['size']}\t"
                f"{entry['crc32']}\t{rel_name}"
            )
            task_data.append((entry, root, verify_crc, path, file_size))

    # Manifest is generated after parsing, before extraction, preserving the
    # original ARC workflow.
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix=".filelist-",
        suffix=".tmp",
        dir=str(root),
        delete=False,
    ) as f:
        manifest_tmp = Path(f.name)
        f.write("\n".join(filelist_lines))
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(manifest_tmp), str(filelist_path))

    database_path = write_arc_database(root, path, entries)
    print(f"   - Database: {database_path}")

    total_files = len(entries)
    print(f"🚀 Extracting {total_files:,} files using {workers or 'auto'} threads...")

    ok = 0
    fail = 0
    error_logs = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(extract_single_file, task): task[0]["index"]
            for task in task_data
        }

        completed = 0
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            idx, success, err_msg = future.result()
            if success:
                ok += 1
            else:
                fail += 1
                error_logs.append(f"[{idx}] {err_msg}")

            if completed % 100 == 0 or completed == total_files:
                pct = (completed / total_files) * 100 if total_files else 100.0
                elapsed = time.time() - start_time
                speed = completed / elapsed if elapsed > 0 else 0
                sys.stdout.write(
                    f"\rProgress: {completed}/{total_files} ({pct:.1f}%) | "
                    f"Speed: {speed:.1f} files/sec   "
                )
                sys.stdout.flush()

    print()

    if error_logs:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix=".errors-",
            suffix=".tmp",
            dir=str(root),
            delete=False,
        ) as f:
            error_tmp = Path(f.name)
            f.write("\n".join(error_logs))
            f.flush()
            os.fsync(f.fileno())
        os.replace(str(error_tmp), str(error_log_path))
        print(f"⚠️ Saved {len(error_logs)} errors to {error_log_path}")

    elapsed_total = time.time() - start_time
    print(f"\n✨ Done in {elapsed_total:.2f}s!")
    print(f"   - Successfully extracted: {ok:,}")
    print(f"   - Failed: {fail:,}")
    print(f"   - File Manifest: {filelist_path}")


def process_arc_probe(path, verbose=True):
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        if len(mm) < 8 or mm[:4] != MAGIC:
            raise ParseError("Invalid ARC file")
        header_size = struct.unpack_from("<I", mm, 4)[0]
        if 8 + header_size > len(mm):
            raise ParseError("header runs past EOF")
        header = parse_header(mm[8:8 + header_size], verbose=verbose)
        print(
            f"\nfile_count = {header['file_count']}\n"
            f"trailing header bytes = {header['trailing_bytes']}"
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Extractor Windows: .database se -d è specificato, "
            ".arc/ARC0 altrimenti"
        )
    )
    parser.add_argument(
        "input_positional",
        nargs="?",
        help="File di input (.arc oppure binario usato con -d)",
    )
    parser.add_argument(
        "--input", "-i", dest="input_option",
        help="File di input (.arc oppure binario usato con -d)",
    )
    parser.add_argument(
        "--database", "-d", default=None,
        help="File .database; se omesso viene usata la modalità ARC0",
    )
    parser.add_argument(
        "--outdir", "-o", default=None,
        help="Cartella di output (database: '.', ARC: directory del file .arc)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Solo database: mostra cosa verrebbe estratto senza scrivere",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Stampa informazioni dettagliate",
    )
    parser.add_argument(
        "--truncate-on-eof", action="store_true",
        help="Solo database: tronca length quando supera EOF",
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=None,
        help="Solo ARC: numero di thread concorrenti (default: auto)",
    )
    parser.add_argument(
        "--probe", action="store_true",
        help="Solo ARC: analizza i metadati senza estrarre",
    )
    parser.add_argument(
        "--no-crc", action="store_true",
        help="Solo ARC: disabilita la verifica CRC",
    )
    args = parser.parse_args()

    input_name = args.input_option or args.input_positional
    if not input_name:
        parser.error("specificare il file di input con -i/--input oppure come argomento posizionale")

    input_path = Path(input_name)
    database_mode = args.database is not None

    if not input_path.is_file():
        print(f"Errore: file di input non trovato: {input_path}")
        return 1

    if database_mode:
        db_path = Path(args.database)
        outdir = Path(args.outdir if args.outdir is not None else ".")

        if not db_path.is_file():
            print(f"Errore: file database non trovato: {db_path}")
            return 1

        if args.workers is not None or args.probe or args.no_crc:
            print("[WARN] -w/--workers, --probe e --no-crc sono opzioni ARC e vengono ignorate in modalità database.")

        if args.verbose:
            print(f"Modalità: DATABASE")
            print(f"Caricamento database: {db_path}")

        try:
            entries = load_database(db_path, verbose=args.verbose)
        except OSError as exc:
            print(f"Errore: impossibile leggere il database {db_path}: {exc}")
            return 1

        if not entries:
            print("Nessuna voce valida trovata nel database. Esco.")
            return 0

        if args.verbose:
            print(f"Trovate {len(entries)} voci. Output directory: {outdir}")

        try:
            extract_segments(
                input_path,
                entries,
                outdir,
                dry_run=args.dry_run,
                verbose=args.verbose,
                truncate_on_eof=args.truncate_on_eof,
            )
        except (OSError, RuntimeError) as exc:
            print(f"Errore durante l'estrazione: {exc}")
            return 1

        if args.verbose and not args.dry_run:
            print("Estrazione completata.")
        return 0

    # ARC mode: if -o is omitted, extract directly beside the .arc file.
    outdir = Path(args.outdir) if args.outdir is not None else input_path.parent
    if args.workers is not None and args.workers <= 0:
        print("Errore: --workers deve essere > 0")
        return 1
    if args.dry_run or args.truncate_on_eof:
        print("[WARN] --dry-run e --truncate-on-eof sono opzioni database e vengono ignorate in modalità ARC.")

    if args.verbose:
        print("Modalità: ARC0")

    try:
        if args.probe:
            process_arc_probe(input_path, verbose=True)
        else:
            process_arc(
                input_path,
                outdir,
                verify_crc=not args.no_crc,
                verbose=args.verbose,
                workers=args.workers,
            )
    except (OSError, ParseError, RuntimeError) as exc:
        print(f"❌ Parse/extraction error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
