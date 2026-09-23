# V3ARCExtractor

A GUI extractor for the `.arc` / `ARC0` archives used by the **2022 Anniversary Edition of Danganronpa V3 on PC**, distributed through the Microsoft Store / Xbox app.

The project supports two extraction workflows:

* database-assisted selective extraction using external `.database` files
* full extraction directly from the information stored inside the ARC

The main purpose is to make these archives practical to inspect, extract, compare, and use for modding or research.

Usage: `python arc_extractor_gui.py`, or just download the V3ARCExtractor executable file from the Releases page.

Special Thanks to [wheatleynotamoron](https://github.com/wheatleyinspace).

> **AI-assisted development**
>
> Parts of this repository were developed with assistance from generative AI. AI was used during implementation, debugging, diagnostic analysis, and development of supporting tooling. The generated code was reviewed, adapted, and tested against the actual target files and game environment.
>
> This README was also written with the assistance of generative AI.

---

## Overview

Functionally, the `.ARC0` files used by the Microsoft Store version fill a role similar to the `.CPK` archives used by the Steam version: they are containers holding the game's files and directory structure.

Steam does not use ARC0. Its resources are packed into `.CPK` files using the CRI/CriPak format, which is a much more common archive format and had already been extracted with existing tooling years ago.

ARC0 became interesting because the Anniversary Edition uses a different archive implementation, and because part of its directory structure is represented through a compact tree rather than simply being stored as ordinary full paths.

The game can use the extracted files directly when the expected directory structure is present, so the archive is primarily the packaging layer around those resources.

---

# Why ARC0 Needed Its Own Research

Knowing that the ARC contains files is only part of the problem.

Some file names can be found directly in the archive as readable bytes. Others are represented through the archive's internal name/path structure.

The important discovery for this project was that the directory hierarchy appears to be encoded using a **LOUDS-style succinct tree**.

That allows the extractor to reconstruct paths such as:

```text
flash/climax/program/climax_koma/koma_04_03_US.spc
```

rather than merely recovering:

```text
koma_04_03_US.spc
```

This matters because the Microsoft Store and Steam releases do not always place corresponding resources under the same directories.

For example, `.swb` resources are found inside some files under:

```text
game_resident
```

in the Steam version, while the Microsoft Store version directly uses:

```text
sound
```

Knowing the actual path stored by the ARC is therefore important when recreating the game's extracted directory structure.

---

# The `koma_04_03_US.spc` Example

As mentioned before, the Anniversary Edition contains a file named:

```text
koma_04_03_US.spc
```

It is seemingly only used during Chapter 4 and is not present in the Steam version.

The filename itself can sometimes appear as plain text in the ARC and can therefore be found directly with a hex editor such as HxD. Not every ARC filename is available this way, but some are.

The name could then be compared against the existing Steam filelist, where it was not present.

The interesting problem was its **path**.

The correct path is:

```text
flash/climax/program/climax_koma/koma_04_03_US.spc
```

Recovering that directory hierarchy is where the ARC's internal tree representation becomes important.

---

# ARC0 Structure

For the purposes of this project, `ARC0` refers to the archive format used by the **2022 Anniversary Edition PC release of Danganronpa V3**.

The container begins with:

```text
0x00  char[4]   magic = "ARC0"
0x04  uint32    header_size
0x08  ...       header / metadata
...
      raw file data
```

The raw file data begins at:

```text
0x08 + header_size
```

The header contains the information required to recover the archive's name data, file table, and related metadata.

Some of the structures described below are interpretations inferred from the extractor implementation rather than officially documented specifications.

---

# File Table

The ARC contains a file table beginning with a file count:

```text
uint32 file_count
```

followed by `file_count` entries of 20 bytes each.

Each entry is interpreted as:

```text
+0x00  uint64  size
+0x08  uint64  offset
+0x10  uint32  CRC32
```

The offsets refer to positions inside the ARC itself.

The extractor uses this information to locate and extract the actual file data.

---

# Name and Path Storage

The archive does not appear to store every complete path as an ordinary string.

Instead, the source and extractor implementation suggest a structure roughly like:

```text
ARC
├── metadata
├── name/path tree
├── leaf/file mapping
└── raw file data
```

The tree contains the relationships between directories and names, while separate information connects terminal nodes to entries in the file table.

This is what allows the extractor to reconstruct a complete path from the compact representation.

---

# LOUDS

The name tree appears to use a **LOUDS-style** representation.

LOUDS stands for **Level-Order Unary Degree Sequence** and is a succinct way of representing a tree as a bit sequence.

A normal directory tree might look like:

```text
root
├── flash
│   └── climax
│       └── program
│           └── climax_koma
│               └── koma_04_03_US.spc
└── sound
```

A succinct representation stores the tree structure more compactly and uses bit-level navigation operations to recover parent/child relationships.

The extractor therefore has to reconstruct the hierarchy before it can produce the final file paths.

The exact identification and interpretation of this structure are based on what the existing source appears to implement. This README does not treat every detail of that implementation as independently verified documentation of the original engine.

---

# Rank and Select

Succinct tree representations commonly use operations such as:

* `rank`
* `select`
* direct bit access

The extractor implements equivalent operations over the archive's bitvectors.

These operations are used to navigate the tree efficiently and determine relationships between nodes.

The implementation precomputes rank information so that repeated tree traversal does not require scanning the entire bitvector every time.

---

# Name Index

The archive appears to contain a name index before the file table.

The current parser interprets the relevant region approximately as:

```text
name_index_size
name_index
leaf_index_size
leaf_index
file_count
file_entries
```

The name index appears to contain information such as:

* node count
* tree/LOUDS data
* labels
* additional root information

The exact meaning of individual fields is inferred from how the extractor consumes them.

The corresponding parsing logic is implemented in routines such as:

```text
parse_trie_block()
parse_name_index()
```

---

# Leaf Index

The tree establishes the directory/name hierarchy, while the leaf information appears to connect terminal nodes to the actual file table.

Conceptually:

```text
directory tree
      │
      └── file leaf
             │
             └── file-table entry
                    ├── offset
                    └── size
```

This allows a reconstructed path to resolve to the corresponding bytes inside the ARC.

---

# CRC

The file-table CRC is handled by the extractor as a sparse CRC rather than a normal CRC32 over the entire file.

The implementation samples small chunks at regular intervals:

```python
crc = 0

for pos in range(0, size, 0x200000):
    n = min(0x400, size - pos)
    crc = CRC32_CONTINUE(
        crc,
        data[offset + pos : offset + pos + n]
    )
```

This means the calculation processes `0x400` bytes every `0x200000` bytes of file data.

That behavior is part of the format interpretation used by the current extractor.

---

# ARC0 Research and Source Attribution

The current understanding of ARC0 is based in part on the source associated with **`wheatleynotamoron`**.

That source contains an implementation which suggests a reverse-engineered interpretation of:

* the archive header
* the file table
* the name index
* the tree structure
* the leaf mapping
* the CRC behavior

It also references engine functions including:

```text
sub_140850370
sub_140850580
sub_14084F460
sub_14088BEE0
sub_14088BC00
sub_1408878E0
sub_14084C970
```

The exact history of how each structure was figured out is not independently documented here. Consequently, this README describes those parts as **suggested, inferred, or indicated by the source**, rather than presenting a definitive account of the original reverse-engineering process.

The same applies to the full/slow extractor: it is based on the ARC0 interpretation represented in that source.

---

# Full / Slow Extraction

The project includes a full extractor that can operate without an external database.

It uses the archive's own metadata and reconstructed name tree to recover the complete paths of the files stored inside the ARC.

The implementation follows the general process of:

1. parsing the ARC header
2. reading the name index
3. reconstructing the tree
4. resolving labels
5. connecting leaves to file-table entries
6. rebuilding file paths
7. extracting the corresponding byte ranges

Because the tree has to be reconstructed rather than simply read from a ready-made path list, this mode is slower than database-assisted extraction.

The slow extractor is part of the ARC0 work represented by the source associated with `wheatleynotamoron`.

---

# SHA-256 and Version Comparison

SHA-256 comparison was initially useful when comparing equivalent resources between the Steam and Microsoft Store versions.

The two releases can contain the same data under different paths, so hashing allows matching files by content rather than filename or location.

For example, a Steam resource and a Microsoft Store resource may have completely different paths while containing identical bytes. Their SHA-256 hashes can establish that they correspond to the same underlying file.

This is, of course, rendered useless now that we're able to identify the full path for each file... but back in 2022, and until recent discoveries, it was the best option.

SHA-256 is also used by the GUI to identify known ARC builds and select the appropriate external database.

---

# Database Files

The GUI supports external `.database` files containing known ARC entries and section information.

A typical entry looks like:

```text
offset 0x111FA808 (length 0x10220) is flash/climax/climax_page_US.spc
```

Databases can also describe sections:

```text
# flash
# SECTION_START

offset ...
offset ...

# SECTION_END
```

and nested sections:

```text
# wrd_script
# SECTION_START
# Old Revisions
# SECTION_START
```

which represents:

```text
wrd_script
└── Old Revisions
```

A later section such as:

```text
# Latest Revision
# SECTION_START
```

becomes another child of `wrd_script`.

The database is an external convenience/indexing layer. The ARC itself remains the underlying source of the archive's actual file and path information.

---

# Section Naming Rules

An ordinary comment immediately preceding `SECTION_START` can provide the section name.

For example:

```text
# flash
# SECTION_START
```

produces:

```text
flash
```

and:

```text
# flash/adv
# SECTION_START
```

produces:

```text
flash/adv
```

Inline section names are also supported:

```text
# SECTION_START // minigame
```

which produces:

```text
minigame
```

Comments only remain candidates until a real file entry is encountered.

This allows decorative comments such as:

```text
#
# NEW: Anniversary Edition-only file koma_04_03_US.spc
#
offset ...
```

to remain ordinary comments rather than becoming section names later in the file.

Blank lines are formatting only and have no semantic meaning.

---

# GUI Extraction Modes

## Database Extraction

When a matching database is available, the GUI can:

* display the known hierarchy
* select individual files
* select complete sections
* expand or collapse sections
* extract only the selected files

This mode avoids rebuilding the archive's path tree for every extraction.

## Full Extraction

The **Force slow extraction (without database)** option performs extraction directly from the ARC.

It is intended for cases where no suitable database exists or when the archive's own structure needs to be inspected directly.

---

# Known ARC Builds

The project can identify known ARC files by SHA-256 and associate them with their corresponding databases.

Current database variants include:

```text
partition_data_win
partition_data_win_us
partition_resident_win
partition_data_win_zh
partition_data_win_jp
```

This prevents a database intended for one archive/build from being applied to another.

---

# Path Safety

Extracted paths are normalized before being written to disk.

The extractor handles:

* path separator normalization
* UTF-8 decoding with fallback behavior
* `.` components
* `..` components
* path traversal attempts

The goal is to reproduce the directory structure represented by the archive while keeping extraction inside the selected output directory.

---

# Performance

The full extractor uses memory-mapped access where appropriate and performs extraction concurrently.

This is useful for the large archives used by the game.

Database-assisted extraction is generally faster because the paths are already known and can be used directly.

---

# Project Scope

This project focuses on the `ARC0` archives used by the **2022 Anniversary Edition of Danganronpa V3 on PC through the Microsoft Store / Xbox app**.

The Switch release uses a different engine/resource setup and is outside the scope of this format.

The Steam release is primarily useful as a comparison point:

```text
Steam
└── CRI/CriPak .CPK archives

Microsoft Store Anniversary Edition
└── ARC0 .arc archives
```

The two formats are different, but they serve a broadly similar packaging role in their respective PC versions.

---

# Credits

The ARC0 research and the full/slow extraction implementation are associated with the source attributed to **`wheatleynotamoron`**.

The exact provenance of individual reverse-engineering steps is not independently established here, so technical conclusions derived from that source are described as inferred or suggested rather than as definitive historical claims.

---

# License

This project is released under the **ISC License**.

---

# Legal

This project is intended for research, preservation, interoperability, and modding purposes.

Do not redistribute copyrighted game assets unless you have the necessary rights or permission.

The repository does not include the game's proprietary resources.

     “DANGANRONPA” is a registered trademark of Spike Chunsoft Co., Ltd., Too Kyo Games, LLC and/or NIS America Inc.
     We are not in any way affiliated or associated with them.