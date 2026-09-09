# core/parser.py  ─  Cyber Data Engine v1.0.0
# Universal file parser + semantic chunker + quality gate
# SECURITY: reads files as static data only — never executes content
"""
parser.py  —  Universal File Parser & Semantic Chunker

Purpose:
    Read any uploaded file type and produce a clean UTF-8 string that can
    be chunked and sent to an LLM for dataset generation.

Security Contract:
    This module reads files as STATIC DATA ONLY. It never evaluates, imports,
    or executes any file content regardless of file type. Binary executables
    are parsed structurally (PE/ELF headers) and ASCII strings are extracted
    — they are never loaded into an execution context.

Chunking Strategy (three stages):
    Stage 1 — Semantic: splits at natural code/document boundaries
               (blank lines, function/class defs, Markdown headers).
    Stage 2 — Sliding window: fallback when semantic split produces ≤ 1 unit.
    Stage 3 — Force-split guard: applies when any chunk exceeds 2×chunk_size
               (e.g. minified JS with no newlines).

Size Limits:
    MAX_FILE_SIZE_BYTES = 20 MB hard cap to prevent OOM on huge log files.
    MIN_CHUNK_CHARS    = 80 chars minimum to discard near-empty chunks.

Known Limitations:
    - Archive support: only .zip; other formats (’.tar’, '.gz', etc.)
      return only a header line.
    - Image support: returns a placeholder string, no pixel/EXIF analysis.
"""

from __future__ import annotations

import io
import logging
import re
import struct
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_CHUNK   = 3500
DEFAULT_OVERLAP = 400
MIN_CHUNK_CHARS = 80   # discard chunks shorter than this
MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024  # 20 MB hard limit — prevents OOM on huge logs

_TEXT_EXTS = {
    ".txt",".md",".rst",".log",".csv",".tsv",".conf",".cfg",".ini",
    ".env",".toml",".sql",".py",".pyw",".ps1",".psm1",".psd1",
    ".sh",".bash",".zsh",".bat",".cmd",".vbs",".vba",".js",".mjs",
    ".ts",".jsx",".tsx",".php",".rb",".go",".rs",".swift",".kt",
    ".kts",".scala",".groovy",".c",".cpp",".cc",".h",".hpp",".cs",
    ".java",".lua",".pl",".r",".m",".asm",".s",".nim",".zig",
    ".json",".jsonl",".yaml",".yml",".xml",".html",".htm",".css",
}
_BIN_EXTS = {
    ".exe",".dll",".so",".elf",".bin",".sys",".drv",".com",
    ".ocx",".lib",".a",".o",".ko",
}
_IMG_EXTS = {".png",".jpg",".jpeg",".gif",".bmp",".tiff",".webp",".ico"}
_ARCH_EXTS= {".zip",".tar",".gz",".7z",".rar",".bz2",".xz"}


class FileParser:

    def __init__(
        self,
        chunk_size: int = DEFAULT_CHUNK,
        overlap:    int = DEFAULT_OVERLAP,
    ):
        if overlap >= chunk_size:
            raise ValueError("overlap must be < chunk_size")
        self.chunk_size = chunk_size
        self.overlap    = overlap

    # ── Public ────────────────────────────────────────────────────────────────

    # READ — dispatch to the appropriate format-specific reader.
    # Args:    file_obj: IO — file-like object (must support .seek(0) and .read()).
    #          filename: str — original filename including extension.
    # Returns: str — extracted text content; never raises on decode errors.
    # Side effects: seeks file_obj to position 0 before reading.
    def read(self, file_obj, filename: str) -> str:
        ext = Path(filename).suffix.lower()
        file_obj.seek(0)
        if ext == ".pdf":        return self._read_pdf(file_obj, filename)
        if ext in {".docx",".doc"}: return self._read_docx(file_obj, filename)
        if ext in {".xlsx",".xls"}: return self._read_xlsx(file_obj, filename)
        if ext in {".csv",".tsv"}: return self._read_csv(file_obj)
        if ext in _BIN_EXTS:     return self._read_binary(file_obj, filename)
        if ext in _IMG_EXTS:     return self._read_image_meta(file_obj, filename)
        if ext in _ARCH_EXTS:    return self._read_archive(file_obj, filename)
        if ext in _TEXT_EXTS or ext == "":
            return self._try_text_then_binary(file_obj, filename)
        return self._try_text_then_binary(file_obj, filename)

    # CHUNK — split text into LLM-ready chunks using a three-stage strategy.
    # Args:    text: str — full extracted text to split.
    # Returns: list[str] — chunks of approximately chunk_size characters with
    #          overlap preservation. Empty list if text is blank or all chunks
    #          fall below MIN_CHUNK_CHARS (80 chars).
    # Side effects: None.
    def chunk(self, text: str) -> list[str]:
        if not text.strip():
            return []
        semantic = self._semantic(text)
        result   = semantic if semantic else self._sliding(text)

        # P1.1: Guard against oversized chunks (minified/single-line code).
        # If any produced chunk is > 2x chunk_size it will exceed LLM context →
        # force-split it into safe pieces before returning.
        final = []
        for c in result:
            if len(c) > self.chunk_size * 2:
                logger.debug("Oversized chunk (%d chars) detected — force-splitting.", len(c))
                final.extend(self._force_split(c))
            else:
                final.append(c)

        valid_chunks = []
        for c in final:
            c_strip = c.strip()
            if len(c_strip) < MIN_CHUNK_CHARS:
                continue
            
            # P1.5: OCR Noise / Gibberish Filter
            # If a chunk is mostly symbols/punctuation (e.g., bad PDF extraction or raw base64/hex dumps),
            # it will destroy the LLM's language model. We require at least 50% alphanumeric characters.
            alnum_count = sum(char.isalnum() for char in c_strip)
            alnum_ratio = alnum_count / len(c_strip)
            
            if alnum_ratio < 0.5:
                logger.warning("Chunk discarded due to severe OCR/Symbol noise (alnum ratio: %.2f)", alnum_ratio)
                continue
                
            valid_chunks.append(c)

        return valid_chunks

    # FORCE-SPLIT — last-resort brute-force splitter for oversized chunks.
    # Triggered when semantic or sliding chunkers produce a chunk larger than
    # 2×chunk_size (e.g. a 50,000-char minified JavaScript single line).
    # Args:    text: str — oversized chunk to split.
    # Returns: list[str] — fixed-width slices with overlap.
    # Side effects: None.
    def _force_split(self, text: str) -> list[str]:
        """Last-resort brute-force splitter: slices every chunk_size chars with overlap.

        Used when semantic and sliding chunkers produce chunks too large for the
        model context window (e.g. minified JavaScript on a single line).
        """
        step   = self.chunk_size - self.overlap
        chunks = []
        for i in range(0, len(text), step):
            piece = text[i : i + self.chunk_size]
            if len(piece.strip()) >= MIN_CHUNK_CHARS:
                chunks.append(piece)
        return chunks

    def read_and_chunk(self, file_obj, filename: str) -> list[str]:
        return self.chunk(self.read(file_obj, filename))

    # ── Readers ───────────────────────────────────────────────────────────────

    def _decode(self, raw: bytes) -> str:
        for enc in ("utf-8","utf-8-sig","latin-1","cp1252","utf-16"):
            try:
                return raw.decode(enc)
            except Exception:
                continue
        return raw.decode("utf-8", errors="replace")

    # DETECT — heuristically determine if file bytes are text or binary.
    # Reads up to MAX_FILE_SIZE_BYTES. Inspects the first 512 bytes:
    # if >25% are non-printable control chars (< 0x20, excluding TAB/LF/CR),
    # routes to _read_binary(); otherwise attempts multi-encoding decode.
    # Args:    f: IO          — file-like object.
    #          filename: str  — used for logging.
    # Returns: str — decoded text or binary analysis output.
    # Side effects: logs a WARNING if file exceeds MAX_FILE_SIZE_BYTES.
    def _try_text_then_binary(self, f, filename):
        # P1.1: Read at most MAX_FILE_SIZE_BYTES to prevent OOM on huge files.
        raw = f.read(MAX_FILE_SIZE_BYTES + 1)
        if len(raw) > MAX_FILE_SIZE_BYTES:
            logger.warning(
                "File '%s' exceeds %d MB — truncating to first %d MB for processing.",
                filename, MAX_FILE_SIZE_BYTES // (1024 * 1024),
                MAX_FILE_SIZE_BYTES // (1024 * 1024),
            )
            raw = raw[:MAX_FILE_SIZE_BYTES]
        if isinstance(raw, str):
            return raw
        sample = raw[:512]
        non_print = sum(1 for b in sample if b < 0x20 and b not in (9,10,13))
        if len(sample) > 0 and non_print / len(sample) > 0.25:
            return self._read_binary(io.BytesIO(raw), filename)
        return self._decode(raw)


    def _read_pdf(self, f, filename):
        try:
            from pypdf import PdfReader
        except ImportError:
            raise ImportError("pip install pypdf")
        try:
            reader = PdfReader(f)
            pages = []
            for i, page in enumerate(reader.pages):
                try:
                    pages.append(page.extract_text() or "")
                except Exception as e:
                    logger.warning("PDF page %d: %s", i, e)
                    pages.append("")
            return "\n\n".join(pages)
        except Exception as e:
            raise IOError(f"PDF error '{filename}': {e}")

    def _read_docx(self, f, filename):
        try:
            import docx
        except ImportError:
            raise ImportError("pip install python-docx")
        try:
            doc = docx.Document(f)
            parts = [p.text for p in doc.paragraphs if p.text.strip()]
            for tbl in doc.tables:
                rows = [" | ".join(c.text for c in r.cells) for r in tbl.rows]
                parts.extend(rows)
            return "\n\n".join(parts)
        except Exception as e:
            raise IOError(f"DOCX error '{filename}': {e}")

    def _read_xlsx(self, f, filename):
        try:
            import openpyxl
        except ImportError:
            raise ImportError("pip install openpyxl")
        try:
            wb = openpyxl.load_workbook(f, read_only=True, data_only=True)
            parts = []
            for name in wb.sheetnames:
                ws = wb[name]
                parts.append(f"=== Sheet: {name} ===")
                for row in ws.iter_rows(values_only=True):
                    s = " | ".join("" if c is None else str(c) for c in row)
                    if s.strip(" |"):
                        parts.append(s)
            return "\n".join(parts)
        except Exception as e:
            raise IOError(f"XLSX error '{filename}': {e}")

    def _read_csv(self, f):
        # P1.1: Size guard — CSV files can be enormous.
        raw = f.read(MAX_FILE_SIZE_BYTES + 1)
        if len(raw) > MAX_FILE_SIZE_BYTES:
            logger.warning("CSV file exceeds size limit — truncating to %d MB.",
                           MAX_FILE_SIZE_BYTES // (1024 * 1024))
            raw = raw[:MAX_FILE_SIZE_BYTES]
        return raw if isinstance(raw, str) else self._decode(raw)

    # PARSE BINARY — extract structural metadata and ASCII strings from binary files.
    # Supports PE (Windows executables) and ELF (Linux binaries) header parsing.
    # Extracts up to 600 unique ASCII strings of length >= 6 for content analysis.
    # Args:    f: IO          — file-like object.
    #          filename: str  — original filename for the header line.
    # Returns: str — structured text report of binary metadata and strings.
    # Side effects: None.
    def _read_binary(self, f, filename):
        raw = f.read()
        if isinstance(raw, str):
            raw = raw.encode("latin-1")
        lines = [f"[BINARY FILE: {filename}]", f"[SIZE: {len(raw)} bytes]", ""]

        if raw[:2] == b"MZ":
            lines.append("[FORMAT: PE EXECUTABLE]")
            try:
                e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
                if e_lfanew + 6 < len(raw) and raw[e_lfanew:e_lfanew+4] == b"PE\x00\x00":
                    machine = struct.unpack_from("<H", raw, e_lfanew+4)[0]
                    arch = {0x014c:"x86 32-bit", 0x8664:"x64 64-bit"}.get(machine, hex(machine))
                    lines.append(f"[ARCH: {arch}]")
                    num_sections = struct.unpack_from("<H", raw, e_lfanew+6)[0]
                    lines.append(f"[SECTIONS: {num_sections}]")
            except Exception:
                pass
        elif raw[:4] == b"\x7fELF":
            lines.append("[FORMAT: ELF BINARY]")
            ei_class = raw[4] if len(raw) > 4 else 0
            lines.append(f"[CLASS: {'64-bit' if ei_class==2 else '32-bit'}]")
        elif raw[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
            lines.append("[FORMAT: ZIP/JAR/DOCX CONTAINER]")

        lines.append("\n[EXTRACTED ASCII STRINGS (length ≥ 6)]:")
        found = re.findall(rb'[\x20-\x7e]{6,}', raw)
        seen, count = set(), 0
        for s in found:
            d = s.decode("ascii","ignore")
            if d not in seen:
                seen.add(d)
                lines.append(d)
                count += 1
                if count >= 600:
                    lines.append("[... truncated at 600 strings ...]")
                    break
        return "\n".join(lines)

    def _read_image_meta(self, f, filename):
        raw = f.read()
        sz = len(raw) if isinstance(raw, bytes) else len(raw.encode())
        ext = Path(filename).suffix.upper()
        return (
            f"[IMAGE FILE: {filename}]\n"
            f"[FORMAT: {ext}]\n"
            f"[SIZE: {sz} bytes]\n\n"
            f"Image submitted for cybersecurity context analysis.\n"
            f"Analyze based on filename, metadata, and surrounding context."
        )

    # PARSE ARCHIVE — list files inside an archive.
    # LIMITATION: Only .zip is fully supported. All other archive formats
    # (.tar, .gz, .7z, .rar, .bz2, .xz) return only a header line.
    # Does NOT extract or read archive contents for security reasons.
    # Args:    f: IO          — seekable file-like object.
    #          filename: str  — original filename.
    # Returns: str — newline-separated archive manifest.
    def _read_archive(self, f, filename):
        lines = [f"[ARCHIVE: {filename}]"]
        ext = Path(filename).suffix.lower()
        if ext == ".zip":
            try:
                import zipfile
                f.seek(0)
                with zipfile.ZipFile(f) as zf:
                    names = zf.namelist()
                    lines.append(f"[TOTAL FILES: {len(names)}]")
                    for n in names[:60]:
                        try:
                            info = zf.getinfo(n)
                            lines.append(f"  {n:60s}  ({info.file_size:>10,} bytes)")
                        except Exception:
                            lines.append(f"  {n}")
                    if len(names) > 60:
                        lines.append(f"  ... and {len(names)-60} more files")
            except Exception as e:
                lines.append(f"[Could not list: {e}]")
        return "\n".join(lines)

    # ── Chunkers ──────────────────────────────────────────────────────────────

    # SPLIT SEMANTIC — split text at natural code and document boundaries.
    # Boundary patterns: blank lines, Python def/class, JS function,
    # Java/C# access modifiers, Markdown headers, RST underlines, comment dividers.
    # When a unit exceeds chunk_size it is recursively processed by _sliding().
    # Overlap: the last N chars of the previous chunk (up to self.overlap) are
    # kept as the start of the next chunk to preserve context across boundaries.
    # Args:    text: str — input text.
    # Returns: list[str] — semantic chunks. Empty list if only one unit (triggers
    #          sliding window fallback in chunk()).
    def _semantic(self, text: str) -> list[str]:
        """Split at natural boundaries, respecting chunk_size."""
        splitters = re.compile(
            r'\n{2,}'                  # blank lines
            r'|\ndef '                 # Python function
            r'|\nclass '               # Python class
            r'|\nfunction '            # JS
            r'|\n(?:public|private|protected|static)\s+\w'  # Java/C#
            r'|\n#{1,6} '              # Markdown header
            r'|\n={3,}\n'              # RST header
            r'|\n-{3,}\n'              # RST header
            r'|\n/{4,}\n'              # comment divider
        )
        units = [u.strip() for u in splitters.split(text) if u.strip()]
        if len(units) <= 1:
            return []

        chunks:   list[str] = []
        current:  list[str] = []
        cur_len   = 0

        for unit in units:
            ul = len(unit)
            if ul > self.chunk_size:
                if current:
                    chunks.append("\n\n".join(current))
                    current, cur_len = [], 0
                for sub in self._sliding(unit):
                    chunks.append(sub)
                continue
            if cur_len + ul + 2 > self.chunk_size and current:
                chunks.append("\n\n".join(current))
                # Keep overlap
                ov, ol = [], 0
                for p in reversed(current):
                    if ol + len(p) <= self.overlap:
                        ov.insert(0, p)
                        ol += len(p)
                    else:
                        break
                current, cur_len = ov, ol
            current.append(unit)
            cur_len += ul + 2

        if current:
            chunks.append("\n\n".join(current))
        return [c for c in chunks if c.strip()]

    # SPLIT SLIDING — fixed-width sliding window chunker.
    # Step = chunk_size - overlap, producing overlapping windows.
    # Used as fallback when semantic split yields only one unit.
    # Args:    text: str — input text.
    # Returns: list[str] — all non-empty windows of length chunk_size.
    def _sliding(self, text: str) -> list[str]:
        step = self.chunk_size - self.overlap
        return [text[i:i+self.chunk_size]
                for i in range(0, len(text), step)
                if text[i:i+self.chunk_size].strip()]
