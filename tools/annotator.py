#!/usr/bin/env python3
"""
annotator.py — Split, annotate, and merge tool for chunked disassembly annotation
Usage:
  Split:    python3 annotator.py --split --asm file.asm --sections sections.json --output-dir chunks/
  Annotate: python3 annotator.py --annotate --manifest chunks/manifest.json --ref-dir reference/
  Merge:    python3 annotator.py --merge --manifest chunks/manifest.json --output annotated.asm

Pipeline: dasm6809.py produces the ASM, xref.py --sections produces the chunk
boundaries, then this tool runs split -> annotate -> merge. Chunk files may
also be edited in between (e.g. LLM-added comments); merge only requires that
the CODE_MARKER line and everything after it survive.

Chunk file layout (written by split, relied on by merge):
  EQU header (copied from the source ASM, for assembler context)
  "; CHUNK n of m ..." context block (subroutines, ROM calls, xrefs)
  CODE_MARKER line
  code body (with a synthesized ORG if the chunk didn't start with one)

manifest.json lists every chunk (id, filename, absolute path, address range,
line count, subroutine/ROM-call/HW-access summaries) and is the only file the
driving agent needs to read.
"""

import sys
import os
import json
import argparse
import re

CODE_MARKER = "; --- BEGIN CODE ---"


def extract_header(asm_lines: list[str]) -> tuple[list[str], int]:
    """Extract the EQU header block from the ASM file.

    The header is everything before the first ORG directive (which dasm6809
    emits indented, hence the "ORG anywhere past column 16" fallback).
    Returns (header_lines, first_code_line_index).
    """
    header = []
    i = 0
    for i, line in enumerate(asm_lines):
        stripped = line.strip()
        # Header ends at first ORG directive
        if stripped.startswith("ORG") or (len(stripped) > 16 and "ORG" in stripped):
            break
        header.append(line)
    return header, i


def parse_address_from_line(line: str) -> int | None:
    """Extract address from a disassembly line like '  C000  44  ...'"""
    stripped = line.strip()
    m = re.match(r'^([0-9A-Fa-f]{4})\s', stripped)
    if m:
        return int(m.group(1), 16)
    return None


def find_line_for_address(asm_lines: list[str], start_idx: int, target_addr: int) -> int | None:
    """Find the line index containing or just before target_addr."""
    for i in range(start_idx, len(asm_lines)):
        addr = parse_address_from_line(asm_lines[i])
        if addr is not None and addr >= target_addr:
            j = i
            while j > start_idx and asm_lines[j - 1].strip().startswith((";", "SUB_", "L_")):
                j -= 1
            return j
    return None


# ============================================================
# Pattern Annotator
# ============================================================

class PatternAnnotator:
    """Adds deterministic pattern-based comments to disassembly chunks.

    Lookup tables are parsed from the markdown tables in the reference/
    directory (rom_entry_points.md, coco_memory_map.md), so updating those
    files extends annotation coverage without code changes. annotate_file()
    rewrites each chunk in place and is idempotent: lines that already carry
    a substantial comment are left alone.
    """

    def __init__(self, ref_dir: str):
        self.rom_calls = {}   # addr_int -> (name, description)
        self.hw_regs = {}     # addr_int -> (name, description)
        self.dp_vars = {}     # addr_int -> (name, description)
        self.dskcon_vars = {} # addr_int -> (name, description)
        self._load_references(ref_dir)
        # Reverse map so symbolic operands from dasm6809 (e.g. "GIME_INIT0")
        # resolve to addresses; names are kept identical to dasm6809.HW_LABELS.
        self._hw_names = {name: addr for addr, (name, _) in self.hw_regs.items()}
        self._replace = False

    def _load_references(self, ref_dir: str):
        """Parse reference markdown files into lookup dicts."""
        rom_path = os.path.join(ref_dir, "rom_entry_points.md")
        mem_path = os.path.join(ref_dir, "coco_memory_map.md")

        if os.path.exists(rom_path):
            self._parse_rom_entry_points(rom_path)
        if os.path.exists(mem_path):
            self._parse_memory_map(mem_path)

    def _parse_table_rows(self, filepath: str):
        """Yield (address_str, name, description) from markdown tables."""
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("|") or line.startswith("|---") or line.startswith("| Address") or line.startswith("| Range") or line.startswith("| Offset") or line.startswith("| Mode"):
                    continue
                parts = [p.strip() for p in line.split("|")]
                parts = [p for p in parts if p]
                if len(parts) >= 3:
                    yield parts[0], parts[1], parts[2]

    def _parse_rom_entry_points(self, filepath: str):
        """Parse rom_entry_points.md into rom_calls dict."""
        for addr_str, name, desc in self._parse_table_rows(filepath):
            m = re.match(r'\$([0-9A-Fa-f]{4})', addr_str)
            if m:
                addr = int(m.group(1), 16)
                self.rom_calls[addr] = (name, desc)
            # Also parse DSKCON control block entries
            m2 = re.match(r'\$00([EF][0-9A-Fa-f])', addr_str)
            if m2:
                addr = int(addr_str[1:], 16)
                self.dskcon_vars[addr] = (name, desc)

    def _parse_memory_map(self, filepath: str):
        """Parse coco_memory_map.md into hw_regs and dp_vars dicts."""
        in_section = ""
        for addr_str, name, desc in self._parse_table_rows(filepath):
            m = re.match(r'\$([0-9A-Fa-f]{4})', addr_str)
            if not m:
                # Try range like $0000-$0018
                m2 = re.match(r'\$([0-9A-Fa-f]{4})-\$([0-9A-Fa-f]{4})', addr_str)
                if m2:
                    addr = int(m2.group(1), 16)
                    if addr >= 0xFF00:
                        self.hw_regs[addr] = (name, desc)
                    elif addr < 0x0100:
                        self.dp_vars[addr] = (name, desc)
                continue
            addr = int(m.group(1), 16)
            if addr >= 0xFF00:
                self.hw_regs[addr] = (name, desc)
            elif addr < 0x0100:
                self.dp_vars[addr] = (name, desc)

    def annotate_file(self, filepath: str) -> int:
        """Annotate a single chunk file in-place. Returns count of comments added."""
        with open(filepath, "r") as f:
            lines = f.readlines()

        new_lines = []
        added = 0

        for i, line in enumerate(lines):
            comment = self._analyze_line(line, lines, i)
            if comment and self._replace and comment not in line:
                # Replace dasm6809's generic register comment with the decode
                code, _ = line.split(";", 1)
                new_lines.append(f"{code}{comment}\n")
                added += 1
            elif comment and comment not in line:
                # Append comment to existing line
                stripped = line.rstrip("\n")
                # Pad to column 50 for alignment if line is shorter
                if len(stripped) < 50:
                    stripped = stripped.ljust(50)
                new_lines.append(f"{stripped} {comment}\n")
                added += 1
            else:
                new_lines.append(line)

        with open(filepath, "w") as f:
            f.writelines(new_lines)

        return added

    def _analyze_line(self, line: str, all_lines: list[str], idx: int) -> str | None:
        """Analyze a single disassembly line and return a comment or None.

        Expects dasm6809's hex-dump format ("  C000  BD A5 9A   JSR  CLS");
        lines that don't match are skipped. Only literal $XXXX / <$XX
        operands are resolved — symbolic operands (e.g. "JSR CLS") are left
        to dasm6809 --annotate, which already commented them.
        all_lines/idx allow looking at neighbors, e.g. the preceding
        LDA/LDB #imm for value-aware GIME/MMU/palette decodes.
        """
        stripped = line.strip()

        # Skip comment-only lines, labels, directives, empty lines
        if not stripped or stripped.startswith(";") or stripped.startswith("ORG"):
            return None

        # Already has a substantial comment? Skip — unless it is dasm6809's
        # generic "LABEL - description" comment on a GIME/MMU/palette
        # register, which a value-aware decode can improve (annotate_file
        # then replaces the comment instead of appending).
        self._replace = False
        if ";" in line:
            comment_part = line.split(";", 1)[1].strip()
            if len(comment_part) > 5:
                first = comment_part.split(" - ", 1)[0].strip()
                reg = self._hw_names.get(first)
                if reg is None or not (0xFF90 <= reg <= 0xFFBF):
                    return None
                self._replace = True

        # Extract instruction mnemonic and operand from the disassembly line
        # Format: "  C000  BD A5 9A          JSR     CLS"
        m = re.match(r'^\s*[0-9A-Fa-f]{4}\s+(?:[0-9A-Fa-f]{2}\s+)+\s*(\w+)\s*(.*?)(?:\s*;.*)?$', stripped)
        if not m:
            return None
        mnemonic = m.group(1).upper()
        operand = m.group(2).strip()

        # --- JSR/BSR to known ROM entry points ---
        if mnemonic in ("JSR", "BSR"):
            addr = self._parse_operand_address(operand)
            if addr is not None and addr in self.rom_calls:
                name, desc = self.rom_calls[addr]
                return f"; {name} - {desc}"

        # --- JMP to known ROM entry points ---
        if mnemonic == "JMP":
            addr = self._parse_operand_address(operand)
            if addr is not None and addr in self.rom_calls:
                name, desc = self.rom_calls[addr]
                return f"; {name} - {desc}"

        # --- Hardware register access (extended addressing) ---
        if mnemonic in ("LDA", "LDB", "LDD", "LDX", "LDY", "LDU",
                        "STA", "STB", "STD", "STX", "STY", "STU",
                        "ORA", "ORB", "ANDA", "ANDB", "EORA", "EORB",
                        "BITA", "BITB", "TST", "CLR", "COM", "INC", "DEC"):
            addr = self._parse_operand_address(operand)
            if addr is not None and 0xFF90 <= addr <= 0xFFBF:
                # Value-aware decodes first (store of a preceding LDA/LDB #imm)
                value = self._find_preceding_immediate(all_lines, idx, mnemonic)
                if value is not None:
                    if addr <= 0xFF9F:
                        decode = self._decode_gime_value(addr, value)
                        if decode:
                            name = self.hw_regs.get(addr, (f"GIME_{addr:04X}", ""))[0]
                            return f"; {name} - {decode}"
                    elif addr <= 0xFFAF:
                        return self._decode_mmu_write(addr, value)
                    else:
                        return self._decode_palette_write(addr, value)
            if self._replace:
                return None  # nothing better than the existing comment
            if addr is not None:
                if addr in self.hw_regs:
                    name, desc = self.hw_regs[addr]
                    return f"; {name} - {desc}"
                # Disk controller: named registers come from the reference
                # (DSKREG $FF40, WD179x $FF48-$FF4B); anything else in the
                # $FF40-$FF5F SCS window is cartridge I/O.
                if 0xFF40 <= addr <= 0xFF5F:
                    return f"; Disk/cartridge SCS I/O ${addr:04X}"
                # SAM registers
                if 0xFFC0 <= addr <= 0xFFDF:
                    return f"; SAM register ${addr:04X}"
                # GIME / MMU / palette without a known value
                if 0xFF90 <= addr <= 0xFF9F:
                    return f"; GIME register ${addr:04X}"
                if 0xFFA0 <= addr <= 0xFFAF:
                    return self._decode_mmu_write(addr, None)
                if 0xFFB0 <= addr <= 0xFFBF:
                    return self._decode_palette_write(addr, None)

        # --- Direct-page access to known BASIC/system variables ---
        if mnemonic in ("LDA", "LDB", "LDD", "STA", "STB", "STD",
                        "LDX", "LDY", "STX", "STY", "CLR", "TST",
                        "INC", "DEC", "COM", "ADDA", "ADDB", "ADDD",
                        "SUBA", "SUBB", "SUBD", "CMPA", "CMPB", "CMPD"):
            dp_addr = self._parse_dp_address(operand)
            if dp_addr is not None and dp_addr in self.dp_vars:
                name, desc = self.dp_vars[dp_addr]
                return f"; {name} - {desc}"
            # DSKCON control block
            if dp_addr is not None and dp_addr in self.dskcon_vars:
                name, desc = self.dskcon_vars[dp_addr]
                return f"; {name} - {desc}"

        # --- PSHS/PULS patterns ---
        if mnemonic == "PSHS" and operand:
            return f"; Save registers: {operand}"
        if mnemonic == "PULS" and "PC" in operand.upper():
            return "; Restore registers and return"

        # --- SWI / SWI2 / SWI3 ---
        if mnemonic == "SWI":
            return "; Software interrupt"
        if mnemonic == "SWI2":
            return "; Software interrupt 2 (OS9 system call)"
        if mnemonic == "SWI3":
            return "; Software interrupt 3"

        # --- Memory clear loop detection ---
        # Pattern: CLR ,X+ / CMPX #xxxx / BNE back
        if mnemonic == "CLR" and ",X+" in operand:
            # Look ahead for CMPX + BNE
            for j in range(idx + 1, min(idx + 4, len(all_lines))):
                next_stripped = all_lines[j].strip()
                if "CMPX" in next_stripped:
                    end_m = re.search(r'#\$([0-9A-Fa-f]{4})', next_stripped)
                    if end_m:
                        return f"; Zero-fill memory up to ${end_m.group(1)}"

        # --- Self-modifying code detection ---
        if mnemonic in ("STA", "STB", "STD") and not operand.startswith("<"):
            addr = self._parse_operand_address(operand)
            if addr is not None:
                # Check if target is within typical code regions
                src_addr = parse_address_from_line(line)
                if src_addr is not None and addr >= 0xC000 and addr <= 0xDFFF:
                    # Storing into ROM space — possibly patching RAM copy
                    if abs(addr - src_addr) < 0x200:
                        return "; Self-modifying code: patching nearby instruction"

        return None

    def _parse_operand_address(self, operand: str) -> int | None:
        """Extract an absolute address from '$FF40' or a hardware label such
        as 'GIME_INIT0' (as emitted by dasm6809). Immediates return None."""
        m = re.match(r'^>?\$([0-9A-Fa-f]{4})$', operand)
        if m:
            return int(m.group(1), 16)
        return self._hw_names.get(operand.lstrip('>'))

    def _parse_dp_address(self, operand: str) -> int | None:
        """Extract direct-page address from operand like '<$5F' or '<$EA'."""
        m = re.match(r'^<\$([0-9A-Fa-f]{2})$', operand)
        if m:
            return int(m.group(1), 16)
        return None

    def _find_preceding_immediate(self, all_lines: list[str], idx: int,
                                  mnemonic: str = "STA") -> int | None:
        """Return the 8-bit value a store writes, when knowable.

        CLR writes 0. For STA/STB, look back up to 3 instruction lines for
        the most recent load of the same register (LDA/LDB #$xx); any other
        instruction that targets that register (e.g. LDA ,X+) means the
        value is unknown. STD and other stores return None.
        """
        if mnemonic == "CLR":
            return 0
        reg = {"STA": "A", "STB": "B"}.get(mnemonic)
        if reg is None:
            return None
        seen = 0
        for j in range(idx - 1, -1, -1):
            m = re.match(r'^\s*[0-9A-Fa-f]{4}\s+(?:[0-9A-Fa-f]{2}\s+)+\s*(\w+)\s*(\S*)',
                         all_lines[j].strip())
            if not m:
                if all_lines[j].strip().endswith(":"):
                    return None  # label = possible branch target, value unknown
                continue
            mn, opnd = m.group(1).upper(), m.group(2)
            if mn == "LD" + reg:
                im = re.match(r'^#\$([0-9A-Fa-f]{2})$', opnd)
                return int(im.group(1), 16) if im else None
            if mn.endswith(reg) and not mn.startswith(("ST", "CMP", "BIT", "TST")):
                return None  # register modified by something else
            if mn in ("LDD", "MUL", "TFR", "EXG", "PULS", "PULU") or \
               (reg == "A" and mn == "DAA"):
                return None
            seen += 1
            if seen >= 3:
                return None
        return None

    def _decode_gime_value(self, reg_addr: int, value: int) -> str | None:
        """Decode a value written to a GIME register into human-readable bits."""
        if reg_addr == 0xFF90:
            parts = ["CoCo compat video" if value & 0x80 else "CoCo3 video"]
            if value & 0x40: parts.append("MMU on")
            if value & 0x20: parts.append("GIME IRQ")
            if value & 0x10: parts.append("GIME FIRQ")
            if value & 0x08: parts.append("$FExx const RAM")
            if value & 0x04: parts.append("std SCS")
            parts.append(["16K int+16K ext ROM", "16K int+16K ext ROM",
                          "32K internal ROM", "32K external ROM"][value & 0x03])
            return ", ".join(parts)
        if reg_addr == 0xFF91:
            task = "Task1" if value & 0x01 else "Task0"
            tins = "3.58MHz (279ns)" if value & 0x20 else "line rate (63.5us)"
            return f"{task}, timer={tins}"
        if reg_addr == 0xFF98:
            lpr = ["1", "1", "2", "8", "9", "10", "11", "inf"][value & 0x07]
            parts = ["graphics" if value & 0x80 else "text"]
            if value & 0x20: parts.append("BPI")
            if value & 0x10: parts.append("mono composite")
            parts.append("50Hz" if value & 0x08 else "60Hz")
            parts.append(f"{lpr} lines/row")
            return ", ".join(parts)
        if reg_addr == 0xFF92 or reg_addr == 0xFF93:
            kind = "IRQ" if reg_addr == 0xFF92 else "FIRQ"
            parts = []
            if value & 0x20: parts.append("TMR")
            if value & 0x10: parts.append("HBORD")
            if value & 0x08: parts.append("VBORD")
            if value & 0x04: parts.append("EI2")
            if value & 0x02: parts.append("EI1")
            if value & 0x01: parts.append("EI0")
            return f"{kind}: {'+'.join(parts)}" if parts else f"{kind}: none"
        if reg_addr == 0xFF99:
            # Text/graphics interpretation depends on $FF98 BP, which isn't
            # known here, so both readings are given.
            hres = (value >> 2) & 0x07
            lpf = ["192", "199", "inf", "225"][(value >> 5) & 0x03]
            hres_bytes = [16, 20, 32, 40, 64, 80, 128, 160][hres]
            text_cols = [32, 40, 32, 40, 64, 80, 64, 80][hres]
            cres = ["2col", "4col", "16col", "?"][(value & 0x03)]
            attr = "+attr" if value & 0x01 else ""
            return (f"{lpf} lines, gfx {hres_bytes} B/row {cres}"
                    f" | text {text_cols} cols{attr}")
        if reg_addr == 0xFF9F:
            hven = "HVEN, " if value & 0x80 else ""
            return f"{hven}X offset {(value & 0x7F) * 2} bytes"
        return None

    def _decode_mmu_write(self, reg_addr: int, value: int | None) -> str:
        """Annotate an MMU register write with task/slot/address mapping."""
        task = 0 if reg_addr < 0xFFA8 else 1
        slot = (reg_addr - 0xFFA0) % 8
        lo = slot * 0x2000
        hi = lo + 0x1FFF
        base = f"Task{task} page{slot} (${lo:04X}-${hi:04X})"
        if value is not None:
            phys = value * 0x2000
            return f"; MMU {base} = block ${value:02X} (phys ${phys:05X})"
        return f"; MMU {base}"

    def _decode_palette_write(self, reg_addr: int, value: int | None) -> str:
        """Annotate a palette register write with RGB decode."""
        idx = reg_addr - 0xFFB0
        if value is not None:
            # CoCo 3 RGB bit order is R1 G1 B1 R0 G0 B0 (b5..b0)
            r = ((value >> 4) & 0x02) | ((value >> 2) & 0x01)
            g = ((value >> 3) & 0x02) | ((value >> 1) & 0x01)
            b = ((value >> 2) & 0x02) | (value & 0x01)
            return f"; PAL_{idx} = RGB({r},{g},{b})"
        return f"; PAL_{idx}"


# ============================================================
# Split
# ============================================================

def do_split(args):
    """Split an ASM file into chunk files at the section boundaries from
    xref.py --sections, writing manifest.json alongside them (see module
    docstring for the chunk file layout)."""
    with open(args.asm, "r") as f:
        asm_lines = f.readlines()

    with open(args.sections, "r") as f:
        sections = json.load(f)

    os.makedirs(args.output_dir, exist_ok=True)

    # Extract header (EQU block)
    header_lines, first_code_idx = extract_header(asm_lines)
    header_text = "".join(header_lines)

    manifest = {
        "source_asm": os.path.abspath(args.asm),
        "source_sections": os.path.abspath(args.sections),
        "total_chunks": len(sections),
        "chunks": [],
    }

    # Sanity check: the section map must describe the same addresses as the
    # listing. A mismatch (e.g. dasm6809 and xref.py run with different
    # --org/--raw) would otherwise silently yield 1-line chunks.
    asm_addrs = [a for a in (parse_address_from_line(l) for l in asm_lines[first_code_idx:])
                 if a is not None]
    if asm_addrs and sections:
        lo, hi = min(asm_addrs), max(asm_addrs)
        outside = [s["id"] for s in sections
                   if int(s["end_addr_hex"], 16) < lo or int(s["start_addr_hex"], 16) > hi]
        if len(outside) * 2 > len(sections):
            sys.exit(f"Error: {len(outside)} of {len(sections)} sections lie outside the "
                     f"listing's range ${lo:04X}-${hi:04X}. Run xref.py with the same "
                     f"--org/--raw flags as dasm6809.py.")
        for cid in outside:
            print(f"Warning: section {cid} is outside the listing range "
                  f"${lo:04X}-${hi:04X}", file=sys.stderr)

    for section in sections:
        chunk_id = section["id"]
        start_hex = section["start_addr_hex"]
        end_hex = section["end_addr_hex"]
        start_addr = int(start_hex, 16)
        end_addr = int(end_hex, 16)

        # Find line range for this chunk
        chunk_start_line = find_line_for_address(asm_lines, first_code_idx, start_addr)
        if chunk_start_line is None:
            print(f"Warning: Could not find start address {start_hex} in ASM, skipping chunk {chunk_id}", file=sys.stderr)
            continue

        # Find end: start of next chunk or end of file
        if chunk_id + 1 < len(sections):
            next_start_addr = int(sections[chunk_id + 1]["start_addr_hex"], 16)
            chunk_end_line = find_line_for_address(asm_lines, chunk_start_line + 1, next_start_addr)
            if chunk_end_line is None:
                chunk_end_line = len(asm_lines)
        else:
            chunk_end_line = len(asm_lines)

        chunk_lines = asm_lines[chunk_start_line:chunk_end_line]
        actual_line_count = len(chunk_lines)

        # Build context header
        ctx = []
        ctx.append(f"; =============================================")
        ctx.append(f"; CHUNK {chunk_id} of {len(sections)} -- {start_hex} to {end_hex} ({actual_line_count} lines)")
        ctx.append(f"; =============================================")

        if section.get("subroutines"):
            ctx.append(f"; Subroutines: {', '.join(section['subroutines'])}")
        if section.get("rom_calls"):
            ctx.append(f"; ROM calls: {', '.join(section['rom_calls'])}")
        if section.get("hw_accesses"):
            ctx.append(f"; HW accesses: {', '.join(section['hw_accesses'])}")
        if section.get("calls_out"):
            ctx.append(f"; Calls out: {', '.join(section['calls_out'][:15])}")
            if len(section.get("calls_out", [])) > 15:
                ctx.append(f";   (+{len(section['calls_out']) - 15} more)")
        if section.get("called_from"):
            ctx.append(f"; Called from: {', '.join(section['called_from'][:10])}")
            if len(section.get("called_from", [])) > 10:
                ctx.append(f";   (+{len(section['called_from']) - 10} more)")
        ctx.append(f"; =============================================")
        ctx.append("")

        context_header = "\n".join(ctx) + "\n"

        # Write chunk file
        chunk_filename = f"chunk_{chunk_id:02d}_{start_addr:04X}.asm"
        chunk_path = os.path.join(args.output_dir, chunk_filename)

        with open(chunk_path, "w") as f:
            # Include EQU header for context
            f.write(header_text)
            f.write("\n")
            f.write(context_header)
            # Code marker for reliable merge
            f.write(CODE_MARKER + "\n")
            # Add ORG if the chunk doesn't start with one
            first_content = "".join(chunk_lines).strip()
            if "ORG" not in first_content[:200]:
                f.write(f"                 ORG    ${start_addr:04X}\n\n")
            f.write("".join(chunk_lines))

        manifest["chunks"].append({
            "id": chunk_id,
            "filename": chunk_filename,
            "path": os.path.abspath(chunk_path),
            "start_addr": start_hex,
            "end_addr": end_hex,
            "line_count": actual_line_count,
            "subroutines": section.get("subroutines", []),
            "rom_calls": section.get("rom_calls", []),
            "hw_accesses": section.get("hw_accesses", []),
        })

    # Write manifest
    manifest_path = os.path.join(args.output_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"Split into {len(manifest['chunks'])} chunks in {args.output_dir}", file=sys.stderr)
    print(f"Manifest: {manifest_path}", file=sys.stderr)
    for chunk in manifest["chunks"]:
        print(f"  chunk_{chunk['id']:02d}: {chunk['start_addr']}-{chunk['end_addr']} ({chunk['line_count']} lines)", file=sys.stderr)


# ============================================================
# Annotate
# ============================================================

def do_annotate(args):
    """Run Python-based pattern annotation on all chunks in manifest."""
    with open(args.manifest, "r") as f:
        manifest = json.load(f)

    annotator = PatternAnnotator(args.ref_dir)
    total_added = 0

    for chunk_info in manifest["chunks"]:
        chunk_path = chunk_info["path"]
        if not os.path.exists(chunk_path):
            chunks_dir = os.path.dirname(os.path.abspath(args.manifest))
            chunk_path = os.path.join(chunks_dir, chunk_info["filename"])

        added = annotator.annotate_file(chunk_path)
        total_added += added
        print(f"  chunk_{chunk_info['id']:02d}: +{added} comments", file=sys.stderr)

    print(f"Annotation complete: {total_added} comments added across {len(manifest['chunks'])} chunks", file=sys.stderr)


# ============================================================
# Merge
# ============================================================

def do_merge(args):
    """Merge annotated chunks back into a single file.

    Takes the EQU header once from the first chunk, then for every chunk
    keeps only the body after CODE_MARKER — stripping the per-chunk header
    that was duplicated for annotation context. Falls back to finding the
    first ORG line if a chunk lost its marker.
    """
    with open(args.manifest, "r") as f:
        manifest = json.load(f)

    chunks_dir = os.path.dirname(os.path.abspath(args.manifest))

    # Read the header from the first chunk (everything before the CODE_MARKER)
    first_chunk_path = manifest["chunks"][0]["path"]
    if not os.path.exists(first_chunk_path):
        first_chunk_path = os.path.join(chunks_dir, manifest["chunks"][0]["filename"])

    with open(first_chunk_path, "r") as f:
        first_chunk_lines = f.readlines()

    # Extract header: everything before the CHUNK context block
    header_lines = []
    for i, line in enumerate(first_chunk_lines):
        if line.strip().startswith("; CHUNK "):
            header_lines = first_chunk_lines[:i]
            break

    out = []
    # Write header once
    out.extend(header_lines)

    # Merge each chunk's body (everything after CODE_MARKER)
    for chunk_info in manifest["chunks"]:
        chunk_path = chunk_info["path"]
        if not os.path.exists(chunk_path):
            chunk_path = os.path.join(chunks_dir, chunk_info["filename"])

        with open(chunk_path, "r") as f:
            lines = f.readlines()

        # Find body: everything after CODE_MARKER
        body_start_idx = 0
        for i, line in enumerate(lines):
            if line.strip() == CODE_MARKER.strip():
                body_start_idx = i + 1
                break
        else:
            # Fallback: no marker found, skip EQU header, find first ORG
            for i, line in enumerate(lines):
                if "ORG    $" in line:
                    body_start_idx = i
                    break

        body = lines[body_start_idx:]
        out.append(f"\n; ---- Chunk {chunk_info['id']}: {chunk_info['start_addr']}-{chunk_info['end_addr']} ----\n")
        out.extend(body)

    # Write merged output
    output_text = "".join(out)
    if args.output:
        with open(args.output, "w") as f:
            f.write(output_text)
        print(f"Merged {len(manifest['chunks'])} chunks to {args.output}", file=sys.stderr)
    else:
        print(output_text)


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Disassembly annotation splitter/merger")
    subparsers = parser.add_subparsers(dest="command")

    # Split command
    split_parser = subparsers.add_parser("split", help="Split ASM into annotatable chunks")
    split_parser.add_argument("--asm", required=True, help="Input ASM file from dasm6809.py")
    split_parser.add_argument("--sections", required=True, help="Sections JSON from xref.py --sections")
    split_parser.add_argument("--output-dir", required=True, help="Output directory for chunks")

    # Annotate command
    ann_parser = subparsers.add_parser("annotate", help="Pattern-based annotation of chunks")
    ann_parser.add_argument("--manifest", required=True, help="Manifest JSON from split")
    ann_parser.add_argument("--ref-dir", required=True, help="Reference files directory")

    # Merge command
    merge_parser = subparsers.add_parser("merge", help="Merge annotated chunks into single file")
    merge_parser.add_argument("--manifest", required=True, help="Manifest JSON from split")
    merge_parser.add_argument("--output", "-o", help="Output file (default: stdout)")

    # Also support --split/--merge/--annotate flags for backward compatibility
    parser.add_argument("--split", action="store_true", help="Split mode")
    parser.add_argument("--merge", action="store_true", help="Merge mode")
    parser.add_argument("--annotate", action="store_true", help="Annotate mode")
    parser.add_argument("--asm", help="Input ASM file (for --split)")
    parser.add_argument("--sections", help="Sections JSON (for --split)")
    parser.add_argument("--output-dir", help="Output directory (for --split)")
    parser.add_argument("--manifest", help="Manifest JSON (for --merge/--annotate)")
    parser.add_argument("--output", "-o", help="Output file (for --merge)")
    parser.add_argument("--ref-dir", help="Reference directory (for --annotate)")

    args = parser.parse_args()

    if args.command == "split":
        do_split(args)
    elif args.command == "annotate":
        do_annotate(args)
    elif args.command == "merge":
        do_merge(args)
    elif getattr(args, 'split', False):
        if not args.asm or not args.sections or not args.output_dir:
            parser.error("--split requires --asm, --sections, and --output-dir")
        do_split(args)
    elif getattr(args, 'annotate', False):
        if not args.manifest or not args.ref_dir:
            parser.error("--annotate requires --manifest and --ref-dir")
        do_annotate(args)
    elif getattr(args, 'merge', False):
        if not args.manifest:
            parser.error("--merge requires --manifest")
        do_merge(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
