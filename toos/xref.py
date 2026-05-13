#!/usr/bin/env python3
"""
xref.py — Cross-reference and call graph builder for 6809 binaries
Usage: python3 xref.py <binfile> [--org 0x0E00] [--output xref.txt]

Builds a unified memory image from all DECB segments before analyzing,
so cross-segment references are correctly tracked.
"""

import sys
import argparse
from collections import defaultdict
try:
    from tools.dasm6809 import (Disassembler6809, MemoryImage, load_decb_bin,
                                 ROM_LABELS, HW_LABELS, hw_comment)
except ImportError:
    from dasm6809 import (Disassembler6809, MemoryImage, load_decb_bin,
                           ROM_LABELS, HW_LABELS, hw_comment)


class CrossReferenceBuilder:
    def __init__(self, mem: MemoryImage, exec_addr: int = None):
        self.mem = mem
        self.exec_addr = exec_addr
        self.dasm = Disassembler6809(mem, entry_addr=exec_addr)

        # Analysis results
        self.calls_from: dict[int, list[int]] = defaultdict(list)
        self.calls_to: dict[int, list[int]] = defaultdict(list)
        self.jumps_from: dict[int, list[int]] = defaultdict(list)
        self.jumps_to: dict[int, list[int]] = defaultdict(list)
        self.data_refs: dict[int, list[int]] = defaultdict(list)
        self.rom_calls: dict[int, list[int]] = defaultdict(list)
        self.hw_accesses: dict[int, list[int]] = defaultdict(list)
        self.subroutines: set[int] = set()
        self.strings: list[tuple[int, str]] = []

    def analyze(self):
        """Run full cross-reference analysis on unified memory."""
        self._pass_find_refs()
        self._find_strings()

    def _pass_find_refs(self):
        """Scan all populated ranges to build reference maps."""
        ranges = self.mem.get_contiguous_ranges()
        for rng_start, rng_end in ranges:
            pc = rng_start
            while pc <= rng_end:
                mnemonic, operand, consumed, comment = self.dasm.disassemble_instruction(pc)
                target = self._extract_target(pc, mnemonic, operand)

                if target is not None:
                    if mnemonic in ("JSR", "BSR", "LBSR"):
                        self.calls_from[pc].append(target)
                        self.calls_to[target].append(pc)
                        self.subroutines.add(target)
                        if target in ROM_LABELS:
                            self.rom_calls[target].append(pc)

                    elif mnemonic in ("JMP", "BRA", "LBRA",
                                       "BNE", "BEQ", "BCC", "BCS", "BHI", "BLS",
                                       "BPL", "BMI", "BGE", "BLT", "BGT", "BLE",
                                       "BVC", "BVS",
                                       "LBNE", "LBEQ", "LBCC", "LBCS", "LBHI", "LBLS",
                                       "LBPL", "LBMI", "LBGE", "LBLT", "LBGT", "LBLE",
                                       "LBVC", "LBVS"):
                        self.jumps_from[pc].append(target)
                        self.jumps_to[target].append(pc)

                    elif mnemonic in ("LDA", "LDB", "LDD", "LDX", "LDY", "LDU", "LDS",
                                       "STA", "STB", "STD", "STX", "STY", "STU", "STS",
                                       "CMPA", "CMPB", "CMPD", "CMPX", "CMPY", "CMPU", "CMPS",
                                       "CLR", "TST", "INC", "DEC", "NEG", "COM",
                                       "ASL", "ASR", "LSR", "ROL", "ROR"):
                        self.data_refs[target].append(pc)
                        if target in HW_LABELS or 0xFF00 <= target <= 0xFFFF:
                            self.hw_accesses[target].append(pc)

                pc += consumed

    def _extract_target(self, pc: int, mnemonic: str, operand: str) -> int | None:
        """Extract target address from an operand string."""
        # Direct $XXXX format
        if operand.startswith("$") and len(operand) == 5:
            try:
                return int(operand[1:], 16)
            except ValueError:
                pass

        # Check all known label maps
        for addr, label in ROM_LABELS.items():
            if operand == label:
                return addr
        for addr, label in HW_LABELS.items():
            if operand == label:
                return addr
        for addr, label in self.dasm.labels.items():
            if operand == label:
                return addr

        # L_xxxx or SUB_xxxx format
        for prefix in ("L_", "SUB_"):
            if operand.startswith(prefix):
                try:
                    return int(operand[len(prefix):], 16)
                except (ValueError, IndexError):
                    pass

        return None

    def _find_strings(self):
        """Find possible ASCII strings in populated memory."""
        ranges = self.mem.get_contiguous_ranges()
        for rng_start, rng_end in ranges:
            i = rng_start
            while i <= rng_end:
                if 32 <= self.mem.byte_at(i) <= 126:
                    start = i
                    while i <= rng_end and 32 <= self.mem.byte_at(i) <= 126:
                        i += 1
                    length = i - start
                    if length >= 4:
                        text = ''.join(chr(self.mem.byte_at(start + j)) for j in range(length))
                        self.strings.append((start, text))
                else:
                    i += 1

    def format_report(self) -> str:
        """Generate cross-reference report."""
        out = []
        ranges = self.mem.get_contiguous_ranges()
        total_bytes = sum(e - s + 1 for s, e in ranges)

        out.append("=" * 70)
        out.append("  CROSS-REFERENCE REPORT")
        out.append(f"  Memory: {total_bytes} bytes in {len(ranges)} range(s)")
        for s, e in ranges:
            out.append(f"    ${s:04X}-${e:04X} ({e - s + 1} bytes)")
        if self.exec_addr is not None:
            out.append(f"  Exec address: ${self.exec_addr:04X}")
        out.append("=" * 70)

        # Subroutines
        out.append(f"\n--- SUBROUTINES ({len(self.subroutines)}) ---")
        for addr in sorted(self.subroutines):
            callers = self.calls_to.get(addr, [])
            label = ROM_LABELS.get(addr, f"SUB_{addr:04X}")
            caller_str = ", ".join(f"${c:04X}" for c in callers[:8])
            if len(callers) > 8:
                caller_str += f" (+{len(callers)-8} more)"
            out.append(f"  ${addr:04X}  {label:20s}  called from: {caller_str}")

        # ROM calls
        if self.rom_calls:
            out.append(f"\n--- ROM CALLS ({len(self.rom_calls)}) ---")
            for addr in sorted(self.rom_calls.keys()):
                callers = self.rom_calls[addr]
                label = ROM_LABELS.get(addr, f"${addr:04X}")
                for caller in sorted(callers):
                    out.append(f"  ${caller:04X} -> {label} (${addr:04X})")

        # Hardware accesses
        if self.hw_accesses:
            out.append(f"\n--- HARDWARE I/O ACCESSES ({len(self.hw_accesses)}) ---")
            for addr in sorted(self.hw_accesses.keys()):
                refs = self.hw_accesses[addr]
                label = HW_LABELS.get(addr, f"${addr:04X}")
                for ref in sorted(refs):
                    out.append(f"  ${ref:04X} -> {label} (${addr:04X})")

        # Branch/jump targets
        jump_only = set()
        for target in sorted(self.jumps_to.keys()):
            if target not in self.subroutines:
                jump_only.add(target)
        if jump_only:
            out.append(f"\n--- BRANCH/JUMP TARGETS ({len(jump_only)}) ---")
            for addr in sorted(jump_only):
                sources = self.jumps_to.get(addr, [])
                src_str = ", ".join(f"${s:04X}" for s in sorted(sources)[:8])
                out.append(f"  L_{addr:04X}  from: {src_str}")

        # Strings
        if self.strings:
            out.append(f"\n--- ASCII STRINGS ({len(self.strings)}) ---")
            for addr, text in self.strings:
                display = text[:60]
                if len(text) > 60:
                    display += "..."
                out.append(f"  ${addr:04X}  \"{display}\"")

        # Call graph
        if self.calls_from:
            out.append(f"\n--- CALL GRAPH ---")
            for caller in sorted(self.calls_from.keys()):
                targets = self.calls_from[caller]
                for target in targets:
                    label = ROM_LABELS.get(target, f"SUB_{target:04X}")
                    out.append(f"  ${caller:04X} --> {label}")

        out.append("\n" + "=" * 70)
        return "\n".join(out)

    def format_sections(self, chunk_target: int = 500, max_chunks: int = None) -> str:
        """Output JSON section map with logical boundaries for chunked annotation.
        chunk_target: target instructions per chunk (default 500).
        max_chunks: if set, override chunk_target to produce at most this many chunks."""
        import json

        ranges = self.mem.get_contiguous_ranges()

        # Build ordered list of all "boundary" addresses: subroutine entries + range starts
        boundaries = set()
        for rng_start, _ in ranges:
            boundaries.add(rng_start)
        for addr in self.subroutines:
            # Only include subroutines within our populated ranges
            for rng_start, rng_end in ranges:
                if rng_start <= addr <= rng_end:
                    boundaries.add(addr)
        boundaries = sorted(boundaries)

        # Count lines per boundary-delimited section by walking the disassembly
        section_lines = []  # list of (start_addr, end_addr, line_count)
        for idx, baddr in enumerate(boundaries):
            # Find end: next boundary - 1 or range end
            if idx + 1 < len(boundaries):
                end_addr = boundaries[idx + 1] - 1
            else:
                # Last section: find the range it belongs to
                end_addr = baddr
                for rng_start, rng_end in ranges:
                    if rng_start <= baddr <= rng_end:
                        end_addr = rng_end
                        break

            # Count instructions/data lines in this section
            line_count = 0
            pc = baddr
            while pc <= end_addr:
                if self.mem.is_populated(pc):
                    _, _, consumed, _ = self.dasm.disassemble_instruction(pc)
                    line_count += 1
                    pc += consumed
                else:
                    break
            if line_count > 0:
                section_lines.append((baddr, end_addr, line_count))

        # If max_chunks is set, compute chunk_target from total instructions
        if max_chunks is not None and section_lines:
            total_instructions = sum(lc for _, _, lc in section_lines)
            chunk_target = max(200, total_instructions // max_chunks)

        # Merge small sections into chunks targeting chunk_target lines
        chunks = []
        current_chunk = None
        for start_addr, end_addr, line_count in section_lines:
            if current_chunk is None:
                current_chunk = {
                    "start_addr": start_addr,
                    "end_addr": end_addr,
                    "line_count": line_count,
                    "subroutines": [],
                }
            elif current_chunk["line_count"] + line_count <= chunk_target * 1.3:
                # Merge into current chunk
                current_chunk["end_addr"] = end_addr
                current_chunk["line_count"] += line_count
            else:
                chunks.append(current_chunk)
                current_chunk = {
                    "start_addr": start_addr,
                    "end_addr": end_addr,
                    "line_count": line_count,
                    "subroutines": [],
                }
            # Track subroutines in chunk
            if start_addr in self.subroutines:
                label = ROM_LABELS.get(start_addr, f"SUB_{start_addr:04X}")
                current_chunk["subroutines"].append(label)

        if current_chunk:
            chunks.append(current_chunk)

        # Enrich each chunk with cross-reference metadata
        for i, chunk in enumerate(chunks):
            chunk["id"] = i
            chunk["start_addr_hex"] = f"0x{chunk['start_addr']:04X}"
            chunk["end_addr_hex"] = f"0x{chunk['end_addr']:04X}"

            # ROM calls within this chunk's address range
            chunk_rom_calls = set()
            for rom_addr, callers in self.rom_calls.items():
                for caller in callers:
                    if chunk["start_addr"] <= caller <= chunk["end_addr"]:
                        chunk_rom_calls.add(ROM_LABELS.get(rom_addr, f"${rom_addr:04X}"))
            chunk["rom_calls"] = sorted(chunk_rom_calls)

            # HW accesses within this chunk
            chunk_hw = set()
            for hw_addr, refs in self.hw_accesses.items():
                for ref in refs:
                    if chunk["start_addr"] <= ref <= chunk["end_addr"]:
                        chunk_hw.add(HW_LABELS.get(hw_addr, f"${hw_addr:04X}"))
            chunk["hw_accesses"] = sorted(chunk_hw)

            # Calls out to other chunks
            calls_out = set()
            for caller, targets in self.calls_from.items():
                if chunk["start_addr"] <= caller <= chunk["end_addr"]:
                    for target in targets:
                        if not (chunk["start_addr"] <= target <= chunk["end_addr"]):
                            label = ROM_LABELS.get(target, f"SUB_{target:04X}")
                            calls_out.add(label)
            chunk["calls_out"] = sorted(calls_out)

            # Called from other chunks
            called_from = set()
            for target, callers in self.calls_to.items():
                if chunk["start_addr"] <= target <= chunk["end_addr"]:
                    for caller in callers:
                        if not (chunk["start_addr"] <= caller <= chunk["end_addr"]):
                            called_from.add(f"${caller:04X}")
            chunk["called_from"] = sorted(called_from)

            # Clean up internal fields
            del chunk["start_addr"]
            del chunk["end_addr"]

        return json.dumps(chunks, indent=2)


def main():
    parser = argparse.ArgumentParser(description="6809 Cross-Reference Builder")
    parser.add_argument("file", help="Binary file to analyze")
    parser.add_argument("--org", type=lambda x: int(x, 0), default=None,
                        help="Origin address (auto-detected for DECB BIN)")
    parser.add_argument("--output", "-o", help="Output file")
    parser.add_argument("--sections", action="store_true",
                        help="Output JSON section map for chunked annotation")
    parser.add_argument("--chunk-size", type=int, default=500,
                        help="Target instructions per chunk for --sections (default: 500)")
    parser.add_argument("--max-chunks", type=int, default=None,
                        help="Maximum number of chunks (overrides --chunk-size)")
    parser.add_argument("--raw", action="store_true",
                        help="Treat as raw binary (skip DECB format detection)")
    args = parser.parse_args()

    with open(args.file, "rb") as f:
        raw = f.read()

    mem = MemoryImage()
    exec_addr = None

    if not args.raw and len(raw) > 5 and raw[0] == 0x00:
        segments, exec_addr = load_decb_bin(raw)
        if segments:
            print(f"; DECB BIN — {len(segments)} segment(s), unified analysis", file=sys.stderr)
            for seg_org, seg_data in segments:
                mem.load_segment(seg_org, seg_data)
        else:
            org = args.org if args.org is not None else 0x0E00
            mem.load_segment(org, raw)
    else:
        org = args.org if args.org is not None else 0x0E00
        mem.load_segment(org, raw)

    xref = CrossReferenceBuilder(mem, exec_addr=exec_addr)
    xref.analyze()

    if args.sections:
        result = xref.format_sections(chunk_target=args.chunk_size, max_chunks=args.max_chunks)
    else:
        result = xref.format_report()

    if args.output:
        with open(args.output, "w") as f:
            f.write(result)
        print(f"Output written to {args.output}", file=sys.stderr)
    else:
        print(result)


if __name__ == "__main__":
    main()
