---
name: coco-disassemble
description: "Use when the user asks to disassemble, reverse-engineer, or annotate a 6809/CoCo binary (.bin, .rom, .cas, or raw machine code)."
---

# Disassemble 6809 Binary

Produces annotated LWASM-compatible assembly via a chunked pipeline that keeps
main-agent context small: read only tool stdout and the manifest — never the
full ASM or xref output.

Run all commands from `/home/pi/coco-6809-agent/` (paths below are relative).
`<name>` = input file basename.

**Fast mode**: if the user says "fast" or passes `--fast`, skip step 7. The
Python-annotated output is still highly useful.

## Steps

1. **Identify format**: `python3 tools/romloader.py <file>` (detects DECB BIN, raw, CAS, ROM image).

2. **Disassemble**: `python3 tools/dasm6809.py <file> --annotate --output output/<name>.asm`
   - DECB BIN: segments auto-detected and merged — do **not** pass `--org`.
   - ROM images: origin is inferred (Color BASIC $A000, Extended BASIC $8000, Disk BASIC/cartridges $C000, 32K CoCo 3 $8000) and printed as `; Raw image at ...`. Pass `--org` to override.
   - Raw binaries: if the stderr line says "defaulted to $0E00", pass `--org <addr>`; ask the user if unclear.
   - Non-DECB files: add `--raw` to skip DECB detection.

3. **Section map**: `python3 tools/xref.py <file> --sections --max-chunks N --output output/<name>_sections.json`
   - Same `--org`/`--raw` flags as step 2. N = 6 for binaries ≤16K, 10 for larger.

4. **Split**: `python3 tools/annotator.py --split --asm output/<name>.asm --sections output/<name>_sections.json --output-dir output/<name>_chunks/`
   - Each chunk gets the EQU header, a context header (subroutines, ROM calls, HW accesses, xrefs), and a `; --- BEGIN CODE ---` merge marker.

5. **Read the manifest**: `output/<name>_chunks/manifest.json` (~2KB) for the chunk list.

6. **Python annotation**: `python3 tools/annotator.py --annotate --manifest output/<name>_chunks/manifest.json --ref-dir reference/`
   - Pattern-matches all chunks in one pass (~2s, zero LLM tokens): ROM call descriptions, hardware registers, direct-page BASIC variables, DSKCON fields, memory-clear loops, PSHS/PULS saves, self-modifying code, CoCo 3 GIME/MMU/palette decodes.

7. **Optional LLM annotation** (skip if fast mode): pick up to 2 chunks from the manifest with the highest combined subroutines + hw_accesses + rom_calls count. Dispatch one **foreground** subagent per chunk, in parallel (never background / `run_in_background` — they must be able to prompt for permissions). Each subagent (~30KB context budget):
   - Reads its chunk file (already Python-annotated, ~15KB).
   - Adds inline `;` commentary: subroutine purposes, block behavior (memory init, I/O, string output), notable techniques (self-modifying code, timing loops, bank switching); for CoCo 3, GIME bit fields, MMU page mapping with physical addresses, palette RGB values.
   - Writes the enhanced chunk back to the same file with the Write tool.

8. **Merge**: `python3 tools/annotator.py --merge --manifest output/<name>_chunks/manifest.json --output <path>`
   - Default path if the user didn't specify one: `output/<name>_annotated.asm`.

9. **Present findings** from the manifest only (not the merged file): ROM type, chunk/section count and total lines, key subroutines per section, ROM calls and hardware accesses summary, output file path.

## References

The Python annotator reads these automatically; consult them yourself only when
interpreting results:
- `reference/coco_memory_map.md` — hardware registers (CoCo 1/2/3 incl. GIME/MMU/palette)
- `reference/rom_entry_points.md` — ROM subroutines (Color/Extended/Disk/Super Extended BASIC)

## Output

LWASM-compatible: EQU header, ORG per contiguous region, `L_xxxx`/`SUB_xxxx`
labels, symbolic ROM names, subroutine separators, I/O and ROM-call comments,
FCC/RMB data directives, chunk boundary markers.
