# CoCo 6809 Disassembler Expert — Claude Code Agent

A Claude Code agent specialized in MC6809 disassembly and reverse engineering
for the TRS-80 Color Computer (CoCo) ecosystem.

## Quick Start

```bash
# Open this project in Claude Code
cd coco-6809-agent
claude

# Available slash commands:
/coco-disassemble <file>   # Full disassembly with annotations
/analyze-rom <file>        # Deep ROM image analysis
/trace-calls <file>        # Call graph and execution flow
/coco-help <topic>         # Quick reference lookup
```

## Setup

1. Place your CoCo ROM files in the `roms/` directory:
   - `bas12.rom` — Color BASIC 1.2
   - `extbas11.rom` — Extended BASIC 1.1
   - `disk11.rom` — Disk BASIC 1.1
   - Any program binaries (.bin, .cas) you want to analyze

2. Open the project with Claude Code:
   ```bash
   claude
   ```

3. Ask Claude to analyze any binary:
   - "Disassemble this BASIC ML program at $3F00"
   - "What ROM calls does this program make?"
   - "Analyze the interrupt handling in this ROM"
   - "Trace the call graph starting from the EXEC address"

## Tools

| Tool | Purpose |
|------|---------|
| `tools/dasm6809.py` | Two-pass 6809 disassembler with label resolution |
| `tools/romloader.py` | File format detection (DECB BIN, CAS, raw, known ROMs) |
| `tools/xref.py` | Cross-reference builder (calls, jumps, data refs, strings) |
| `tools/annotator.py` | Split / pattern-annotate / merge for chunked disassembly |

## What the Agent Knows

- Complete MC6809 instruction set (all 3 opcode pages)
- Indexed addressing mode decoding (all postbyte variants)
- CoCo memory map ($0000-$FFFF)
- Color BASIC, Extended BASIC, and Disk BASIC ROM entry points
- PIA, SAM, VDG, and FDC hardware register maps
- DECB BIN file format (multi-segment + exec trailer)
- CAS cassette format detection
- Common CoCo programming patterns and idioms

## Output

Disassembly output is LWASM-compatible and includes:
- EQU definitions for ROM/hardware symbols used
- ORG directives matching load addresses
- Symbolic labels for all branch/jump targets
- ROM subroutine names for known entry points
- Hardware I/O comments on PIA/SAM/FDC accesses
- FCB/FCC directives for data regions

## License

MIT — Built for the CoCoByte Club
