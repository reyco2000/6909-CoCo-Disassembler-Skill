# CoCo 6809 Disassembler Expert — Code Agent

A Code agent specialized in MC6809 disassembly and reverse engineering
for the TRS-80 Color Computer (CoCo) ecosystem.

## Quick Start & Installation

You can use this toolset locally in this folder, or install it as a global skill in your AI coding assistants!

### Using with Antigravity (Global Skill)
To use these tools natively inside Antigravity from any workspace:
1. Clone this repository to a known location on your machine (e.g., `C:\tools\coco-6809-agent`).
2. Open Antigravity in any workspace and say: 
   *"Please look into `C:\tools\coco-6809-agent` and help me to add this as a skill to be used globally in Antigravity."*
3. Antigravity will automatically create a **Knowledge Item (KI)** documenting the python pipeline and FDC mappings, allowing it to seamlessly run the tools whenever you ask it to disassemble or analyze a CoCo binary.

### Using with Claude Code
Claude Code natively supports the `.claude/skills` and `.claude/commands` folders included in this repository.
* **Project Level**: Simply `cd` into this directory and run `claude`. The custom slash commands will be immediately available.
* **Global Level**: To use these commands anywhere, copy the contents of the `.claude/skills` directory into your global Claude configuration (typically `~/.claude/skills/`).

## Setup & Usage

1. Place your CoCo ROM files or binaries in the `roms/` directory (or provide the absolute path to your binaries):
   - `bas12.rom` — Color BASIC 1.2
   - `extbas11.rom` — Extended BASIC 1.1
   - `disk11.rom` — Disk BASIC 1.1
   - Any program binaries (.bin, .cas) you want to analyze

2. Use the available commands to analyze your binaries:
   - **`/disassemble <file>`** — Full disassembly with automatic annotation
   - **`/analyze-rom <file>`** — Deep ROM image analysis
   - **`/trace-calls <file>`** — Call graph and execution flow
   - **`/coco-help <topic>`** — Quick reference lookup

3. Natural language prompts also work beautifully:
   - *"Disassemble this BASIC ML program at $3F00"*
   - *"What ROM calls does this program make?"*
   - *"Analyze the interrupt handling in this ROM"*

## Tools

| Tool | Purpose |
|------|---------|
| `tools/dasm6809.py` | Two-pass 6809 disassembler with label resolution |
| `tools/romloader.py` | File format detection (DECB BIN, CAS, raw, known ROMs) |
| `tools/xref.py` | Cross-reference builder (calls, jumps, data refs, strings) |

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
