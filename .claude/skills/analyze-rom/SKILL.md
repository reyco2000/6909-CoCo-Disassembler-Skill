---
name: analyze-rom
description: "Deep-analyze a CoCo ROM image. Identifies ROM type, maps subroutine boundaries, documents the vector table, and produces a structured analysis of the ROM's functionality."
---

# Analyze CoCo ROM Image

## Steps

1. **Identify ROM**: Run `python3 tools/romloader.py <file> --json` to get format, MD5, and known ROM match
2. **Read reference data**: Load `reference/rom_entry_points.md` and `reference/coco_memory_map.md`
3. **Map the ROM**:
   - Read the interrupt vector table at the end ($FFF0-$FFFF relative to ROM)
   - Identify the reset vector entry point
   - Disassemble from the reset vector forward
   - Use `python3 tools/xref.py` to find all subroutine boundaries
4. **Classify regions**:
   - Code regions (instructions)
   - Data tables (byte sequences that don't decode as valid instructions)
   - String tables (ASCII text)
   - Jump tables (vectors)
5. **Produce report**: Document each major subroutine with:
   - Address range
   - Entry conditions (registers expected)
   - Exit conditions (return values)
   - Purpose description
   - Called-by / calls-to relationships

## Analysis Tips

- CoCo ROMs often have jump tables near the beginning
- Keyword tables for BASIC are tokenized ASCII strings with bit 7 set on the last character
- Error message tables follow a similar pattern
- Math routines in Color BASIC use a floating-point accumulator (FAC) at $004F-$0054
- Always check for indirect jumps through the vector table at $0100-$0200 area (BASIC hooks)
