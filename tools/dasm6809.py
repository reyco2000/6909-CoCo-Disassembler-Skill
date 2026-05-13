#!/usr/bin/env python3
"""
dasm6809.py — MC6809 Disassembler Engine for CoCo Analysis
Author: CoCoByte Club
Usage:  python3 dasm6809.py <binfile> [--org 0x0E00] [--output file.asm] [--end 0xFFFF]

Supports:
  - DECB BIN multi-segment files (builds unified memory image)
  - Automatic data region detection (strings, tables, zero-fill)
  - CoCo 1/2/3 hardware labels (PIA, SAM, FDC, GIME, MMU, palette)
  - Cross-segment instruction decoding
"""

import sys
import argparse
from typing import Optional

# ===========================================================================
# MC6809 OPCODE TABLES
# ===========================================================================

INH  = "inherent"
IMM8 = "immediate8"
IMM16= "immediate16"
DIR  = "direct"
EXT  = "extended"
IDX  = "indexed"
REL8 = "relative8"
REL16= "relative16"

OPCODES_PAGE1 = {
    0x00: ("NEG",   DIR,  1), 0x03: ("COM",   DIR,  1), 0x04: ("LSR",   DIR,  1),
    0x06: ("ROR",   DIR,  1), 0x07: ("ASR",   DIR,  1), 0x08: ("ASL",   DIR,  1),
    0x09: ("ROL",   DIR,  1), 0x0A: ("DEC",   DIR,  1), 0x0C: ("INC",   DIR,  1),
    0x0D: ("TST",   DIR,  1), 0x0E: ("JMP",   DIR,  1), 0x0F: ("CLR",   DIR,  1),

    0x12: ("NOP",   INH,  0), 0x13: ("SYNC",  INH,  0), 0x16: ("LBRA",  REL16, 2),
    0x17: ("LBSR",  REL16, 2), 0x19: ("DAA",   INH,  0), 0x1A: ("ORCC",  IMM8, 1),
    0x1C: ("ANDCC", IMM8, 1), 0x1D: ("SEX",   INH,  0), 0x1E: ("EXG",   IMM8, 1),
    0x1F: ("TFR",   IMM8, 1),

    0x20: ("BRA",   REL8, 1), 0x21: ("BRN",   REL8, 1), 0x22: ("BHI",   REL8, 1),
    0x23: ("BLS",   REL8, 1), 0x24: ("BCC",   REL8, 1), 0x25: ("BCS",   REL8, 1),
    0x26: ("BNE",   REL8, 1), 0x27: ("BEQ",   REL8, 1), 0x28: ("BVC",   REL8, 1),
    0x29: ("BVS",   REL8, 1), 0x2A: ("BPL",   REL8, 1), 0x2B: ("BMI",   REL8, 1),
    0x2C: ("BGE",   REL8, 1), 0x2D: ("BLT",   REL8, 1), 0x2E: ("BGT",   REL8, 1),
    0x2F: ("BLE",   REL8, 1),

    0x30: ("LEAX",  IDX,  None), 0x31: ("LEAY",  IDX,  None),
    0x32: ("LEAS",  IDX,  None), 0x33: ("LEAU",  IDX,  None),
    0x34: ("PSHS",  IMM8, 1), 0x35: ("PULS",  IMM8, 1),
    0x36: ("PSHU",  IMM8, 1), 0x37: ("PULU",  IMM8, 1),
    0x39: ("RTS",   INH,  0), 0x3A: ("ABX",   INH,  0),
    0x3B: ("RTI",   INH,  0), 0x3C: ("CWAI",  IMM8, 1),
    0x3D: ("MUL",   INH,  0), 0x3F: ("SWI",   INH,  0),

    0x40: ("NEGA",  INH,  0), 0x43: ("COMA",  INH,  0), 0x44: ("LSRA",  INH,  0),
    0x46: ("RORA",  INH,  0), 0x47: ("ASRA",  INH,  0), 0x48: ("ASLA",  INH,  0),
    0x49: ("ROLA",  INH,  0), 0x4A: ("DECA",  INH,  0), 0x4C: ("INCA",  INH,  0),
    0x4D: ("TSTA",  INH,  0), 0x4F: ("CLRA",  INH,  0),

    0x50: ("NEGB",  INH,  0), 0x53: ("COMB",  INH,  0), 0x54: ("LSRB",  INH,  0),
    0x56: ("RORB",  INH,  0), 0x57: ("ASRB",  INH,  0), 0x58: ("ASLB",  INH,  0),
    0x59: ("ROLB",  INH,  0), 0x5A: ("DECB",  INH,  0), 0x5C: ("INCB",  INH,  0),
    0x5D: ("TSTB",  INH,  0), 0x5F: ("CLRB",  INH,  0),

    0x60: ("NEG",   IDX,  None), 0x63: ("COM",   IDX,  None),
    0x64: ("LSR",   IDX,  None), 0x66: ("ROR",   IDX,  None),
    0x67: ("ASR",   IDX,  None), 0x68: ("ASL",   IDX,  None),
    0x69: ("ROL",   IDX,  None), 0x6A: ("DEC",   IDX,  None),
    0x6C: ("INC",   IDX,  None), 0x6D: ("TST",   IDX,  None),
    0x6E: ("JMP",   IDX,  None), 0x6F: ("CLR",   IDX,  None),

    0x70: ("NEG",   EXT,  2), 0x73: ("COM",   EXT,  2), 0x74: ("LSR",   EXT,  2),
    0x76: ("ROR",   EXT,  2), 0x77: ("ASR",   EXT,  2), 0x78: ("ASL",   EXT,  2),
    0x79: ("ROL",   EXT,  2), 0x7A: ("DEC",   EXT,  2), 0x7C: ("INC",   EXT,  2),
    0x7D: ("TST",   EXT,  2), 0x7E: ("JMP",   EXT,  2), 0x7F: ("CLR",   EXT,  2),

    0x80: ("SUBA",  IMM8, 1), 0x81: ("CMPA",  IMM8, 1), 0x82: ("SBCA",  IMM8, 1),
    0x83: ("SUBD",  IMM16,2), 0x84: ("ANDA",  IMM8, 1), 0x85: ("BITA",  IMM8, 1),
    0x86: ("LDA",   IMM8, 1), 0x88: ("EORA",  IMM8, 1), 0x89: ("ADCA",  IMM8, 1),
    0x8A: ("ORA",   IMM8, 1), 0x8B: ("ADDA",  IMM8, 1), 0x8C: ("CMPX",  IMM16,2),
    0x8D: ("BSR",   REL8, 1), 0x8E: ("LDX",   IMM16,2),

    0x90: ("SUBA",  DIR,  1), 0x91: ("CMPA",  DIR,  1), 0x92: ("SBCA",  DIR,  1),
    0x93: ("SUBD",  DIR,  1), 0x94: ("ANDA",  DIR,  1), 0x95: ("BITA",  DIR,  1),
    0x96: ("LDA",   DIR,  1), 0x97: ("STA",   DIR,  1), 0x98: ("EORA",  DIR,  1),
    0x99: ("ADCA",  DIR,  1), 0x9A: ("ORA",   DIR,  1), 0x9B: ("ADDA",  DIR,  1),
    0x9C: ("CMPX",  DIR,  1), 0x9D: ("JSR",   DIR,  1), 0x9E: ("LDX",   DIR,  1),
    0x9F: ("STX",   DIR,  1),

    0xA0: ("SUBA",  IDX,  None), 0xA1: ("CMPA",  IDX,  None),
    0xA2: ("SBCA",  IDX,  None), 0xA3: ("SUBD",  IDX,  None),
    0xA4: ("ANDA",  IDX,  None), 0xA5: ("BITA",  IDX,  None),
    0xA6: ("LDA",   IDX,  None), 0xA7: ("STA",   IDX,  None),
    0xA8: ("EORA",  IDX,  None), 0xA9: ("ADCA",  IDX,  None),
    0xAA: ("ORA",   IDX,  None), 0xAB: ("ADDA",  IDX,  None),
    0xAC: ("CMPX",  IDX,  None), 0xAD: ("JSR",   IDX,  None),
    0xAE: ("LDX",   IDX,  None), 0xAF: ("STX",   IDX,  None),

    0xB0: ("SUBA",  EXT,  2), 0xB1: ("CMPA",  EXT,  2), 0xB2: ("SBCA",  EXT,  2),
    0xB3: ("SUBD",  EXT,  2), 0xB4: ("ANDA",  EXT,  2), 0xB5: ("BITA",  EXT,  2),
    0xB6: ("LDA",   EXT,  2), 0xB7: ("STA",   EXT,  2), 0xB8: ("EORA",  EXT,  2),
    0xB9: ("ADCA",  EXT,  2), 0xBA: ("ORA",   EXT,  2), 0xBB: ("ADDA",  EXT,  2),
    0xBC: ("CMPX",  EXT,  2), 0xBD: ("JSR",   EXT,  2), 0xBE: ("LDX",   EXT,  2),
    0xBF: ("STX",   EXT,  2),

    0xC0: ("SUBB",  IMM8, 1), 0xC1: ("CMPB",  IMM8, 1), 0xC2: ("SBCB",  IMM8, 1),
    0xC3: ("ADDD",  IMM16,2), 0xC4: ("ANDB",  IMM8, 1), 0xC5: ("BITB",  IMM8, 1),
    0xC6: ("LDB",   IMM8, 1), 0xC8: ("EORB",  IMM8, 1), 0xC9: ("ADCB",  IMM8, 1),
    0xCA: ("ORB",   IMM8, 1), 0xCB: ("ADDB",  IMM8, 1), 0xCC: ("LDD",   IMM16,2),
    0xCE: ("LDU",   IMM16,2),

    0xD0: ("SUBB",  DIR,  1), 0xD1: ("CMPB",  DIR,  1), 0xD2: ("SBCB",  DIR,  1),
    0xD3: ("ADDD",  DIR,  1), 0xD4: ("ANDB",  DIR,  1), 0xD5: ("BITB",  DIR,  1),
    0xD6: ("LDB",   DIR,  1), 0xD7: ("STB",   DIR,  1), 0xD8: ("EORB",  DIR,  1),
    0xD9: ("ADCB",  DIR,  1), 0xDA: ("ORB",   DIR,  1), 0xDB: ("ADDB",  DIR,  1),
    0xDC: ("LDD",   DIR,  1), 0xDD: ("STD",   DIR,  1), 0xDE: ("LDU",   DIR,  1),
    0xDF: ("STU",   DIR,  1),

    0xE0: ("SUBB",  IDX,  None), 0xE1: ("CMPB",  IDX,  None),
    0xE2: ("SBCB",  IDX,  None), 0xE3: ("ADDD",  IDX,  None),
    0xE4: ("ANDB",  IDX,  None), 0xE5: ("BITB",  IDX,  None),
    0xE6: ("LDB",   IDX,  None), 0xE7: ("STB",   IDX,  None),
    0xE8: ("EORB",  IDX,  None), 0xE9: ("ADCB",  IDX,  None),
    0xEA: ("ORB",   IDX,  None), 0xEB: ("ADDB",  IDX,  None),
    0xEC: ("LDD",   IDX,  None), 0xED: ("STD",   IDX,  None),
    0xEE: ("LDU",   IDX,  None), 0xEF: ("STU",   IDX,  None),

    0xF0: ("SUBB",  EXT,  2), 0xF1: ("CMPB",  EXT,  2), 0xF2: ("SBCB",  EXT,  2),
    0xF3: ("ADDD",  EXT,  2), 0xF4: ("ANDB",  EXT,  2), 0xF5: ("BITB",  EXT,  2),
    0xF6: ("LDB",   EXT,  2), 0xF7: ("STB",   EXT,  2), 0xF8: ("EORB",  EXT,  2),
    0xF9: ("ADCB",  EXT,  2), 0xFA: ("ORB",   EXT,  2), 0xFB: ("ADDB",  EXT,  2),
    0xFC: ("LDD",   EXT,  2), 0xFD: ("STD",   EXT,  2), 0xFE: ("LDU",   EXT,  2),
    0xFF: ("STU",   EXT,  2),
}

OPCODES_PAGE2 = {
    0x21: ("LBRN",  REL16, 2), 0x22: ("LBHI",  REL16, 2), 0x23: ("LBLS",  REL16, 2),
    0x24: ("LBCC",  REL16, 2), 0x25: ("LBCS",  REL16, 2), 0x26: ("LBNE",  REL16, 2),
    0x27: ("LBEQ",  REL16, 2), 0x28: ("LBVC",  REL16, 2), 0x29: ("LBVS",  REL16, 2),
    0x2A: ("LBPL",  REL16, 2), 0x2B: ("LBMI",  REL16, 2), 0x2C: ("LBGE",  REL16, 2),
    0x2D: ("LBLT",  REL16, 2), 0x2E: ("LBGT",  REL16, 2), 0x2F: ("LBLE",  REL16, 2),
    0x3F: ("SWI2",  INH,  0),
    0x83: ("CMPD",  IMM16,2), 0x8C: ("CMPY",  IMM16,2), 0x8E: ("LDY",   IMM16,2),
    0x93: ("CMPD",  DIR,  1), 0x9C: ("CMPY",  DIR,  1), 0x9E: ("LDY",   DIR,  1),
    0x9F: ("STY",   DIR,  1),
    0xA3: ("CMPD",  IDX,  None), 0xAC: ("CMPY",  IDX,  None),
    0xAE: ("LDY",   IDX,  None), 0xAF: ("STY",   IDX,  None),
    0xB3: ("CMPD",  EXT,  2), 0xBC: ("CMPY",  EXT,  2),
    0xBE: ("LDY",   EXT,  2), 0xBF: ("STY",   EXT,  2),
    0xCE: ("LDS",   IMM16,2),
    0xDE: ("LDS",   DIR,  1), 0xDF: ("STS",   DIR,  1),
    0xEE: ("LDS",   IDX,  None), 0xEF: ("STS",   IDX,  None),
    0xFE: ("LDS",   EXT,  2), 0xFF: ("STS",   EXT,  2),
}

OPCODES_PAGE3 = {
    0x3F: ("SWI3",  INH,  0),
    0x83: ("CMPU",  IMM16,2), 0x8C: ("CMPS",  IMM16,2),
    0x93: ("CMPU",  DIR,  1), 0x9C: ("CMPS",  DIR,  1),
    0xA3: ("CMPU",  IDX,  None), 0xAC: ("CMPS",  IDX,  None),
    0xB3: ("CMPU",  EXT,  2), 0xBC: ("CMPS",  EXT,  2),
}

# ===========================================================================
# INDEXED ADDRESSING MODE DECODER
# ===========================================================================

REGISTER_NAMES = {0: "X", 1: "Y", 2: "U", 3: "S"}

def decode_indexed(data: bytes, offset: int) -> tuple:
    """Decode 6809 indexed addressing postbyte. Returns (text, bytes_consumed)."""
    if offset >= len(data):
        return ("???", 1)

    postbyte = data[offset]
    reg = REGISTER_NAMES.get((postbyte >> 5) & 0x03, "?")

    if not (postbyte & 0x80):
        off5 = postbyte & 0x1F
        if off5 & 0x10:
            off5 = off5 - 32
        if off5 == 0:
            return (f",{reg}", 1)
        return (f"{off5},{reg}", 1)

    mode = postbyte & 0x1F
    indirect = bool(postbyte & 0x10) and (mode & 0x01)

    consumed = 1
    text = ""

    if mode == 0x00:
        text = f",{reg}+"
    elif mode == 0x01:
        text = f",{reg}++"
    elif mode == 0x02:
        text = f",-{reg}"
    elif mode == 0x03:
        text = f",--{reg}"
    elif mode == 0x04:
        text = f",{reg}"
    elif mode == 0x05:
        text = f"B,{reg}"
    elif mode == 0x06:
        text = f"A,{reg}"
    elif mode == 0x08:
        if offset + 1 < len(data):
            off8 = data[offset + 1]
            if off8 & 0x80:
                off8 = off8 - 256
            text = f"{off8},{reg}"
            consumed = 2
        else:
            text = f"?,{reg}"
    elif mode == 0x09:
        if offset + 2 < len(data):
            off16 = (data[offset + 1] << 8) | data[offset + 2]
            if off16 & 0x8000:
                off16 = off16 - 65536
            text = f"${off16 & 0xFFFF:04X},{reg}"
            consumed = 3
        else:
            text = f"?,{reg}"
    elif mode == 0x0B:
        text = f"D,{reg}"
    elif mode == 0x0C:
        if offset + 1 < len(data):
            off8 = data[offset + 1]
            if off8 & 0x80:
                off8 = off8 - 256
            text = f"{off8},PCR"
            consumed = 2
        else:
            text = f"?,PCR"
    elif mode == 0x0D:
        if offset + 2 < len(data):
            off16 = (data[offset + 1] << 8) | data[offset + 2]
            if off16 & 0x8000:
                off16 = off16 - 65536
            text = f"${off16 & 0xFFFF:04X},PCR"
            consumed = 3
        else:
            text = f"?,PCR"
    elif mode == 0x1F:
        if offset + 2 < len(data):
            addr = (data[offset + 1] << 8) | data[offset + 2]
            text = f"[${addr:04X}]"
            consumed = 3
            return (text, consumed)
        else:
            text = "[?]"
    else:
        text = f"<idx:{postbyte:02X}>"

    if indirect and mode not in (0x00, 0x02):
        text = f"[{text}]"

    return (text, consumed)


# ===========================================================================
# PUSH/PULL / TFR/EXG DECODERS
# ===========================================================================

PUSH_REGS_S = {0x01: "CC", 0x02: "A", 0x04: "B", 0x08: "DP",
               0x10: "X",  0x20: "Y", 0x40: "U", 0x80: "PC"}
PUSH_REGS_U = {0x01: "CC", 0x02: "A", 0x04: "B", 0x08: "DP",
               0x10: "X",  0x20: "Y", 0x40: "S", 0x80: "PC"}

def decode_push_pull(postbyte: int, use_s_stack: bool = True) -> str:
    regs = PUSH_REGS_S if use_s_stack else PUSH_REGS_U
    result = []
    for bit in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]:
        if postbyte & bit:
            result.append(regs[bit])
    return ",".join(result) if result else "??"

TFR_REGS = {
    0x0: "D",  0x1: "X",  0x2: "Y",  0x3: "U",
    0x4: "S",  0x5: "PC", 0x8: "A",  0x9: "B",
    0xA: "CC", 0xB: "DP",
}

def decode_tfr_exg(postbyte: int) -> str:
    src = TFR_REGS.get((postbyte >> 4) & 0x0F, "??")
    dst = TFR_REGS.get(postbyte & 0x0F, "??")
    return f"{src},{dst}"


# ===========================================================================
# KNOWN LABELS: ROM ENTRY POINTS + HARDWARE I/O (CoCo 1/2/3)
# ===========================================================================

ROM_LABELS = {
    0xA000: "BASIC_WARM",    0xA027: "CHROUT",      0xA176: "PUTCHR",
    0xA1B1: "LPRINT",        0xA1C1: "OUTCHR",      0xA282: "GETKEY",
    0xA35F: "PRNTCR",        0xA928: "POLCAT",       0xA59A: "CLS",
    0xA5C7: "SETGR",         0xA60C: "HPRINT",       0xA7D8: "JOYSTK",
    0xA8C5: "SOUND",         0xA974: "KEYIN",        0xAD19: "EXEC",
    0xAE38: "LNKBAS",        0xB44A: "CHKRST",       0xB4F0: "SNDOUT",
    0xB938: "DSKCON",        0xB95D: "DOSINI",       0xBC77: "GETFIL",
    0xBE6C: "DCNVEC",        0xC004: "DSKINI",
    # Super Extended BASIC (CoCo 3)
    0xE000: "SECB_ENTRY", 0xE004: "HSCREEN", 0xE007: "HCLS",
    0xE00A: "HCOLOR", 0xE00D: "HPSET", 0xE010: "HPRESET",
    0xE012: "HLINE", 0xE015: "HCIRCLE",
    0xE018: "HPAINT", 0xE01B: "HGET", 0xE01E: "HPUT",
    0xE021: "HBUFF", 0xE024: "HPRINT", 0xE027: "PALETTE",
    0xE02A: "RGB", 0xE02D: "WIDTH", 0xE030: "LOCATE",
    0xE033: "ATTR", 0xE036: "HPOINT", 0xE039: "HSTAT",
    0xE03C: "HDRAW", 0xE03F: "HPLAY",
}

# ROM entry point descriptions for --annotate mode
ROM_DESCRIPTIONS = {
    0xA000: "Warm start entry (OK prompt)",
    0xA027: "Output char in A to current device",
    0xA176: "Print character in A to screen",
    0xA1B1: "LPRINT - print to printer",
    0xA1C1: "Output character with device routing",
    0xA282: "Get keyboard input character",
    0xA35F: "Print carriage return",
    0xA59A: "Clear screen (text mode)",
    0xA5C7: "Set graphics/text mode",
    0xA60C: "Print hex value",
    0xA7D8: "Read joystick values",
    0xA8C5: "SOUND command (freq, duration)",
    0xA928: "Poll keyboard, Z=1 if no key",
    0xA974: "Key input with cursor blink",
    0xAD19: "EXEC command handler",
    0xAE38: "Re-link BASIC program lines",
    0xB44A: "Check for reset / error handler",
    0xB4F0: "Low-level sound output",
    0xB938: "Disk I/O control block handler",
    0xB95D: "DOS warm initialization",
    0xBC77: "Get filename from BASIC",
    0xBE6C: "DOS conversion vector",
    0xC004: "Initialize disk system",
    # Super Extended BASIC (CoCo 3)
    0xE000: "Super Extended BASIC cold start",
    0xE004: "Set hi-res screen mode (0-4)",
    0xE007: "Clear hi-res graphics screen",
    0xE00A: "Set hi-res foreground drawing color",
    0xE00D: "Set hi-res pixel",
    0xE010: "Reset hi-res pixel",
    0xE012: "Draw hi-res line",
    0xE015: "Draw hi-res circle",
    0xE018: "Hi-res flood fill",
    0xE01B: "Capture hi-res screen region to buffer",
    0xE01E: "Display buffer to hi-res screen",
    0xE021: "Allocate hi-res graphics buffer",
    0xE024: "Print text on hi-res screen",
    0xE027: "Set palette register value",
    0xE02A: "Set palette RGB color value",
    0xE02D: "Set text width (32/40/80)",
    0xE030: "Position cursor on hi-res text screen",
    0xE033: "Set text attributes (fg/bg color)",
    0xE036: "Read hi-res pixel color",
    0xE039: "Return hi-res screen status info",
    0xE03C: "Hi-res DRAW string commands",
    0xE03F: "Hi-res PLAY music string",
}


def rom_comment(addr: int) -> str:
    """Get ROM call description for annotated output."""
    if addr in ROM_DESCRIPTIONS:
        return f"; {ROM_DESCRIPTIONS[addr]}"
    return ""


# Hardware I/O addresses — CoCo 1/2/3
HW_LABELS = {
    # PIA 0 - keyboard / joystick
    0xFF00: "PIA0_DA",   0xFF01: "PIA0_CA",   0xFF02: "PIA0_DB",   0xFF03: "PIA0_CB",
    # PIA 1 - VDG / sound / cassette
    0xFF20: "PIA1_DA",   0xFF21: "PIA1_CA",   0xFF22: "PIA1_DB",   0xFF23: "PIA1_CB",
    # FDC - floppy disk controller
    0xFF40: "DSK_CMD",   0xFF41: "DSK_TRK",   0xFF42: "DSK_SEC",   0xFF43: "DSK_DAT",
    0xFF48: "DSK_CTL",
    # GIME registers (CoCo 3)
    0xFF90: "GIME_INIT0",  0xFF91: "GIME_INIT1",  0xFF92: "GIME_IRQEN",
    0xFF93: "GIME_FIRQEN", 0xFF94: "GIME_TMRHI",  0xFF95: "GIME_TMRLO",
    0xFF98: "GIME_VMODE",  0xFF99: "GIME_VRES",   0xFF9A: "GIME_BORDER",
    0xFF9B: "GIME_VSCRL",  0xFF9C: "GIME_VOFFHI", 0xFF9D: "GIME_VOFFLO",
    0xFF9E: "GIME_HOFFHI", 0xFF9F: "GIME_HOFFLO",
    # MMU registers (CoCo 3) — Task 0
    0xFFA0: "MMU_T0_P0",  0xFFA1: "MMU_T0_P1",  0xFFA2: "MMU_T0_P2",
    0xFFA3: "MMU_T0_P3",  0xFFA4: "MMU_T0_P4",  0xFFA5: "MMU_T0_P5",
    0xFFA6: "MMU_T0_P6",  0xFFA7: "MMU_T0_P7",
    # MMU registers — Task 1
    0xFFA8: "MMU_T1_P0",  0xFFA9: "MMU_T1_P1",  0xFFAA: "MMU_T1_P2",
    0xFFAB: "MMU_T1_P3",  0xFFAC: "MMU_T1_P4",  0xFFAD: "MMU_T1_P5",
    0xFFAE: "MMU_T1_P6",  0xFFAF: "MMU_T1_P7",
    # GIME palette registers (CoCo 3)
    0xFFB0: "PAL_0",  0xFFB1: "PAL_1",  0xFFB2: "PAL_2",  0xFFB3: "PAL_3",
    0xFFB4: "PAL_4",  0xFFB5: "PAL_5",  0xFFB6: "PAL_6",  0xFFB7: "PAL_7",
    0xFFB8: "PAL_8",  0xFFB9: "PAL_9",  0xFFBA: "PAL_10", 0xFFBB: "PAL_11",
    0xFFBC: "PAL_12", 0xFFBD: "PAL_13", 0xFFBE: "PAL_14", 0xFFBF: "PAL_15",
    # SAM registers
    0xFFC0: "SAM_V0CLR", 0xFFC1: "SAM_V0SET", 0xFFC2: "SAM_V1CLR",
    0xFFC3: "SAM_V1SET", 0xFFC4: "SAM_V2CLR", 0xFFC5: "SAM_V2SET",
    0xFFC6: "SAM_F0CLR", 0xFFC7: "SAM_F0SET",
    0xFFD4: "SAM_P1",
    0xFFD8: "SAM_R0CLR", 0xFFD9: "SAM_R0SET",
    0xFFDE: "SAM_ROMOFF", 0xFFDF: "SAM_ROMON",
}

# Hardware I/O descriptions — CoCo 3 GIME/MMU/Palette + SAM
HW_DESCRIPTIONS = {
    0xFF90: "Init 0: COCO|MMUEN|IEN|FEN|MC3-0",
    0xFF91: "Init 1: timer input, task select",
    0xFF92: "IRQ enable: TMR|HBORD|VBORD|EI2-0",
    0xFF93: "FIRQ enable: TMR|HBORD|VBORD|EI2-0",
    0xFF94: "Timer MSB (12-bit countdown)",
    0xFF95: "Timer LSB (12-bit countdown)",
    0xFF98: "Video mode: BP|BPI|MOCH|H50|LPR",
    0xFF99: "Video res: LPF|HRES|CRES",
    0xFF9A: "Border color (6-bit palette index)",
    0xFF9B: "Vertical scroll (4-bit)",
    0xFF9C: "Video offset MSB",
    0xFF9D: "Video offset LSB",
    0xFF9E: "Horizontal offset MSB",
    0xFF9F: "Horizontal offset LSB",
    # MMU Task 0
    0xFFA0: "Task0 page0 ($0000-$1FFF)", 0xFFA1: "Task0 page1 ($2000-$3FFF)",
    0xFFA2: "Task0 page2 ($4000-$5FFF)", 0xFFA3: "Task0 page3 ($6000-$7FFF)",
    0xFFA4: "Task0 page4 ($8000-$9FFF)", 0xFFA5: "Task0 page5 ($A000-$BFFF)",
    0xFFA6: "Task0 page6 ($C000-$DFFF)", 0xFFA7: "Task0 page7 ($E000-$FEFF)",
    # MMU Task 1
    0xFFA8: "Task1 page0 ($0000-$1FFF)", 0xFFA9: "Task1 page1 ($2000-$3FFF)",
    0xFFAA: "Task1 page2 ($4000-$5FFF)", 0xFFAB: "Task1 page3 ($6000-$7FFF)",
    0xFFAC: "Task1 page4 ($8000-$9FFF)", 0xFFAD: "Task1 page5 ($A000-$BFFF)",
    0xFFAE: "Task1 page6 ($C000-$DFFF)", 0xFFAF: "Task1 page7 ($E000-$FEFF)",
    # Palette
    **{0xFFB0 + i: f"Palette {i} (6-bit RGB)" for i in range(16)},
}


def hw_comment(addr: int) -> str:
    """Get hardware comment for I/O addresses."""
    if addr in HW_DESCRIPTIONS:
        label = HW_LABELS.get(addr, "")
        if label:
            return f"; {label} - {HW_DESCRIPTIONS[addr]}"
        return f"; {HW_DESCRIPTIONS[addr]}"
    if addr in HW_LABELS:
        return f"; {HW_LABELS[addr]}"
    if 0xFF00 <= addr <= 0xFF03:
        return "; PIA0 (keyboard/joystick)"
    if 0xFF20 <= addr <= 0xFF23:
        return "; PIA1 (VDG/sound/cassette)"
    if 0xFF40 <= addr <= 0xFF4F:
        return "; FDC (floppy disk controller)"
    if 0xFF90 <= addr <= 0xFF9F:
        return "; GIME register"
    if 0xFFA0 <= addr <= 0xFFAF:
        return "; MMU page register"
    if 0xFFB0 <= addr <= 0xFFBF:
        return "; GIME palette"
    if 0xFFC0 <= addr <= 0xFFDF:
        return "; SAM register"
    return ""


# ===========================================================================
# UNIFIED MEMORY IMAGE (solves cross-segment boundary problem)
# ===========================================================================

class MemoryImage:
    """Represents a sparse memory image built from DECB segments.
    Tracks which addresses are populated vs. gaps."""

    def __init__(self):
        self.data = bytearray(0x10000)  # 64K address space
        self.populated = bytearray(0x10000)  # 1 = byte loaded, 0 = gap
        self.segments = []  # list of (start, end) ranges

    def load_segment(self, addr: int, seg_data: bytes):
        end = addr + len(seg_data)
        for i, b in enumerate(seg_data):
            self.data[addr + i] = b
            self.populated[addr + i] = 1
        self.segments.append((addr, end - 1))

    def is_populated(self, addr: int) -> bool:
        return 0 <= addr < 0x10000 and self.populated[addr]

    def byte_at(self, addr: int) -> int:
        if 0 <= addr < 0x10000:
            return self.data[addr]
        return 0

    def get_contiguous_ranges(self) -> list:
        """Return list of (start, end) for contiguous populated regions."""
        ranges = []
        in_range = False
        start = 0
        for i in range(0x10000):
            if self.populated[i]:
                if not in_range:
                    start = i
                    in_range = True
            else:
                if in_range:
                    ranges.append((start, i - 1))
                    in_range = False
        if in_range:
            ranges.append((start, 0xFFFF))
        return ranges


# ===========================================================================
# DATA REGION DETECTOR
# ===========================================================================

def detect_data_regions(mem: MemoryImage, code_addrs: set, ranges: list) -> dict:
    """Heuristic detection of data regions within populated memory.

    Returns dict of addr -> 'string' | 'zero' | 'table' for known data areas.
    code_addrs = set of addresses confirmed as instruction starts from pass 1.
    """
    data_regions = {}  # addr -> type

    for rng_start, rng_end in ranges:
        addr = rng_start
        while addr <= rng_end:
            if addr in code_addrs:
                addr += 1
                continue

            # Detect ASCII strings (4+ printable chars)
            if 32 <= mem.byte_at(addr) <= 126:
                slen = 0
                a = addr
                while a <= rng_end and 32 <= mem.byte_at(a) <= 126:
                    slen += 1
                    a += 1
                if slen >= 4 and a not in code_addrs:
                    for i in range(addr, addr + slen):
                        data_regions[i] = 'string'
                    # Include null terminator if present
                    if a <= rng_end and mem.byte_at(a) == 0:
                        data_regions[a] = 'string'
                    addr = a
                    continue

            # Detect zero-fill regions (8+ consecutive zeros not in code)
            if mem.byte_at(addr) == 0:
                zlen = 0
                a = addr
                while a <= rng_end and mem.byte_at(a) == 0 and a not in code_addrs:
                    zlen += 1
                    a += 1
                if zlen >= 8:
                    for i in range(addr, addr + zlen):
                        data_regions[i] = 'zero'
                    addr = a
                    continue

            addr += 1

    return data_regions


# ===========================================================================
# MAIN DISASSEMBLER
# ===========================================================================

class Disassembler6809:
    def __init__(self, mem: MemoryImage, entry_addr: int = None):
        """Initialize with a unified MemoryImage.
        entry_addr: exec address or primary entry point (for labeling)."""
        self.mem = mem
        self.entry_addr = entry_addr
        self.labels: dict[int, str] = {}
        self.comments: dict[int, str] = {}
        self.lines: list[tuple] = []
        self.jump_targets: set[int] = set()
        self.call_targets: set[int] = set()
        self.code_addrs: set[int] = set()  # addresses that are instruction starts
        self.data_regions: dict[int, str] = {}

    def addr_label(self, addr: int) -> str:
        if addr in ROM_LABELS:
            return ROM_LABELS[addr]
        if addr in HW_LABELS:
            return HW_LABELS[addr]
        if addr in self.labels:
            return self.labels[addr]
        return f"${addr:04X}"

    def add_target_label(self, addr: int, is_call: bool = False):
        if is_call:
            self.call_targets.add(addr)
            if addr not in ROM_LABELS and addr not in HW_LABELS:
                self.labels.setdefault(addr, f"SUB_{addr:04X}")
        else:
            self.jump_targets.add(addr)
            if addr not in ROM_LABELS and addr not in HW_LABELS:
                self.labels.setdefault(addr, f"L_{addr:04X}")

    def _read_byte(self, addr: int) -> Optional[int]:
        if self.mem.is_populated(addr):
            return self.mem.byte_at(addr)
        return None

    def disassemble_instruction(self, pc: int) -> tuple:
        """Disassemble one instruction at absolute address pc.
        Returns (mnemonic, operand, bytes_consumed, comment)."""
        b0 = self._read_byte(pc)
        if b0 is None:
            return ("FCB", "$??", 1, "; unpopulated")

        page_table = OPCODES_PAGE1
        prefix_bytes = 0

        if b0 == 0x10 and self._read_byte(pc + 1) is not None:
            page_table = OPCODES_PAGE2
            prefix_bytes = 1
            b0 = self.mem.byte_at(pc + 1)
        elif b0 == 0x11 and self._read_byte(pc + 1) is not None:
            page_table = OPCODES_PAGE3
            prefix_bytes = 1
            b0 = self.mem.byte_at(pc + 1)

        if b0 not in page_table:
            return ("FCB", f"${self.mem.byte_at(pc):02X}", 1, "; unknown opcode")

        mnemonic, mode, extra = page_table[b0]
        consumed = 1 + prefix_bytes
        operand = ""
        comment = ""
        data_addr = pc + consumed

        if mode == INH:
            pass

        elif mode == IMM8:
            val = self._read_byte(data_addr)
            if val is not None:
                consumed += 1
                if mnemonic in ("PSHS", "PULS"):
                    operand = decode_push_pull(val, use_s_stack=True)
                elif mnemonic in ("PSHU", "PULU"):
                    operand = decode_push_pull(val, use_s_stack=False)
                elif mnemonic in ("TFR", "EXG"):
                    operand = decode_tfr_exg(val)
                else:
                    operand = f"#${val:02X}"

        elif mode == IMM16:
            b1 = self._read_byte(data_addr)
            b2 = self._read_byte(data_addr + 1)
            if b1 is not None and b2 is not None:
                val = (b1 << 8) | b2
                consumed += 2
                operand = f"#${val:04X}"

        elif mode == DIR:
            val = self._read_byte(data_addr)
            if val is not None:
                consumed += 1
                operand = f"<${val:02X}"

        elif mode == EXT:
            b1 = self._read_byte(data_addr)
            b2 = self._read_byte(data_addr + 1)
            if b1 is not None and b2 is not None:
                addr = (b1 << 8) | b2
                consumed += 2
                label = self.addr_label(addr)
                operand = label
                comment = hw_comment(addr)
                if mnemonic in ("JSR",):
                    self.add_target_label(addr, is_call=True)
                elif mnemonic in ("JMP",):
                    self.add_target_label(addr, is_call=False)

        elif mode == IDX:
            # Build a temporary bytes buffer from memory for the indexed decoder
            idx_buf = bytes([self.mem.byte_at(data_addr + i) for i in range(4)
                             if self._read_byte(data_addr + i) is not None])
            if idx_buf:
                idx_text, idx_consumed = decode_indexed(idx_buf, 0)
                consumed += idx_consumed
                operand = idx_text
            else:
                consumed += 1
                operand = "???"

        elif mode == REL8:
            val = self._read_byte(data_addr)
            if val is not None:
                off8 = val if val < 128 else val - 256
                consumed += 1
                target = pc + consumed + off8
                self.add_target_label(target, is_call=(mnemonic == "BSR"))
                operand = self.addr_label(target)

        elif mode == REL16:
            b1 = self._read_byte(data_addr)
            b2 = self._read_byte(data_addr + 1)
            if b1 is not None and b2 is not None:
                off16 = (b1 << 8) | b2
                if off16 & 0x8000:
                    off16 = off16 - 65536
                consumed += 2
                target = pc + consumed + off16
                self.add_target_label(target, is_call=(mnemonic in ("LBSR",)))
                operand = self.addr_label(target)

        return (mnemonic, operand, consumed, comment)

    def disassemble(self, show_hex: bool = True, annotate: bool = False) -> str:
        """Full two-pass disassembly of all populated ranges."""
        ranges = self.mem.get_contiguous_ranges()

        # Pass 1: scan all code to find labels and detect backward branches
        self.backward_branches = set()  # PCs of backward branch instructions
        for rng_start, rng_end in ranges:
            pc = rng_start
            while pc <= rng_end:
                mnemonic, operand, consumed, _ = self.disassemble_instruction(pc)
                self.code_addrs.add(pc)
                # Track backward branches for loop detection
                if annotate and mnemonic in ("BNE", "BEQ", "BCC", "BCS", "BHI", "BLS",
                        "BPL", "BMI", "BGE", "BLT", "BGT", "BLE", "BVC", "BVS",
                        "BRA", "LBNE", "LBEQ", "LBCC", "LBCS", "LBHI", "LBLS",
                        "LBPL", "LBMI", "LBGE", "LBLT", "LBGT", "LBLE", "LBVC", "LBVS", "LBRA"):
                    target = self._resolve_branch_target(operand)
                    if target is not None and target < pc:
                        self.backward_branches.add(pc)
                pc += consumed

        # Detect data regions
        self.data_regions = detect_data_regions(self.mem, self.code_addrs, ranges)

        # Pass 2: generate output, respecting data regions
        self.lines = []
        for rng_start, rng_end in ranges:
            pc = rng_start
            while pc <= rng_end:
                # Check if this is a data region
                if pc in self.data_regions:
                    dtype = self.data_regions[pc]
                    if dtype == 'string':
                        # Emit FCC for string run
                        s_start = pc
                        chars = []
                        while pc <= rng_end and self.data_regions.get(pc) == 'string' and self.mem.byte_at(pc) >= 32:
                            chars.append(chr(self.mem.byte_at(pc)))
                            pc += 1
                        if chars:
                            text = ''.join(chars)
                            hex_b = ' '.join(f'{ord(c):02X}' for c in text[:6])
                            self.lines.append((s_start, hex_b, "FCC", f'"{text}"', "; ASCII string"))
                        # Null terminator
                        if pc <= rng_end and self.data_regions.get(pc) == 'string' and self.mem.byte_at(pc) == 0:
                            self.lines.append((pc, "00", "FCB", "$00", "; null terminator"))
                            pc += 1
                        continue
                    elif dtype == 'zero':
                        z_start = pc
                        z_count = 0
                        while pc <= rng_end and self.data_regions.get(pc) == 'zero':
                            z_count += 1
                            pc += 1
                        self.lines.append((z_start, "00 ...", "RMB", str(z_count), f"; {z_count} zero bytes"))
                        continue

                # Normal instruction disassembly
                mnemonic, operand, consumed, comment = self.disassemble_instruction(pc)
                # In annotate mode, add ROM call descriptions and loop markers
                if annotate:
                    if mnemonic in ("JSR", "BSR", "LBSR") and not comment:
                        target = self._resolve_branch_target(operand)
                        if target is not None:
                            rc = rom_comment(target)
                            if rc:
                                comment = rc
                    if pc in self.backward_branches and not comment:
                        comment = "; loop back"
                    elif pc in self.backward_branches and comment:
                        comment += " (loop)"
                hex_bytes = " ".join(f"{self.mem.byte_at(pc+i):02X}" for i in range(consumed)
                                     if self.mem.is_populated(pc+i))
                self.lines.append((pc, hex_bytes, mnemonic, operand, comment))
                pc += consumed

        return self._format_output(show_hex, annotate)

    def _resolve_branch_target(self, operand: str) -> Optional[int]:
        """Resolve an operand to an absolute address."""
        if operand.startswith("$") and len(operand) == 5:
            try:
                return int(operand[1:], 16)
            except ValueError:
                pass
        for addr, label in ROM_LABELS.items():
            if operand == label:
                return addr
        for addr, label in self.labels.items():
            if operand == label:
                return addr
        return None

    def _format_output(self, show_hex: bool = True, annotate: bool = False) -> str:
        out = []

        # Header: EQU definitions for ROM calls found
        found_rom_calls = sorted(self.call_targets & set(ROM_LABELS.keys()))
        if found_rom_calls:
            out.append("; =============================================")
            out.append("; ROM Entry Points Used")
            out.append("; =============================================")
            for addr in found_rom_calls:
                desc = f"  ; {ROM_DESCRIPTIONS[addr]}" if annotate and addr in ROM_DESCRIPTIONS else ""
                out.append(f"{ROM_LABELS[addr]:16s} EQU    ${addr:04X}{desc}")
            out.append("")

        # Hardware EQUs
        found_hw = set()
        for (pc, hx, mn, op, cm) in self.lines:
            for addr, label in HW_LABELS.items():
                if label in op:
                    found_hw.add(addr)
        if found_hw:
            out.append("; =============================================")
            out.append("; Hardware I/O Addresses")
            out.append("; =============================================")
            for addr in sorted(found_hw):
                out.append(f"{HW_LABELS[addr]:16s} EQU    ${addr:04X}")
            out.append("")

        # Segments info
        ranges = self.mem.get_contiguous_ranges()
        out.append("; =============================================")
        out.append(f"; Memory ranges: {len(ranges)}")
        for s, e in ranges:
            out.append(f";   ${s:04X}-${e:04X} ({e - s + 1} bytes)")
        if self.entry_addr is not None:
            out.append(f"; Entry: ${self.entry_addr:04X}")
        out.append("; =============================================")
        out.append("")

        prev_end = None
        prev_was_data = False
        for (pc, hex_bytes, mnemonic, operand, comment) in self.lines:
            # Insert ORG directive when there's a gap
            if prev_end is not None and pc > prev_end + 1:
                out.append("")
                out.append(f"                 ORG    ${pc:04X}")
                out.append("")
            elif prev_end is None:
                out.append(f"                 ORG    ${pc:04X}")
                out.append("")

            # Label
            label_str = ""
            if pc in self.labels:
                label_str = self.labels[pc]
            elif pc in ROM_LABELS:
                label_str = ROM_LABELS[pc]

            # Annotate mode: subroutine separators and data region headers
            if annotate:
                is_data = mnemonic in ("FCC", "FCB", "FDB", "RMB")
                # Subroutine separator
                if label_str and label_str.startswith("SUB_"):
                    out.append("")
                    out.append(f"; ---- {label_str} ----")
                # Data region header (transition from code to data)
                if is_data and not prev_was_data:
                    if mnemonic == "FCC":
                        out.append("; ---- Data: ASCII string ----")
                    elif mnemonic == "RMB":
                        out.append(f"; ---- Data: zero-fill ({operand} bytes) ----")
                    else:
                        out.append("; ---- Data ----")
                prev_was_data = is_data

            # Instruction text
            if operand:
                instr = f"{mnemonic:8s}{operand}"
            else:
                instr = mnemonic

            if show_hex:
                if label_str:
                    out.append(f"{label_str}:")
                out.append(f"  {pc:04X}  {hex_bytes:16s}  {instr:30s}{comment}")
            else:
                if label_str:
                    line = f"{label_str:16s} {instr:30s}{comment}"
                else:
                    line = f"{'':16s} {instr:30s}{comment}"
                out.append(line)

            # Track end for gap detection
            # Estimate instruction length from hex dump
            byte_count = len(hex_bytes.replace("...", "").split())
            prev_end = pc + max(byte_count, 1) - 1

        if self.entry_addr is not None:
            out.append("")
            out.append(f"                 END    ${self.entry_addr:04X}")

        return "\n".join(out)


# ===========================================================================
# DECB BIN FILE LOADER
# ===========================================================================

def load_decb_bin(data: bytes) -> tuple:
    """Parse RS-DOS DECB BIN format.
    Returns (list of (org, data) segments, exec_addr)."""
    segments = []
    exec_addr = None
    pos = 0

    while pos < len(data):
        if data[pos] == 0x00:
            if pos + 4 >= len(data):
                break
            length = (data[pos+1] << 8) | data[pos+2]
            addr = (data[pos+3] << 8) | data[pos+4]
            pos += 5
            seg_data = data[pos:pos+length]
            segments.append((addr, seg_data))
            pos += length
        elif data[pos] == 0xFF:
            if pos + 4 < len(data):
                exec_addr = (data[pos+3] << 8) | data[pos+4]
            break
        else:
            break

    return segments, exec_addr


# ===========================================================================
# CLI ENTRY POINT
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(description="MC6809 Disassembler for CoCo")
    parser.add_argument("file", help="Binary file to disassemble")
    parser.add_argument("--org", type=lambda x: int(x, 0), default=None,
                        help="Origin address (hex, e.g. 0x0E00). Auto-detected for DECB BIN.")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument("--no-hex", action="store_true", help="Omit hex dump column")
    parser.add_argument("--raw", action="store_true",
                        help="Treat as raw binary (skip DECB format detection)")
    parser.add_argument("--annotate", action="store_true",
                        help="Enhanced output: subroutine separators, ROM call descriptions, loop markers")
    args = parser.parse_args()

    with open(args.file, "rb") as f:
        raw = f.read()

    mem = MemoryImage()
    exec_addr = None

    if not args.raw and len(raw) > 5 and raw[0] in (0x00, 0xFF):
        segments, exec_addr = load_decb_bin(raw)
        if segments:
            print(f"; DECB BIN format — {len(segments)} segment(s)", file=sys.stderr)
            if exec_addr is not None:
                print(f"; Exec address: ${exec_addr:04X}", file=sys.stderr)
            for i, (seg_org, seg_data) in enumerate(segments):
                print(f";   Segment {i}: ${seg_org:04X}-${seg_org+len(seg_data)-1:04X} ({len(seg_data)} bytes)", file=sys.stderr)
                mem.load_segment(seg_org, seg_data)
        else:
            # Not valid DECB, treat as raw
            org = args.org if args.org is not None else 0x0E00
            mem.load_segment(org, raw)
    else:
        org = args.org if args.org is not None else 0x0E00
        mem.load_segment(org, raw)

    dasm = Disassembler6809(mem, entry_addr=exec_addr)
    output = dasm.disassemble(show_hex=not args.no_hex, annotate=args.annotate)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Output written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
