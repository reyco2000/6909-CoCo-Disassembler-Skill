#!/usr/bin/env python3
"""
dasm6309.py - Recursive-descent HD6309/MC6809 disassembler for CoCo memory images.

Unlike dasm6809.py (linear sweep over every populated byte), this follows
control flow from one or more entry points, so it copes with 64K memory
snapshots where code is interleaved with graphics/level data. Unreached bytes
are emitted as FCB/RMB data. Supports the full HD6309 instruction set
(W/E/F/Q/V registers, TFM, bit ops, OIM/AIM/EIM/TIM, DIVD/DIVQ/MULD, W index
modes) and all 6809 indirect indexed modes.

Output lines use the same "  ADDR  HEX  MNEM OPERAND" layout as dasm6809.py so
annotator.py --split/--annotate/--merge work unchanged. With --sections it also
writes an xref.py-compatible section map (chunks split at subroutine starts).

Usage:
  dasm6309.py image.bin --org 0 --entry 0xFD00 [--entry 0x....] \
      --output game.asm --sections game_sections.json --max-chunks 10
"""
import argparse, json, sys, os
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dasm6809 import HW_LABELS, ROM_LABELS, hw_comment  # reuse CoCo label tables

INH, IMM8, IMM16, IMM32, DIR, EXT, IDX, REL8, REL16 = range(9)
REGOP, TFM, BITOP, MEMI_DIR, MEMI_IDX, MEMI_EXT, PSH = range(9, 16)

def _rows(table, names, modes):
    """Fill table from parallel opcode->name rows for the four addressing columns."""
    for base, mode in modes:
        for lo, name in names.items():
            if name:
                table[base + lo] = (name, mode)

P1, P2, P3 = {}, {}, {}

# ---- page 1 -----------------------------------------------------------------
_mem = {0x0: "NEG", 0x1: "OIM", 0x2: "AIM", 0x3: "COM", 0x4: "LSR", 0x5: "EIM", 0x6: "ROR",
        0x7: "ASR", 0x8: "ASL", 0x9: "ROL", 0xA: "DEC", 0xB: "TIM", 0xC: "INC", 0xD: "TST",
        0xE: "JMP", 0xF: "CLR"}
for lo, n in _mem.items():
    if n in ("OIM", "AIM", "EIM", "TIM"):
        P1[0x00 + lo] = (n, MEMI_DIR); P1[0x60 + lo] = (n, MEMI_IDX); P1[0x70 + lo] = (n, MEMI_EXT)
    else:
        P1[0x00 + lo] = (n, DIR); P1[0x60 + lo] = (n, IDX); P1[0x70 + lo] = (n, EXT)
P1.update({0x12: ("NOP", INH), 0x13: ("SYNC", INH), 0x14: ("SEXW", INH), 0x16: ("LBRA", REL16),
           0x17: ("LBSR", REL16), 0x19: ("DAA", INH), 0x1A: ("ORCC", IMM8), 0x1C: ("ANDCC", IMM8),
           0x1D: ("SEX", INH), 0x1E: ("EXG", REGOP), 0x1F: ("TFR", REGOP),
           0x30: ("LEAX", IDX), 0x31: ("LEAY", IDX), 0x32: ("LEAS", IDX), 0x33: ("LEAU", IDX),
           0x34: ("PSHS", PSH), 0x35: ("PULS", PSH), 0x36: ("PSHU", PSH), 0x37: ("PULU", PSH),
           0x39: ("RTS", INH), 0x3A: ("ABX", INH), 0x3B: ("RTI", INH), 0x3C: ("CWAI", IMM8),
           0x3D: ("MUL", INH), 0x3F: ("SWI", INH), 0x8D: ("BSR", REL8), 0xCD: ("LDQ", IMM32)})
_br = ["BRA", "BRN", "BHI", "BLS", "BCC", "BCS", "BNE", "BEQ", "BVC", "BVS", "BPL", "BMI",
       "BGE", "BLT", "BGT", "BLE"]
for i, n in enumerate(_br):
    P1[0x20 + i] = (n, REL8)
for lo, n in {0x0: "NEG", 0x3: "COM", 0x4: "LSR", 0x6: "ROR", 0x7: "ASR", 0x8: "ASL", 0x9: "ROL",
              0xA: "DEC", 0xC: "INC", 0xD: "TST", 0xF: "CLR"}.items():
    P1[0x40 + lo] = (n + "A", INH); P1[0x50 + lo] = (n + "B", INH)
_acc = {0x0: "SUB", 0x1: "CMP", 0x2: "SBC", 0x4: "AND", 0x5: "BIT", 0x6: "LD", 0x7: "ST",
        0x8: "EOR", 0x9: "ADC", 0xA: "OR", 0xB: "ADD"}
for lo, n in _acc.items():
    for reg, base in (("A", 0x80), ("B", 0xC0)):
        if n != "ST":
            P1[base + lo] = (n + reg, IMM8)
        P1[base + 0x10 + lo] = (n + reg, DIR)
        P1[base + 0x20 + lo] = (n + reg, IDX)
        P1[base + 0x30 + lo] = (n + reg, EXT)
for lo, (n, imm) in {0x3: ("SUBD", True), 0xC: ("CMPX", True), 0xE: ("LDX", True), 0xF: ("STX", False),
                     0xD: ("JSR", False)}.items():
    if imm:
        P1[0x80 + lo] = (n, IMM16)
    P1[0x90 + lo] = (n, DIR); P1[0xA0 + lo] = (n, IDX); P1[0xB0 + lo] = (n, EXT)
P1[0x8D] = ("BSR", REL8)
for lo, (n, imm) in {0x3: ("ADDD", True), 0xC: ("LDD", True), 0xD: ("STD", False),
                     0xE: ("LDU", True), 0xF: ("STU", False)}.items():
    if imm:
        P1[0xC0 + lo] = (n, IMM16)
    P1[0xD0 + lo] = (n, DIR); P1[0xE0 + lo] = (n, IDX); P1[0xF0 + lo] = (n, EXT)
P1[0xCD] = ("LDQ", IMM32)

# ---- page 2 ($10) -------------------------------------------------------------
for i, n in enumerate(_br):
    if i:
        P2[0x20 + i] = ("L" + n, REL16)
P2.update({0x30: ("ADDR", REGOP), 0x31: ("ADCR", REGOP), 0x32: ("SUBR", REGOP), 0x33: ("SBCR", REGOP),
           0x34: ("ANDR", REGOP), 0x35: ("ORR", REGOP), 0x36: ("EORR", REGOP), 0x37: ("CMPR", REGOP),
           0x38: ("PSHSW", INH), 0x39: ("PULSW", INH), 0x3A: ("PSHUW", INH), 0x3B: ("PULUW", INH),
           0x3F: ("SWI2", INH)})
for lo, n in {0x0: "NEG", 0x3: "COM", 0x4: "LSR", 0x6: "ROR", 0x7: "ASR", 0x8: "ASL", 0x9: "ROL",
              0xA: "DEC", 0xC: "INC", 0xD: "TST", 0xF: "CLR"}.items():
    P2[0x40 + lo] = (n + "D", INH)
for lo, n in {0x3: "COM", 0x4: "LSR", 0x6: "ROR", 0x9: "ROL", 0xA: "DEC", 0xC: "INC", 0xD: "TST",
              0xF: "CLR"}.items():
    P2[0x50 + lo] = (n + "W", INH)
_p2 = {0x0: "SUBW", 0x1: "CMPW", 0x2: "SBCD", 0x3: "CMPD", 0x4: "ANDD", 0x5: "BITD", 0x6: "LDW",
       0x7: "STW", 0x8: "EORD", 0x9: "ADCD", 0xA: "ORD", 0xB: "ADDW", 0xC: "CMPY", 0xE: "LDY", 0xF: "STY"}
for lo, n in _p2.items():
    if n not in ("STW", "STY"):
        P2[0x80 + lo] = (n, IMM16)
    P2[0x90 + lo] = (n, DIR); P2[0xA0 + lo] = (n, IDX); P2[0xB0 + lo] = (n, EXT)
P2.update({0xCE: ("LDS", IMM16), 0xDC: ("LDQ", DIR), 0xDD: ("STQ", DIR), 0xDE: ("LDS", DIR), 0xDF: ("STS", DIR),
           0xEC: ("LDQ", IDX), 0xED: ("STQ", IDX), 0xEE: ("LDS", IDX), 0xEF: ("STS", IDX),
           0xFC: ("LDQ", EXT), 0xFD: ("STQ", EXT), 0xFE: ("LDS", EXT), 0xFF: ("STS", EXT)})

# ---- page 3 ($11) -------------------------------------------------------------
P3.update({0x30: ("BAND", BITOP), 0x31: ("BIAND", BITOP), 0x32: ("BOR", BITOP), 0x33: ("BIOR", BITOP),
           0x34: ("BEOR", BITOP), 0x35: ("BIEOR", BITOP), 0x36: ("LDBT", BITOP), 0x37: ("STBT", BITOP),
           0x38: ("TFM", TFM), 0x39: ("TFM", TFM), 0x3A: ("TFM", TFM), 0x3B: ("TFM", TFM),
           0x3C: ("BITMD", IMM8), 0x3D: ("LDMD", IMM8), 0x3F: ("SWI3", INH)})
for lo, n in {0x3: "COM", 0xA: "DEC", 0xC: "INC", 0xD: "TST", 0xF: "CLR"}.items():
    P3[0x40 + lo] = (n + "E", INH); P3[0x50 + lo] = (n + "F", INH)
_p3 = {0x0: ("SUBE", IMM8), 0x1: ("CMPE", IMM8), 0x3: ("CMPU", IMM16), 0x6: ("LDE", IMM8), 0x7: ("STE", None),
       0xB: ("ADDE", IMM8), 0xC: ("CMPS", IMM16), 0xD: ("DIVD", IMM8), 0xE: ("DIVQ", IMM16), 0xF: ("MULD", IMM16)}
for lo, (n, im) in _p3.items():
    if im is not None:
        P3[0x80 + lo] = (n, im)
    P3[0x90 + lo] = (n, DIR); P3[0xA0 + lo] = (n, IDX); P3[0xB0 + lo] = (n, EXT)
for lo, n in {0x0: "SUBF", 0x1: "CMPF", 0x6: "LDF", 0x7: "STF", 0xB: "ADDF"}.items():
    if n != "STF":
        P3[0xC0 + lo] = (n, IMM8)
    P3[0xD0 + lo] = (n, DIR); P3[0xE0 + lo] = (n, IDX); P3[0xF0 + lo] = (n, EXT)

REGS = ["D", "X", "Y", "U", "S", "PC", "W", "V", "A", "B", "CC", "DP", "0", "0", "E", "F"]
IDXR = ["X", "Y", "U", "S"]
PSHS_BITS = ["CC", "A", "B", "DP", "X", "Y", "U", "PC"]
PSHU_BITS = ["CC", "A", "B", "DP", "X", "Y", "S", "PC"]
BIT_REGS = ["CC", "A", "B", "?"]

# Flow classification
UNCOND = {"BRA", "LBRA", "JMP", "RTS", "RTI", "PULS_PC", "PULU_PC", "SWI", "SWI2", "SWI3"}
CALLS = {"BSR", "LBSR", "JSR"}


def s8(v): return v - 256 if v & 0x80 else v
def s16(v): return v - 65536 if v & 0x8000 else v


class Image:
    def __init__(self, data, org):
        self.data, self.org = data, org
    def ok(self, a): return self.org <= a < self.org + len(self.data)
    def b(self, a): return self.data[a - self.org]


class Insn:
    __slots__ = ("addr", "size", "mn", "opr", "target", "is_call", "flow_end", "ext_addr",
                 "indirect_jump", "imm")
    def __init__(self, addr):
        self.addr = addr; self.size = 1; self.mn = "FCB"; self.opr = ""
        self.target = None; self.is_call = False; self.flow_end = False
        self.ext_addr = None; self.indirect_jump = False; self.imm = None


def decode_idx(img, a):
    """Decode indexed postbyte at a. Returns (text, nbytes, ext_addr_or_None, pcr_target_or_None)."""
    pb = img.b(a)
    r = IDXR[(pb >> 5) & 3]
    if not pb & 0x80:
        o = pb & 0x1F
        o = o - 32 if o & 0x10 else o
        return (f"{o},{r}" if o else f",{r}"), 1, None, None
    m = pb & 0x1F; ind = bool(pb & 0x10); n = 1; ext = None; pcr = None
    lo = m & 0x0F
    if lo == 0x0F or (m == 0x10):  # W modes / extended indirect
        if m == 0x1F:
            ext = (img.b(a + 1) << 8) | img.b(a + 2)
            return f"[${ext:04X}]", 3, ext, None
        sub = (pb >> 5) & 3
        if m == 0x0F:
            t = [",W", None, ",W++", ",--W"][sub]
            if sub == 1:
                t = f"${(img.b(a+1) << 8) | img.b(a+2):04X},W"; n = 3
        else:  # 0x10 indirect W
            t = ["[,W]", None, "[,W++]", "[,--W]"][sub]
            if sub == 1:
                t = f"[${(img.b(a+1) << 8) | img.b(a+2):04X},W]"; n = 3
        return t, n, None, None
    if lo == 0x0:
        t = f",{r}+"
        if ind: return f"<idx:{pb:02X}>", 1, None, None
    elif lo == 0x1: t = f",{r}++"
    elif lo == 0x2:
        t = f",-{r}"
        if ind: return f"<idx:{pb:02X}>", 1, None, None
    elif lo == 0x3: t = f",--{r}"
    elif lo == 0x4: t = f",{r}"
    elif lo == 0x5: t = f"B,{r}"
    elif lo == 0x6: t = f"A,{r}"
    elif lo == 0x7: t = f"E,{r}"
    elif lo == 0x8: t = f"{s8(img.b(a+1))},{r}"; n = 2
    elif lo == 0x9: t = f"${(img.b(a+1) << 8) | img.b(a+2):04X},{r}"; n = 3
    elif lo == 0xA: t = f"F,{r}"
    elif lo == 0xB: t = f"D,{r}"
    elif lo == 0xC:
        pcr = (a + 2 + s8(img.b(a + 1))) & 0xFFFF; t = f"${pcr:04X},PCR"; n = 2
    elif lo == 0xD:
        pcr = (a + 3 + s16((img.b(a+1) << 8) | img.b(a+2))) & 0xFFFF; t = f"${pcr:04X},PCR"; n = 3
    elif lo == 0xE: t = f"W,{r}"
    if ind: t = f"[{t}]"
    return t, n, ext, pcr


DP_VALUE = None  # set via --dp: resolves direct-page JMP/JSR targets


def _idx_force(img, a, text):
    """Add lwasm size-forcing so the operand re-assembles to the same postbyte/length.
    a = address of the indexed postbyte; text = operand text for that indexed part."""
    pb = img.b(a)
    if not pb & 0x80:
        if (pb & 0x1F) == 0 and not text.lstrip("[").startswith("0"):
            return text.replace(",", "0,", 1)          # 5-bit zero offset, not ,R
        return text
    m = pb & 0x1F; lo = m & 0x0F; ind = bool(pb & 0x10)
    pre = "[" if text.startswith("[") else ""
    body = text[len(pre):]
    if lo == 0x8 and not ind and -16 <= s8(img.b(a + 1)) <= 15:
        return pre + "<" + body
    if lo == 0x9 and -128 <= s16((img.b(a + 1) << 8) | img.b(a + 2)) <= 127:
        return pre + ">" + body
    if lo == 0xD and -128 <= s16((img.b(a + 1) << 8) | img.b(a + 2)) <= 127:
        return pre + ">" + body
    return text


def lwasm_force(img, pc, opr):
    """Return opr with lwasm forcing prefixes so `lwasm --6309` reproduces the exact bytes."""
    op = img.b(pc); a = pc + 1; table = P1
    if op in (0x10, 0x11):
        table = P2 if op == 0x10 else P3; op = img.b(a); a += 1
    if op not in table or not opr or opr[0] in "<>":
        return opr
    mn, mode = table[op]
    if mode in (EXT, MEMI_EXT):
        v = (img.b(a + (1 if mode == MEMI_EXT else 0)) << 8) | img.b(a + (2 if mode == MEMI_EXT else 1))
        if v < 0x100:
            if mode == MEMI_EXT:
                imm, _, rest = opr.partition(",")
                return f"{imm},>{rest}" if not rest.startswith(">") else opr
            return ">" + opr
        return opr
    if mode == IDX:
        return _idx_force(img, a, opr)
    if mode == MEMI_IDX:
        imm, _, rest = opr.partition(",")
        return f"{imm},{_idx_force(img, a + 1, rest)}"
    return opr


def decode(img, pc):
    ins = Insn(pc)
    if not img.ok(pc):
        return ins
    try:
        op = img.b(pc); a = pc + 1; table = P1; pre = ""
        if op in (0x10, 0x11) and img.ok(pc + 1):
            table = P2 if op == 0x10 else P3; op = img.b(a); a += 1
        if op not in table:
            ins.opr = f"${img.b(pc):02X}"; return ins
        mn, mode = table[op]
        opr = ""
        if mode == INH:
            pass
        elif mode == IMM8:
            ins.imm = img.b(a); opr = f"#${img.b(a):02X}"; a += 1
        elif mode == IMM16:
            v = (img.b(a) << 8) | img.b(a + 1); ins.imm = v; opr = f"#${v:04X}"; a += 2
        elif mode == IMM32:
            v = int.from_bytes(bytes(img.b(a + i) for i in range(4)), "big"); opr = f"#${v:08X}"; a += 4
        elif mode == DIR:
            opr = f"<${img.b(a):02X}"
            if DP_VALUE is not None:
                ins.ext_addr = (DP_VALUE << 8) | img.b(a)
                if mn in ("JMP", "JSR"): ins.target = ins.ext_addr
            a += 1
        elif mode == EXT:
            v = (img.b(a) << 8) | img.b(a + 1); ins.ext_addr = v; opr = f"${v:04X}"; a += 2
            if mn in ("JMP", "JSR"): ins.target = v
        elif mode == IDX:
            t, n, ext, pcr = decode_idx(img, a); opr = t; a += n
            ins.ext_addr = ext if ext is not None else pcr
            if mn in ("JMP", "JSR"):
                if pcr is not None and not t.startswith("["): ins.target = pcr
                else: ins.indirect_jump = True
        elif mode == REL8:
            ins.target = (a + 1 + s8(img.b(a))) & 0xFFFF; opr = f"${ins.target:04X}"; a += 1
        elif mode == REL16:
            ins.target = (a + 2 + s16((img.b(a) << 8) | img.b(a + 1))) & 0xFFFF; opr = f"${ins.target:04X}"; a += 2
        elif mode == REGOP:
            pb = img.b(a); opr = f"{REGS[pb >> 4]},{REGS[pb & 15]}"; a += 1
            if mn == "TFR" and (pb & 15) == 5: ins.indirect_jump = True; ins.flow_end = True
        elif mode == PSH:
            pb = img.b(a); bits = PSHS_BITS if mn in ("PSHS", "PULS") else PSHU_BITS
            opr = ",".join(bits[i] for i in range(8) if pb & (1 << i)) or "#0"; a += 1
            if mn in ("PULS", "PULU") and pb & 0x80: ins.flow_end = True
        elif mode == TFM:
            pb = img.b(a); s, d = REGS[pb >> 4], REGS[pb & 15]
            opr = {0x38: f"{s}+,{d}+", 0x39: f"{s}-,{d}-", 0x3A: f"{s}+,{d}", 0x3B: f"{s},{d}+"}[op]; a += 1
        elif mode == BITOP:
            pb = img.b(a); opr = f"{BIT_REGS[pb >> 6]},{(pb >> 3) & 7},{pb & 7},<${img.b(a+1):02X}"; a += 2
        elif mode == MEMI_DIR:
            opr = f"#${img.b(a):02X},<${img.b(a+1):02X}"; ins.imm = img.b(a); a += 2
        elif mode == MEMI_IDX:
            im = img.b(a); t, n, ext, _ = decode_idx(img, a + 1); opr = f"#${im:02X},{t}"; ins.imm = im; a += 1 + n
        elif mode == MEMI_EXT:
            im = img.b(a); v = (img.b(a + 1) << 8) | img.b(a + 2); ins.ext_addr = v; ins.imm = im
            opr = f"#${im:02X},${v:04X}"; a += 3
        ins.mn, ins.opr, ins.size = mn, opr, a - pc
        ins.is_call = mn in CALLS
        if mn in ("BRA", "LBRA", "JMP", "RTS", "RTI", "SWI", "SWI2", "SWI3"):
            ins.flow_end = True
        if not all(img.ok(pc + i) for i in range(ins.size)):
            return Insn(pc)
    except (IndexError, KeyError):
        return Insn(pc)
    return ins


class Tracer:
    def __init__(self, img, entries, speculate=0, data_ranges=()):
        self.img = img; self.code = {}; self.labels = {}; self.subs = set(); self.indirect = []
        self.refs = defaultdict(set); self.owner = {}
        self.bad = set(); self.speculative = set()
        for lo, hi in data_ranges: self.bad.update(range(lo, hi + 1))
        for e in entries: self.subs.add(e)
        self._trace(list(entries))
        for _ in range(speculate):
            found = self._speculate()
            if not found: break
            for f in found: self.subs.add(f); self.speculative.add(f)
            self._trace(found)
        self._make_labels()

    def _plausible(self, pc):
        """Code-like run from pc: valid opcodes, no overlap, ends in flow-end within 48 insns,
        and not a run of identical filler bytes."""
        n = 0; seen = []
        while n < 48:
            if not self.img.ok(pc) or pc in self.owner or pc in self.bad: return False
            ins = decode(self.img, pc)
            if ins.mn == "FCB" or ins.mn.startswith("SWI") or ins.mn in ("SYNC", "CWAI", "DAA"): return False
            if "<idx" in ins.opr: return False
            seen.append(ins.mn)
            if len(seen) >= 3 and seen[-1] == seen[-2] == seen[-3] and ins.size == 1: return False
            if ins.flow_end: return n >= 1
            pc += ins.size; n += 1
        return False

    def _speculate(self):
        found = []
        for a, ins in list(self.code.items()):
            if not ins.flow_end: continue
            g = a + ins.size
            if g in self.owner or not self.img.ok(g) or self.img.b(g) == 0: continue
            if self._plausible(g): found.append(g)
        return found

    def _trace(self, work):
        while work:
            pc = work.pop()
            while self.img.ok(pc) and pc not in self.code and pc not in self.bad:
                ins = decode(self.img, pc)
                if ins.mn == "FCB":
                    self.bad.add(pc); break
                if any(pc + k in self.owner for k in range(ins.size)):
                    break  # overlaps already-decoded code; stop this path
                self.code[pc] = ins
                for k in range(ins.size): self.owner[pc + k] = pc
                if ins.target is not None:
                    self.refs[ins.target].add(pc)
                    if ins.is_call: self.subs.add(ins.target)
                    work.append(ins.target)
                if ins.indirect_jump:
                    self.indirect.append(pc)
                if ins.flow_end: break
                pc += ins.size

    def _make_labels(self):
        for a, ins in self.code.items():
            if ins.target is not None and ins.target in self.code:
                self.labels.setdefault(ins.target, ("SUB_" if ins.target in self.subs else "L_") + f"{ins.target:04X}")
        for s in self.subs:
            if s in self.code: self.labels[s] = f"SUB_{s:04X}"


def label_for(tr, a):
    if a in tr.labels: return tr.labels[a]
    if a in HW_LABELS: return HW_LABELS[a]
    return None


def render(tr, img, entries, out_asm, out_sec, max_chunks, title):
    lines = []; hw_used = {}
    for ins in tr.code.values():
        if ins.ext_addr is not None and ins.ext_addr in HW_LABELS:
            hw_used[ins.ext_addr] = HW_LABELS[ins.ext_addr]
    lines.append("; =============================================")
    lines.append(f"; {title}")
    lines.append("; Recursive-descent HD6309 disassembly (dasm6309.py)")
    lines.append("; Entry points: " + " ".join(f"${e:04X}" for e in entries))
    lines.append(f"; Code bytes traced: {sum(i.size for i in tr.code.values())}  instructions: {len(tr.code)}")
    lines.append("; =============================================")
    lines.append("                 PRAGMA 6309")
    lines.append("; Hardware I/O Addresses")
    for a in sorted(hw_used):
        lines.append(f"{hw_used[a]:<16} EQU    ${a:04X}")
    lines.append("")
    lines.append(f"                 ORG    ${img.org:04X}")
    lines.append("")
    pc = img.org; end = img.org + len(img.data)
    sub_lines = []
    while pc < end:
        if pc in tr.code:
            ins = tr.code[pc]
            if pc in tr.subs:
                lines.append(f"; ---- {tr.labels.get(pc, f'SUB_{pc:04X}')} ----")
                if pc in tr.speculative:
                    lines.append("; (speculative entry: no static reference found - reached via table/computed jump?)")
                sub_lines.append(pc)
            if pc in tr.labels:
                lines.append(f"{tr.labels[pc]}:")
            hx = " ".join(f"{img.b(pc+i):02X}" for i in range(ins.size))
            opr = ins.opr
            dp_ref = opr.startswith("<$") and ins.target is not None
            if dp_ref and ins.target in tr.labels:
                cmt = f"; -> {tr.labels[ins.target]} (DP-relative)"
            elif ins.target is not None and ins.target in tr.labels and not opr.startswith("["):
                lbl = tr.labels[ins.target]
                opr = opr.replace(f"${ins.target:04X},PCR", f"{lbl},PCR") if ",PCR" in opr else lbl
            elif ins.ext_addr is not None and ins.ext_addr in HW_LABELS and ins.mn not in ("JMP", "JSR"):
                opr = opr.replace(f"${ins.ext_addr:04X}", HW_LABELS[ins.ext_addr])
            opr = lwasm_force(img, pc, opr)
            if not dp_ref or ins.target not in tr.labels: cmt = ""
            if ins.ext_addr is not None and ins.ext_addr in HW_LABELS:
                cmt = hw_comment(ins.ext_addr) or f"; {HW_LABELS[ins.ext_addr]}"
            if ins.target is not None and ins.target < pc and not ins.is_call and ins.mn not in ("JMP",):
                cmt = (cmt + " ; loop back").strip()
            if ins.indirect_jump:
                cmt = (cmt + " ; INDIRECT JUMP").strip()
            lines.append(f"  {pc:04X}  {hx:<17} {ins.mn:<7} {opr:<22}{cmt}")
            pc += ins.size
            continue
        # data run until next code byte
        start = pc
        while pc < end and pc not in tr.code: pc += 1
        a = start
        lbl_hdr = False
        while a < pc:
            if a in tr.labels:
                lines.append(f"{tr.labels[a]}:")
            # zero run
            z = a
            while z < pc and img.b(z) == 0 and (z == a or z not in tr.labels): z += 1
            if z - a >= 16:
                lines.append(f"  {a:04X}  {'00 ...':<17} RMB     {z-a:<22}; ${a:04X}-${z-1:04X} zero")
                a = z; continue
            n = min(16, pc - a)
            # break run at 16-byte boundary or before a zero run of 16+
            chunk = []
            k = a
            while k < a + n:
                zz = k
                while zz < pc and img.b(zz) == 0: zz += 1
                if zz - k >= 16 and k > a: break
                chunk.append(img.b(k)); k += 1
            txt = ",".join(f"${v:02X}" for v in chunk)
            asc = "".join(chr(v) if 32 <= v < 127 else "." for v in chunk)
            lines.append(f"  {a:04X}  {'..':<17} FCB     {txt}  ; {asc}")
            a = k
    lines.append("                 END")
    with open(out_asm, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Output written to {out_asm} ({len(lines)} lines, {len(tr.code)} instructions,"
          f" {len(tr.subs)} subroutines, {len(tr.indirect)} indirect jumps)", file=sys.stderr)
    for a in tr.indirect:
        print(f"  indirect jump at ${a:04X}: {tr.code[a].mn} {tr.code[a].opr}", file=sys.stderr)

    if out_sec:
        # chunk boundaries at subroutine starts, balanced by instruction count
        subs = sorted(s for s in tr.subs if s in tr.code)
        code_addrs = sorted(tr.code)
        total = len(code_addrs)
        target = max(1, total // max_chunks)
        bounds = [img.org]; cnt = 0; si = 0
        for a in code_addrs:
            cnt += 1
            if cnt >= target and len(bounds) < max_chunks:
                # next subroutine start after a
                nxt = next((s for s in subs if s > a), None)
                if nxt and nxt > bounds[-1]:
                    bounds.append(nxt); cnt = 0
        bounds = sorted(set(bounds))
        secs = []
        for i, b in enumerate(bounds):
            e = (bounds[i + 1] - 1) if i + 1 < len(bounds) else end - 1
            ins_in = [tr.code[a] for a in code_addrs if b <= a <= e]
            ss = [f"SUB_{s:04X}" for s in subs if b <= s <= e]
            hw = sorted({HW_LABELS[x.ext_addr] for x in ins_in if x.ext_addr in HW_LABELS})
            co = sorted({f"SUB_{x.target:04X}" for x in ins_in if x.is_call and x.target is not None
                         and not (b <= x.target <= e)})
            cf = sorted({f"${r:04X}" for s in subs if b <= s <= e for r in tr.refs.get(s, ())
                         if not (b <= r <= e)})
            secs.append({"id": i, "start_addr_hex": f"0x{b:04X}", "end_addr_hex": f"0x{e:04X}",
                         "line_count": len(ins_in), "subroutines": ss, "rom_calls": [],
                         "hw_accesses": hw, "calls_out": co, "called_from": cf})
        with open(out_sec, "w") as f:
            json.dump(secs, f, indent=2)
        print(f"Sections written to {out_sec} ({len(secs)} chunks)", file=sys.stderr)


def main():
    p = argparse.ArgumentParser(description="Recursive-descent HD6309 disassembler")
    p.add_argument("file"); p.add_argument("--org", type=lambda x: int(x, 0), default=0)
    p.add_argument("--entry", type=lambda x: int(x, 0), action="append", required=True)
    p.add_argument("--start", type=lambda x: int(x, 0), help="first address to emit (default org)")
    p.add_argument("--end", type=lambda x: int(x, 0), help="last address+1 to emit")
    p.add_argument("--output", "-o", required=True); p.add_argument("--sections")
    p.add_argument("--max-chunks", type=int, default=10); p.add_argument("--title", default="")
    p.add_argument("--data", action="append", default=[], metavar="HEX-HEX",
                   help="force an address range to be data, e.g. FD26-FD63")
    p.add_argument("--speculate", type=int, default=0, metavar="N",
                   help="N rounds of decoding plausible code in gaps after RTS/JMP/BRA")
    p.add_argument("--dp", type=lambda x: int(x, 0), help="assumed DP register value for <$xx operands")
    a = p.parse_args()
    global DP_VALUE
    DP_VALUE = a.dp
    data = open(a.file, "rb").read()
    img = Image(data, a.org)
    rngs = [tuple(int(v, 16) for v in r.split("-")) for r in a.data]
    tr = Tracer(img, a.entry, speculate=a.speculate, data_ranges=rngs)
    if a.start is not None or a.end is not None:
        s = a.start if a.start is not None else a.org; e = a.end if a.end is not None else a.org + len(data)
        img = Image(data[s - a.org:e - a.org], s)
        tr.code = {k: v for k, v in tr.code.items() if s <= k < e}
    render(tr, img, a.entry, a.output, a.sections, a.max_chunks, a.title or os.path.basename(a.file))


if __name__ == "__main__":
    main()
