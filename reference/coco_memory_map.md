# CoCo 1/2/3 Memory Map Reference

Validated 2026-11-07. Sources: Color BASIC 1.3 / Extended BASIC 1.1 / Disk BASIC 1.1 /
CoCo 3 ROM bytes (Unravelled source aligned to ROM images), and the XRoar
(`tcc1014.c`, `rsdos.c`, `coco3.c`), MAME (`trs/gime.cpp`) and VCC
(`tcc1014registers.cpp`, `FD502/wd1793.cpp`) emulator sources. See "Validation
notes" at the end for errors corrected relative to earlier drafts.

> Format note: `tools/annotator.py` parses every table row whose first cell starts
> with `$XXXX` as `| address | NAME | description |` (only addresses < $0100 or
> >= $FF00 are used). Keep that 3-column shape and no backticks in column 1.

## Address Space Overview

- 6809/6309 logical space is 64K. CoCo 1/2: SAM MC6883 maps RAM directly; ROMs at $8000-$FEFF; I/O at $FF00-$FFFF.
- CoCo 3: GIME (TCC1014) MMU maps eight 8K logical windows onto 64 x 8K physical blocks ($00-$3F, 512K). $FF00-$FFFF is always I/O regardless of MMU.
- ROM on the CoCo 3 is selected by **physical block number**: in ROM mode (TY=0), blocks $3C-$3F read ROM wherever the MMU maps them. With MMUEN=0, logical windows 0-7 map to blocks $38-$3F.
- GIME revisions: 1986 (TCC1014) and 1987 (TCC1014A). Differences that matter to code: timer counts value+2 on '86, value+1 on '87; odd values in $FF9E reportedly crash the '86 GIME (per MAME comment, attributed to JK).

## Zero Page (Direct Page) — $0000-$00FF

Color BASIC (CB), Extended (ECB) and Disk (DECB) variables. Addresses read from ROM code.

| Address | Name | Description |
|---------|------|-------------|
| $0000 | ENDFLG | STOP/END flag |
| $0001 | CHARAC | Terminator character for string scans |
| $0002 | ENDCHR | Alternate terminator character |
| $0003 | TMPLOC | Scratch variable |
| $0004 | IFCTR | IF/ELSE nesting counter |
| $0005 | DIMFLG | DIM flag |
| $0006 | VALTYP | Expression type (0=numeric, $FF=string) |
| $0007 | GARBFL | Garbage-collection flag |
| $0008 | ARYDIS | Array-disable flag |
| $0009 | INPFLG | INPUT/READ flag |
| $000A | RELFLG | Relational operator flag |
| $000B | TEMPPT | Next free temporary string descriptor (2) |
| $000D | LASTPT | Last temporary string descriptor (2) |
| $000F | TEMPTR | Temporary pointer (2) |
| $0011 | TMPTR1 | Temporary pointer (2) |
| $0013 | FPA2 | Floating-point accumulator 2 (4) |
| $0017 | BOTSTK | Bottom-of-stack check pointer (2) |
| $0019 | TXTTAB | Start of BASIC program text (2) |
| $001B | VARTAB | Start of simple variables (2) |
| $001D | ARYTAB | Start of arrays (2) |
| $001F | ARYEND | End of arrays / start of free RAM (2) |
| $0021 | FRETOP | Start of string space (2) |
| $0023 | STRTAB | Start of active strings (2) |
| $0025 | FRESPC | Pointer to newest string (2) |
| $0027 | MEMSIZ | Top of RAM usable by BASIC (CLEAR n,addr) (2) |
| $0029 | OLDTXT | Line number saved by STOP/END (2) |
| $002B | BINVAL | Binary value of a converted line number (2) |
| $002D | OLDPTR | Text pointer saved by STOP/END (2) |
| $002F | TINPTR | Temporary input pointer (2) |
| $0031 | DATTXT | Line number of current DATA (2) |
| $0033 | DATPTR | Pointer to next DATA item (2) |
| $0035 | DATTMP | Temporary DATA pointer (2) |
| $0037 | VARNAM | Current variable name (2) |
| $0039 | VARPTR | Pointer to current variable descriptor (2) |
| $003B | VARDES | Temporary variable descriptor pointer (2) |
| $003D | RELPTR | Relational operator jump pointer (2) |
| $003F | TRELFL | Temporary relational flag |
| $004F | FP0EXP | FPA0 exponent |
| $0050 | FPA0 | Floating-point accumulator 0 mantissa (4) |
| $0054 | FP0SGN | FPA0 sign |
| $0055 | COEFCT | Polynomial coefficient counter |
| $0056 | STRDES | Temporary string descriptor (5) |
| $005B | FPCARY | FP carry/rounding byte |
| $005C | FP1EXP | FPA1 exponent |
| $005D | FPA1 | Floating-point accumulator 1 mantissa (4) |
| $0061 | FP1SGN | FPA1 sign |
| $0062 | RESSGN | Sign of result |
| $0063 | FPSBYT | FP sub-byte (extra precision) |
| $0064 | COEFPT | Polynomial coefficient pointer (2) |
| $0066 | LSTTXT | Current line pointer during LIST (2) |
| $0068 | CURLIN | Current line number ($FFFF = direct mode) (2) |
| $006A | DEVCFW | Device comma field width |
| $006B | DEVLCF | Device last comma field |
| $006C | DEVPOS | Device print position |
| $006D | DEVWID | Device line width |
| $006E | PRTDEV | Print device (0=not cassette, $FF=cassette) |
| $006F | DEVNUM | Active device number (0=screen, -1=cassette, -2=printer, 1-15=disk file) |
| $0070 | CINBFL | Console input buffer flag (EOF) |
| $0071 | RSTFLG | Warm-start flag: $55 = take warm start via RSTVEC on RESET |
| $0072 | RSTVEC | Warm-start vector; target must begin with NOP ($12) (2) |
| $0074 | TOPRAM | Top of physical RAM found at cold start (2) |
| $0078 | FILSTA | Cassette file status (0=closed, 1=input, 2=output) |
| $0079 | CINCTR | Cassette buffer character count |
| $007A | CINPTR | Cassette buffer pointer (2) |
| $007C | BLKTYP | Cassette block type (0=header, 1=data, $FF=EOF) |
| $007D | BLKLEN | Cassette block length |
| $007E | CBUFAD | Cassette I/O buffer address (2) |
| $0080 | CCKSUM | Cassette checksum |
| $0081 | CSRERR | Cassette error flag |
| $0082 | CPULWD | Cassette pulse-width counter |
| $0083 | CPERTM | Cassette bit-period timer |
| $0084 | CBTPHA | Cassette bit phase flag |
| $0085 | CLSTSN | Cassette last sine-table entry |
| $0086 | GRBLOK | SET/RESET/POINT graphics block |
| $0087 | IKEYIM | INKEY$ last key |
| $0088 | CURPOS | Text cursor address in screen RAM (2) |
| $008A | ZERO | Always-zero word (2) |
| $008C | SNDTON | SOUND tone value |
| $008D | SNDDUR | SOUND duration (2) |
| $008F | CMPMID | Cassette 1200/2400 Hz partition |
| $0090 | CMP0 | Cassette 1200 Hz period |
| $0091 | CMP1 | Cassette 2400 Hz period |
| $0094 | BLKCNT | Cassette leader byte count |
| $0095 | LPTBTD | Printer baud-rate delay (2) |
| $0099 | LPTCFW | Printer comma field width |
| $009B | LPTWID | Printer line width |
| $009C | LPTPOS | Printer head position |
| $009D | EXECJP | EXEC default address (set by LOADM) (2) |
| $009F | GETNCH | CHRGET routine in RAM: INC CHARAD, get next char |
| $00A5 | GETCCH | Re-read current character (entry inside CHRGET) |
| $00A6 | CHARAD | BASIC interpreter text pointer (operand of CHRGET's LDA) (2) |
| $00AF | TRCFLG | ECB TRON flag |
| $00B0 | USRADR | ECB USR table pointer (DECB sets $095F) (2) |
| $00B2 | FORCOL | ECB foreground colour |
| $00B3 | BAKCOL | ECB background colour |
| $00B4 | WCOLOR | ECB working colour |
| $00B5 | ALLCOL | ECB all-pixels colour byte |
| $00B6 | PMODE | ECB current PMODE (0-4) |
| $00B7 | ENDGRP | ECB end of current graphics page (2) |
| $00B9 | HORBYT | ECB bytes per graphics row |
| $00BA | BEGGRP | ECB start of current graphics page (2) |
| $00BC | GRPRAM | ECB MSB of graphics RAM start ($06 ECB, $0E DECB) |
| $00BD | HORBEG | ECB graphics cursor X (2) |
| $00BF | VERBEG | ECB graphics cursor Y (2) |
| $00C1 | CSSVAL | ECB SCREEN colour-set value |
| $00C2 | SETFLG | ECB PSET/PRESET flag |
| $00C3 | HOREND | ECB line end X (2) |
| $00C5 | VEREND | ECB line end Y (2) |
| $00C7 | HORDEF | ECB default X (2) |
| $00C9 | VERDEF | ECB default Y (2) |
| $00D8 | VD8 | ECB scratch (RENUM flag / pixel mask) |
| $00DB | CHGFLG | ECB graphics change flag |
| $00DC | TMPSTK | ECB saved stack pointer (DRAW/PLAY) (2) |
| $00DE | OCTAVE | PLAY octave |
| $00DF | VOLHI | PLAY volume high (DAC) |
| $00E0 | VOLLOW | PLAY volume low (DAC) |
| $00E1 | NOTELN | PLAY note length |
| $00E2 | TEMPO | PLAY tempo |
| $00E3 | PLYTMR | PLAY timer (2) |
| $00E5 | DOTVAL | PLAY dotted-note value |
| $00E6 | DLBAUD | DLOAD baud constant |
| $00E7 | TIMOUT | DLOAD timeout (CoCo 3 ROM reuses $E7 as HSCREEN mode) |
| $00E8 | ANGLE | DRAW angle |
| $00E9 | SCALE | DRAW scale |

DSKCON control block ($00EA-$00F0: DCOPC/DCDRV/DCTRK/DSEC/DCBPT/DCSTA) is in `rom_entry_points.md`.

## Low RAM — $0100-$0DFF

| Range | Name | Description |
|-------|------|-------------|
| $0100 | SW3VEC | SWI3 hook (JMP xxxx) — $FFF2 targets here (CoCo 1/2) |
| $0103 | SW2VEC | SWI2 hook |
| $0106 | SWIVEC | SWI hook |
| $0109 | NMIVEC | NMI hook (DECB installs JMP $D8A1) |
| $010C | IRQVEC | IRQ hook (BASIC 60 Hz IRQ; DECB JMP $D8AF) |
| $010F | FRQVEC | FIRQ hook |
| $0112 | TIMVAL | TIMER value (2) |
| $0115 | RVSEED | RND seed |
| $011A | CASFLG | Upper/lower case flag |
| $011B | DEBVAL | Keyboard debounce delay |
| $011D | EXPJMP | Exponentiation vector |
| $0120 | COMVEC | Command/function dispatch tables (CB, ECB, DECB) |
| $0152 | KEYBUF | Keyboard rollover table (8) |
| $015A | POTVAL | Joystick values 0-63: right X, right Y, left X, left Y (4) |
| $015E | RVEC0 | Start of 25 RAM hooks (3 bytes each, RTS by default) to $01A8 |
| $01DA | CASBUF | Cassette I/O buffer (256) |
| $02DA | LINHDR | Line input header |
| $02DC | LINBUF | Line input buffer (251); cold-start stack top = $03D7 |
| $03D7 | STRBUF | String/number conversion buffer |
| $0400 | VIDRAM | 32x16 text screen (512 bytes, $0400-$05FF) |
| $0600 | DBUF0 | DECB: sector buffer 0 ($0600-$06FF) |
| $0700 | DBUF1 | DECB: sector buffer 1 ($0700-$07FF) |
| $0800 | FATBL0 | DECB: FAT images, 4 drives x $4A ($0800/$084A/$0894/$08DE) |
| $0928 | FCBV1 | DECB: FCB pointer table |
| $0948 | RNBFAD | DECB: random-buffer start pointer (default $0989) |
| $094A | FCBADR | DECB: FCB area start pointer |
| $0989 | — | DECB: random buffers (256) then FCBs (281 bytes each), up to $0DFF |

DECB cold start clears $0600-$0988.

## User RAM — $0E00-$7FFF

Graphics pages start at GRPRAM*256: $0600 (CB/ECB cassette) or $0E00 (DECB).
TXTTAB = graphics start + PCLEAR pages x $600 + 1. Default PCLEAR 4 gives $1E01 (ECB) or
$2601 (DECB). Layout upward: program text, simple vars (VARTAB), arrays (ARYTAB..ARYEND),
free RAM/stack, string space (FRETOP..MEMSIZ).

## ROM / Cartridge Space — $8000-$FEFF

| Range | Description |
|-------|-------------|
| $8000-$9FFF | Extended BASIC ROM (CoCo 3: physical block $3C) |
| $A000-$BFFF | Color BASIC ROM (CoCo 3: block $3D) |
| $C000-$DFFF | Cartridge / Disk BASIC ROM (CoCo 3: block $3E) |
| $E000-$FEFF | CoCo 1/2: unused or cartridge. CoCo 3: Super ECB (block $3F) |

CoCo 3 ROM map ($FF90 MC1:MC0, effective when TY=0):

| Mode | Description |
|------|-------------|
| MC1=0 (00/01) | 16K internal (blocks $3C-$3D) + 16K external cartridge (blocks $3E-$3F) |
| MC1:MC0=10 | 32K internal ROM ($8000-$FEFF) |
| MC1:MC0=11 | 32K external cartridge ROM |

CoCo 3 reset writes $0A to $FF90 (32K internal, MC3=1) then BASIC uses $CC.

**$FE00-$FEFF vector page (CoCo 3):** when $FF90 MC3=1, this page is always RAM from physical
block $3F ($7FE00-$7FEFF), bypassing the MMU and ROM mode. The CPU vectors point to JMPs here:

| Range | Name | Description |
|-------|------|-------------|
| $FEEE | — | SWI3 JMP (to $0100 by default) |
| $FEF1 | — | SWI2 JMP ($0103) |
| $FEF4 | — | FIRQ JMP ($010F) |
| $FEF7 | — | IRQ JMP ($010C) |
| $FEFA | — | SWI JMP ($0106) |
| $FEFD | — | NMI JMP ($0109) |

## Hardware I/O — $FF00-$FFFF

### PIA 0 — $FF00-$FF03 (Keyboard / Joystick; interrupts → CPU IRQ)
| Address | Name | Description |
|---------|------|-------------|
| $FF00 | PIA0_DA | Port A (DDR when CRA b2=0): b0-b6 keyboard rows in, b7 joystick comparator in |
| $FF01 | PIA0_CA | Control A: CA1=HSYNC (IRQ), CA2=joystick axis select (b3) |
| $FF02 | PIA0_DB | Port B (DDR when CRB b2=0): keyboard column strobe out |
| $FF03 | PIA0_CB | Control B: CB1=VSYNC/field sync (IRQ, 60 Hz), CB2=joystick port select (b3) |

### PIA 1 — $FF20-$FF23 (Sound / Cassette / VDG; interrupts → CPU FIRQ)
| Address | Name | Description |
|---------|------|-------------|
| $FF20 | PIA1_DA | Port A: b7-b2 6-bit DAC out, b1 RS-232 out, b0 cassette in |
| $FF21 | PIA1_CA | Control A: CA1=RS-232 CD (FIRQ), CA2=cassette motor (b3) |
| $FF22 | PIA1_DB | Port B: b7 A/G, b6 GM2, b5 GM1, b4 GM0/INT-EXT, b3 CSS, b2 RAM-size in (CoCo 1/2), b1 1-bit sound, b0 RS-232 in |
| $FF23 | PIA1_CB | Control B: CB1=cartridge CART (FIRQ), CB2=sound mux enable (b3) |

ECB graphics write $FF22 = $80 | (PMODE+3)<<4 | CSS. The GIME snoops $FF22 writes in CoCo 3.

### Disk Controller — $FF40-$FF4B (RS-DOS / FD-502)
| Address | Name | Description |
|---------|------|-------------|
| $FF40 | DSKREG | Drive control latch (write only): b0-b2 drive 0-2, b3 motor, b4 precomp, b5 density, b6 drive 3/side, b7 HALT enable |
| $FF48 | FDCREG | WD179x command (write) / status (read) |
| $FF49 | FDC_TRK | WD179x track register |
| $FF4A | FDC_SEC | WD179x sector register |
| $FF4B | FDC_DAT | WD179x data register |

The INTRQ line drives the NMI ($FFFC). DRQ with HALT enabled releases the CPU's HALT line for byte transfers.

### GIME — $FF90-$FF9F (CoCo 3)

Only $FF92/$FF93 are readable. Other reads return the floating bus.

| Address | Name | Description |
|---------|------|-------------|
| $FF90 | GIME_INIT0 | COCO\|MMUEN\|IEN\|FEN\|MC3\|MC2\|MC1\|MC0 (see bit fields) |
| $FF91 | GIME_INIT1 | b6 MTYP (RAM type), b5 TINS timer source, b0 TR task select |
| $FF92 | GIME_IRQEN | IRQ enable (write) / pending + acknowledge (read): x\|x\|TMR\|HBORD\|VBORD\|EI2\|EI1\|EI0 |
| $FF93 | GIME_FIRQEN | FIRQ enable (write) / pending + acknowledge (read), same bits |
| $FF94 | GIME_TMRHI | Timer bits 11-8; writing reloads and restarts the timer |
| $FF95 | GIME_TMRLO | Timer bits 7-0; latched only (no restart) |
| $FF98 | GIME_VMODE | BP\|x\|BPI\|MOCH\|H50\|LPR2\|LPR1\|LPR0 |
| $FF99 | GIME_VRES | x\|LPF1\|LPF0\|HRES2\|HRES1\|HRES0\|CRES1\|CRES0 |
| $FF9A | GIME_BORDER | Border colour (6-bit colour code) |
| $FF9B | GIME_EXTBANK | Unused on stock GIME; 2MB/8MB (Disto) upgrade bank bits, latched by MMU writes |
| $FF9C | GIME_VSCRL | Vertical fine scroll (b3-0) |
| $FF9D | GIME_VOFFHI | Video start, physical address bits 18-11 |
| $FF9E | GIME_VOFFLO | Video start, physical address bits 10-3 (8-byte steps) |
| $FF9F | GIME_HOFF | b7 HVEN (256-byte virtual row), b6-0 horizontal offset in 2-byte units |

**$FF90 GIME_INIT0:** b7 COCO (1=CoCo 1/2 VDG-compatible video), b6 MMUEN, b5 IEN (GIME IRQ to CPU),
b4 FEN (GIME FIRQ to CPU), b3 MC3 (1=$FExx constant RAM), b2 MC2 (1=standard SCS:
$FF40-$FF5F to cartridge), b1-0 MC1:MC0 ROM map (table above).

**$FF91 GIME_INIT1:** b5 TINS: 0 = timer counts scanlines (15.7 kHz, 63.5 us), 1 = 3.58 MHz (279.4 ns).
b0 TR: 0 = task 0 ($FFA0-$FFA7), 1 = task 1 ($FFA8-$FFAF). b6 MTYP selects RAM chip type (64K/256K).

**Timer:** 12-bit. Value 0 stops the timer. Underflow sets TMR, auto-reloads, and toggles text blink.

**Interrupt bits ($FF92/$FF93):** b5 TMR, b4 HBORD (end of active line), b3 VBORD (start of bottom border),
b2 EI2 serial, b1 EI1 keyboard (any PA0-PA6 low), b0 EI0 cartridge. Reading acknowledges.
Writing 0 to a bit also clears that pending flag.

**$FF98 GIME_VMODE:** b7 BP (1=graphics, 0=text), b5 BPI (composite burst phase invert),
b4 MOCH (monochrome composite), b3 H50 (50 Hz). LPR lines/row: 000=1, 001=1, 010=2, 011=8,
100=9, 101=10, 110=11, 111=infinite (MAME and XRoar agree).

**$FF99 GIME_VRES:** LPF lines/field: 00=192, 01=199/200, 10=infinite (undefined), 11=225.
Graphics HRES bytes/row: 000=16, 001=20, 010=32, 011=40, 100=64, 101=80, 110=128, 111=160.
Text HRES chars/row (b1 ignored): 000/010=32, 001/011=40, 100/110=64, 101/111=80. CRES graphics: 00=2c, 01=4c, 10=16c. Text: CRES b0=1 enables attributes.

### MMU — $FFA0-$FFAF (CoCo 3)

Each register holds a 6-bit physical block (0-63); physical address = block x $2000.
Readback is the low 6 bits plus floating-bus b7-b6 (512K machines). $FFA7/$FFAF cover $E000-$FEFF
($FF00 page is always I/O; $FExx follows MC3).

| Address | Name | Description |
|---------|------|-------------|
| $FFA0 | MMU_T0_P0 | Task 0 $0000-$1FFF (BASIC default block $38) |
| $FFA1 | MMU_T0_P1 | Task 0 $2000-$3FFF ($39) |
| $FFA2 | MMU_T0_P2 | Task 0 $4000-$5FFF ($3A) |
| $FFA3 | MMU_T0_P3 | Task 0 $6000-$7FFF ($3B) |
| $FFA4 | MMU_T0_P4 | Task 0 $8000-$9FFF ($3C) |
| $FFA5 | MMU_T0_P5 | Task 0 $A000-$BFFF ($3D) |
| $FFA6 | MMU_T0_P6 | Task 0 $C000-$DFFF ($3E) |
| $FFA7 | MMU_T0_P7 | Task 0 $E000-$FEFF ($3F) |
| $FFA8 | MMU_T1_P0 | Task 1 $0000-$1FFF |
| $FFA9 | MMU_T1_P1 | Task 1 $2000-$3FFF |
| $FFAA | MMU_T1_P2 | Task 1 $4000-$5FFF |
| $FFAB | MMU_T1_P3 | Task 1 $6000-$7FFF |
| $FFAC | MMU_T1_P4 | Task 1 $8000-$9FFF |
| $FFAD | MMU_T1_P5 | Task 1 $A000-$BFFF |
| $FFAE | MMU_T1_P6 | Task 1 $C000-$DFFF |
| $FFAF | MMU_T1_P7 | Task 1 $E000-$FEFF |

### Palette — $FFB0-$FFBF (CoCo 3)

6-bit colour codes; readback is the low 6 bits plus floating bus. RGB monitor: b5 R1, b4 G1, b3 B1, b2 R0, b1 G0, b0 B0.
Composite: b5-4 intensity, b3-0 hue.

| Address | Name | Description |
|---------|------|-------------|
| $FFB0 | PAL_0 | Palette 0 (text attr background 0) |
| $FFB1 | PAL_1 | Palette 1 |
| $FFB2 | PAL_2 | Palette 2 |
| $FFB3 | PAL_3 | Palette 3 |
| $FFB4 | PAL_4 | Palette 4 |
| $FFB5 | PAL_5 | Palette 5 |
| $FFB6 | PAL_6 | Palette 6 |
| $FFB7 | PAL_7 | Palette 7 (text attr background 7) |
| $FFB8 | PAL_8 | Palette 8 (text attr foreground 0) |
| $FFB9 | PAL_9 | Palette 9 |
| $FFBA | PAL_10 | Palette 10 |
| $FFBB | PAL_11 | Palette 11 |
| $FFBC | PAL_12 | Palette 12 |
| $FFBD | PAL_13 | Palette 13 |
| $FFBE | PAL_14 | Palette 14 |
| $FFBF | PAL_15 | Palette 15 (text attr foreground 7) |

### SAM (MC6883) — $FFC0-$FFDF

Write-only bit pairs: even address clears the bit and odd address sets it (data ignored).

| Address | Name | Description |
|---------|------|-------------|
| $FFC0 | SAM_V0CLR | VDG mode V0 = 0 |
| $FFC1 | SAM_V0SET | VDG mode V0 = 1 |
| $FFC2 | SAM_V1CLR | VDG mode V1 = 0 |
| $FFC3 | SAM_V1SET | VDG mode V1 = 1 |
| $FFC4 | SAM_V2CLR | VDG mode V2 = 0 |
| $FFC5 | SAM_V2SET | VDG mode V2 = 1 |
| $FFC6 | SAM_F0CLR | Display offset F0 = 0 (offset = F x 512) |
| $FFC7 | SAM_F0SET | Display offset F0 = 1 |
| $FFC8 | SAM_F1CLR | Display offset F1 = 0 |
| $FFC9 | SAM_F1SET | Display offset F1 = 1 ($0400 text = F1 set) |
| $FFCA | SAM_F2CLR | Display offset F2 = 0 |
| $FFCB | SAM_F2SET | Display offset F2 = 1 |
| $FFCC | SAM_F3CLR | Display offset F3 = 0 |
| $FFCD | SAM_F3SET | Display offset F3 = 1 |
| $FFCE | SAM_F4CLR | Display offset F4 = 0 |
| $FFCF | SAM_F4SET | Display offset F4 = 1 |
| $FFD0 | SAM_F5CLR | Display offset F5 = 0 |
| $FFD1 | SAM_F5SET | Display offset F5 = 1 |
| $FFD2 | SAM_F6CLR | Display offset F6 = 0 |
| $FFD3 | SAM_F6SET | Display offset F6 = 1 |
| $FFD4 | SAM_P1CLR | Page #1 = 0 (64K map type 0 only; ignored by GIME) |
| $FFD5 | SAM_P1SET | Page #1 = 1 (upper 32K RAM page) |
| $FFD6 | SAM_R0CLR | MPU rate R0 = 0 (ignored by GIME) |
| $FFD7 | SAM_R0SET | MPU rate R0 = 1 (address-dependent speed-up on CoCo 1/2) |
| $FFD8 | SAM_R1CLR | MPU rate R1 = 0: slow 0.89 MHz |
| $FFD9 | SAM_R1SET | MPU rate R1 = 1: fast 1.79 MHz (CoCo 3 high-speed poke) |
| $FFDA | SAM_M0CLR | Memory size M0 = 0 |
| $FFDB | SAM_M0SET | Memory size M0 = 1 |
| $FFDC | SAM_M1CLR | Memory size M1 = 0 |
| $FFDD | SAM_M1SET | Memory size M1 = 1 (M1:M0 00=4K, 01=16K, 10=64K; ECB sets 64K) |
| $FFDE | SAM_TYCLR | Map type TY = 0: ROM mode (ROMs at $8000-$FEFF) |
| $FFDF | SAM_TYSET | Map type TY = 1: all-RAM mode |

### CPU Vectors — $FFF0-$FFFF
| Address | Name | Description |
|---------|------|-------------|
| $FFF0 | VEC_TRAP | Reserved on 6809; HD6309 illegal-op / divide-by-zero trap |
| $FFF2 | VEC_SWI3 | SWI3 → $0100 (CoCo 1/2) / $FEEE (CoCo 3) |
| $FFF4 | VEC_SWI2 | SWI2 → $0103 / $FEF1 (OS-9 system calls) |
| $FFF6 | VEC_FIRQ | FIRQ → $010F / $FEF4 (PIA1: CART, CD; GIME FIRQ) |
| $FFF8 | VEC_IRQ | IRQ → $010C / $FEF7 (PIA0: HSYNC, VSYNC; GIME IRQ) |
| $FFFA | VEC_SWI | SWI → $0106 / $FEFA |
| $FFFC | VEC_NMI | NMI → $0109 / $FEFD (FDC INTRQ) |
| $FFFE | VEC_RESET | RESET → $A027 (Color BASIC) / $8C1B (CoCo 3) |

## Video Modes

### VDG modes (CoCo 1/2; CoCo 3 with COCO=1)

$FF22 supplies A/G, GM2-0 and CSS; the SAM V bits must match.

| Mode | SAM V | $FF22 A/G GM2-0 | Resolution | Colors | Bytes | ECB |
|------|-------|-----------------|-----------|--------|-------|-----|
| AI/SG4 | 000 | 0 xxx | 32x16 text / 64x32 semigraphics | 2 / 8 | 512 | text |
| CG1 | 001 | 1 000 | 64x64 | 4 | 1024 | — |
| RG1 | 001 | 1 001 | 128x64 | 2 | 1024 | — |
| CG2 | 010 | 1 010 | 128x64 | 4 | 2048 | — |
| RG2 | 011 | 1 011 | 128x96 | 2 | 1536 | PMODE 0 |
| CG3 | 100 | 1 100 | 128x96 | 4 | 3072 | PMODE 1 |
| RG3 | 101 | 1 101 | 128x192 | 2 | 3072 | PMODE 2 |
| CG6 | 110 | 1 110 | 128x192 | 4 | 6144 | PMODE 3 |
| RG6 | 110 | 1 111 | 256x192 | 2 | 6144 | PMODE 4 |

SAM V=111 is DMA mode. Graphics base = GRPRAM: $0600 (ECB) or $0E00 (DECB). Text base is $0400.

### GIME native modes (CoCo 3, COCO=0)

| Mode | $FF98 | $FF99 | HRES | CRES | Bytes/row | Notes |
|------|-------|-------|------|------|-----------|-------|
| WIDTH 40 text | $03 | $05 | 001 | x1 | 80 (char+attr) | LPR 8, LPF 192 → 40x24; screen $6C000 ($FF9D=$D8) |
| WIDTH 80 text | $03 | $15 | 101 | x1 | 160 (char+attr) | 80x24; screen $6C000 |
| HSCREEN 1 | $80 | $15 | 101 | 01 | 80 | 320x192 4c; screen $60000 ($FF9D=$C0) |
| HSCREEN 2 | $80 | $1E | 111 | 10 | 160 | 320x192 16c |
| HSCREEN 3 | $80 | $14 | 101 | 00 | 80 | 640x192 2c |
| HSCREEN 4 | $80 | $1D | 111 | 01 | 160 | 640x192 4c |

General rule: pixels/row = bytes/row x (8, 4, 2) for 2c, 4c, 16c. Examples: 256x 16c = 128 B (HRES 110);
320x 2c = 40 B (011); 512x 2c = 64 B (100); 160x 16c = 80 B (101). Set LPF=01 for 200-line variants.

**Text attribute byte** (second byte of each cell when CRES b0=1): b7 blink, b6 underline,
b5-3 foreground (palette 8-15), b2-0 background (palette 0-7).

## Validation notes (errors corrected vs. earlier drafts)

These are the errors found in `coco-memory-map (1).md`, `coco-memory-map-v2.md` and the previous version of this file:
- Zero page: the drafts' BASIC pointer chain (MEMSIZ $78 / TXTBEG $7A / VARTAB $7C / ARYTAB $7E / FRETOP $80) is wrong; ROM code uses TXTTAB $19, VARTAB $1B, ARYTAB $1D, ARYEND $1F, FRETOP $21, MEMSIZ $27. Also wrong: DEVNUM ($6F, not $68), CURPOS ($88, not $6F), EXECJP ($9D, not $BA), BEGGRP ($BA, not $74), LPTCFW ($99), TMPSTK ($DC), $A6 (CHARAD, not VDG mode), POTVAL ($015A, not $E5). CHARONE/IKESSION/SYSRAM/POS/CURCHR/VDG_MODE are not ROM symbols. RSTFLG $71 / RSTVEC $72 / PLYTMR $E3 were correct.
- PIA0 VSYNC drives IRQ, not FIRQ (FIRQ comes from PIA1: CART/CD). The $FF22 bit map was wrong: A/G is b7, CSS is b3, b0 is RS-232 *in*, and RS-232 out is $FF20 b1.
- FDC: the control latch is $FF40, and the WD179x is at $FF48-$FF4B (not $FF40-$FF43 + $FF48).
- SAM: $FFDE = ROM mode and $FFDF = all-RAM (draft 1 and the old file had these reversed). $FFD4/5 is P1 (RAM page), not speed. CPU speed is R1 ($FFD8/$FFD9).
- GIME: $FF91 TR is b0 (not b2), and TINS=1 selects 279 ns. $FF98 has BPI b5, MOCH b4, H50 b3, LPR b2-0. $FF9B is the 2MB bank register, VSC is $FF9C, VOFF is $FF9D/$FF9E and HOFF is $FF9F (draft 1 and the old file were shifted by one register).
- CoCo 3 vectors point to $FEEE-$FEFD, not $FE00-$FE0F (v2 §6.9).
- VDG: CG1 uses SAM V=001 and RG6 uses V=110 (V=111 is DMA).
- GIME mode table: 320x4c is HRES 101, not 100; 320x2c is 011; 640x4c is 111; WIDTH 40/80 use LPF=00 + LPR=8 (24 rows x 8 lines), not an 8x12 font.
