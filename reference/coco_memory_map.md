# CoCo Memory Map Reference

## Zero Page (Direct Page) — $0000-$00FF

| Address | Name | Description |
|---------|------|-------------|
| $0000-$0018 | | System scratch area |
| $0019 | CHARONE | Keyboard first character |
| $001A | IKESSION | Input device number |
| $0068 | DEVNUM | Device number (0=screen, -1=cassette, -2=printer) |
| $006F-$0070 | CURPOS | Current screen cursor position |
| $0071 | GRPRAM | Graphics RAM page |
| $0072 | ENDGRP | End of graphics page |
| $0073 | HORBYT | Horizontal bytes per line |
| $0074-$0075 | BEGGRP | Beginning of graphics area |
| $0078-$0079 | TXTBEG | Start of BASIC text |
| $007A-$007B | VARTAB | Start of BASIC variables |
| $007C-$007D | ARYTAB | Start of BASIC arrays |
| $007E-$007F | ARYEND | End of BASIC storage (first free) |
| $008A | CHARONE | Character under cursor |
| $0088 | POS | Print position |
| $009A-$009B | TMPSTK | Temporary stack pointer storage |
| $00A6 | VDG_MODE | Current VDG mode |
| $00BA-$00BB | EXECJP | EXEC jump address |
| $00DA | LPTCFW | Printer comma field width |
| $00E5 | POTVAL+0 | Joystick 0 X value |
| $00E6 | POTVAL+1 | Joystick 0 Y value |
| $00E7 | POTVAL+2 | Joystick 1 X value |
| $00E8 | POTVAL+3 | Joystick 1 Y value |

## BASIC Text & Variables — $0E00-$7FFF

| Range | Description |
|-------|-------------|
| $0E00-up | BASIC program text |
| up-$7FFF | Variables, arrays, strings, stack |

## Cartridge / ROM Space — $C000-$FEFF

| Range | Description |
|-------|-------------|
| $8000-$9FFF | Extended BASIC ROM (or RAM in 64K) |
| $A000-$BFFF | Color BASIC ROM |
| $C000-$DFFF | Cartridge ROM / Disk BASIC ROM |
| $E000-$FEFF | Reserved / extended ROM |

## Hardware I/O — $FF00-$FFFF

### PIA 0 — $FF00-$FF03 (Keyboard / Joystick)
| Address | Name | Description |
|---------|------|-------------|
| $FF00 | PIA0_DA | Data/Direction Register A (keyboard rows) |
| $FF01 | PIA0_CA | Control Register A (HSYNC IRQ) |
| $FF02 | PIA0_DB | Data/Direction Register B (keyboard columns) |
| $FF03 | PIA0_CB | Control Register B (VSYNC FIRQ) |

### PIA 1 — $FF20-$FF23 (VDG / Sound / Cassette)
| Address | Name | Description |
|---------|------|-------------|
| $FF20 | PIA1_DA | Data/Direction A (cassette/joystick comparator) |
| $FF21 | PIA1_CA | Control A (serial in, CD) |
| $FF22 | PIA1_DB | Data/Direction B (VDG mode, sound) |
| $FF23 | PIA1_CB | Control B (sound enable, cassette motor) |

**PIA1_DB ($FF22) Bit Map:**
- Bit 7: Not used
- Bit 6-4: CSS, GM2, GM1 (VDG mode)
- Bit 3: GM0 / ~A/G
- Bit 2: ~INT/EXT (internal/external)
- Bit 1: Sound bit (1-bit DAC or mux to 6-bit DAC)
- Bit 0: RS-232 out

### FDC (WD1793) — $FF40-$FF4F (Disk BASIC)
| Address | Name | Description |
|---------|------|-------------|
| $FF40 | DSK_CMD | Command/Status register |
| $FF41 | DSK_TRK | Track register |
| $FF42 | DSK_SEC | Sector register |
| $FF43 | DSK_DAT | Data register |
| $FF48 | DSK_CTL | Drive control (drive select, motor, density) |

### SAM (MC6883) — $FFC0-$FFDF
| Address | Name | Description |
|---------|------|-------------|
| $FFC0-$FFC5 | V0-V2 | VDG display mode (3 bits) |
| $FFC6-$FFD3 | F0-F6 | Display offset (7 bits, x512 bytes) |
| $FFD4-$FFD5 | P1 | Page select (0=slow, 1=fast) |
| $FFD6-$FFD9 | R0-R1 | MPU rate (00=slow, 01=address-dependent) |
| $FFDA-$FFDB | M0 | Memory size (0=4K, 1=16K/64K) |
| $FFDC-$FFDD | M1 | Map type |
| $FFDE-$FFDF | TY | ROM/RAM ($FFDE=all RAM, $FFDF=ROM enabled) |

### GIME Registers ($FF90-$FF9F) — CoCo 3

| Address | Name | Description |
|---------|------|-------------|
| $FF90 | GIME_INIT0 | Init 0: COCO\|MMUEN\|IEN\|FEN\|MC3\|MC2\|MC1\|MC0 |
| $FF91 | GIME_INIT1 | Init 1: x\|x\|TINS\|x\|x\|TR\|x\|x (timer input, task select) |
| $FF92 | GIME_IRQEN | IRQ enable: x\|x\|TMR\|HBORD\|VBORD\|EI2\|EI1\|EI0 |
| $FF93 | GIME_FIRQEN | FIRQ enable: x\|x\|TMR\|HBORD\|VBORD\|EI2\|EI1\|EI0 |
| $FF94 | GIME_TMRHI | Timer MSB (12-bit countdown, bits 11-8) |
| $FF95 | GIME_TMRLO | Timer LSB (12-bit countdown, bits 7-0) |
| $FF98 | GIME_VMODE | Video mode: BP\|x\|x\|BPI1\|BPI0\|MOCH\|H50\|LPR |
| $FF99 | GIME_VRES | Video res: x\|LPF1\|LPF0\|HRES2\|HRES1\|HRES0\|CRES1\|CRES0 |
| $FF9A | GIME_BORDER | Border color (6-bit palette index) |
| $FF9B | GIME_VSCRL | Vertical scroll offset (bits 3-0) |
| $FF9C | GIME_VOFFHI | Video display offset MSB (bits 18-11 of byte addr) |
| $FF9D | GIME_VOFFLO | Video display offset LSB (bits 10-3 of byte addr) |
| $FF9E | GIME_HOFFHI | Horizontal offset MSB / virtual screen |
| $FF9F | GIME_HOFFLO | Horizontal offset LSB / horizontal scroll |

**GIME_INIT0 ($FF90) bit fields:**
- Bit 7: COCO — 1=CoCo compatible mode, 0=CoCo 3 mode
- Bit 6: MMUEN — 1=MMU enabled, 0=disabled (64K mode)
- Bit 5: IEN — 1=GIME IRQ routing enabled
- Bit 4: FEN — 1=GIME FIRQ routing enabled
- Bits 3-0: MC3-MC0 — ROM map control

**GIME_VMODE ($FF98) bit fields:**
- Bit 7: BP — 1=graphics mode, 0=text mode
- Bits 4-3: BPI1-BPI0 — bits per pixel (00=2 colors, 01=4, 10=16, 11=reserved)
- Bit 2: MOCH — monochrome/composite select
- Bit 1: H50 — 1=50Hz, 0=60Hz
- Bit 0: LPR — lines per row (text: 0=1 line, 1=2 lines)

**GIME_VRES ($FF99) bit fields:**
- Bits 6-5: LPF1-LPF0 — lines per field (00=192, 01=200, 10=210, 11=225)
- Bits 4-2: HRES2-HRES0 — horizontal resolution (bytes/row: 16,20,32,40,64,80,128,160)
- Bits 1-0: CRES1-CRES0 — color resolution (00=2 colors, 01=4, 10=16, 11=reserved)

### MMU Registers ($FFA0-$FFAF) — CoCo 3

| Address | Name | Description |
|---------|------|-------------|
| $FFA0 | MMU_T0_P0 | Task 0 page 0 ($0000-$1FFF) 6-bit block select |
| $FFA1 | MMU_T0_P1 | Task 0 page 1 ($2000-$3FFF) 6-bit block select |
| $FFA2 | MMU_T0_P2 | Task 0 page 2 ($4000-$5FFF) 6-bit block select |
| $FFA3 | MMU_T0_P3 | Task 0 page 3 ($6000-$7FFF) 6-bit block select |
| $FFA4 | MMU_T0_P4 | Task 0 page 4 ($8000-$9FFF) 6-bit block select |
| $FFA5 | MMU_T0_P5 | Task 0 page 5 ($A000-$BFFF) 6-bit block select |
| $FFA6 | MMU_T0_P6 | Task 0 page 6 ($C000-$DFFF) 6-bit block select |
| $FFA7 | MMU_T0_P7 | Task 0 page 7 ($E000-$FEFF) 6-bit block select |
| $FFA8 | MMU_T1_P0 | Task 1 page 0 ($0000-$1FFF) 6-bit block select |
| $FFA9 | MMU_T1_P1 | Task 1 page 1 ($2000-$3FFF) 6-bit block select |
| $FFAA | MMU_T1_P2 | Task 1 page 2 ($4000-$5FFF) 6-bit block select |
| $FFAB | MMU_T1_P3 | Task 1 page 3 ($6000-$7FFF) 6-bit block select |
| $FFAC | MMU_T1_P4 | Task 1 page 4 ($8000-$9FFF) 6-bit block select |
| $FFAD | MMU_T1_P5 | Task 1 page 5 ($A000-$BFFF) 6-bit block select |
| $FFAE | MMU_T1_P6 | Task 1 page 6 ($C000-$DFFF) 6-bit block select |
| $FFAF | MMU_T1_P7 | Task 1 page 7 ($E000-$FEFF) 6-bit block select |

**MMU Memory Model:**
- 512K RAM = 64 pages x 8K each
- Each register holds 6-bit value (0-63) selecting which 8K physical page maps to that logical slot
- GIME_INIT1 bit 0 (TR) selects Task 0 or Task 1 register set
- I/O space $FF00-$FFFF always mapped regardless of MMU settings
- Physical address = register_value x $2000

### Palette Registers ($FFB0-$FFBF) — CoCo 3

| Address | Name | Description |
|---------|------|-------------|
| $FFB0 | PAL_0 | Palette 0: 6-bit RGB (R1\|R0\|G1\|G0\|B1\|B0) |
| $FFB1 | PAL_1 | Palette 1: 6-bit RGB |
| $FFB2 | PAL_2 | Palette 2: 6-bit RGB |
| $FFB3 | PAL_3 | Palette 3: 6-bit RGB |
| $FFB4 | PAL_4 | Palette 4: 6-bit RGB |
| $FFB5 | PAL_5 | Palette 5: 6-bit RGB |
| $FFB6 | PAL_6 | Palette 6: 6-bit RGB |
| $FFB7 | PAL_7 | Palette 7: 6-bit RGB |
| $FFB8 | PAL_8 | Palette 8: 6-bit RGB |
| $FFB9 | PAL_9 | Palette 9: 6-bit RGB |
| $FFBA | PAL_10 | Palette 10: 6-bit RGB |
| $FFBB | PAL_11 | Palette 11: 6-bit RGB |
| $FFBC | PAL_12 | Palette 12: 6-bit RGB |
| $FFBD | PAL_13 | Palette 13: 6-bit RGB |
| $FFBE | PAL_14 | Palette 14: 6-bit RGB |
| $FFBF | PAL_15 | Palette 15: 6-bit RGB |

**RGB encoding:** Bits 5-4 = Red, Bits 3-2 = Green, Bits 1-0 = Blue (each 2-bit, 4 levels)

### CoCo 3 Video Modes (GIME)

| Mode | HRES | CRES | LPF | Resolution | Colors | Bytes/row |
|------|------|------|-----|-----------|--------|-----------|
| Text 32 | 010 | - | - | 32x16 | 8 fg/8 bg | 32 |
| Text 40 | 011 | - | - | 40x24 | 8 fg/8 bg | 40 |
| Text 80 | 100 | - | - | 80x24 | 8 fg/8 bg | 80 |
| GFX | 010 | 00 | 00 | 128x192 | 2 | 16 |
| GFX | 011 | 01 | 01 | 160x200 | 4 | 40 |
| GFX | 100 | 10 | 01 | 320x200 | 16 | 160 |
| GFX | 100 | 00 | 01 | 320x200 | 2 | 40 |
| GFX | 100 | 01 | 01 | 320x200 | 4 | 80 |
| GFX | 101 | 00 | 01 | 640x200 | 2 | 80 |
| GFX | 101 | 01 | 01 | 640x200 | 4 | 160 |

### Interrupt Vectors — $FFF0-$FFFF
| Address | Vector | Description |
|---------|--------|-------------|
| $FFF0-$FFF1 | | Reserved |
| $FFF2-$FFF3 | SWI3 | Software Interrupt 3 |
| $FFF4-$FFF5 | SWI2 | Software Interrupt 2 |
| $FFF6-$FFF7 | FIRQ | Fast Interrupt Request |
| $FFF8-$FFF9 | IRQ | Interrupt Request |
| $FFFA-$FFFB | SWI | Software Interrupt |
| $FFFC-$FFFD | NMI | Non-Maskable Interrupt |
| $FFFE-$FFFF | RESET | Reset vector |

## VDG Display Modes

| Mode | SAM V | Resolution | Colors | Start |
|------|-------|-----------|--------|-------|
| Alpha-S | 000 | 32x16 text | 2 | $0400 |
| CG1 | 000 | 64x64 | 4 | $0600 |
| RG1 | 001 | 128x64 | 2 | $0600 |
| CG2 | 010 | 128x64 | 4 | $0600 |
| RG2 | 011 | 128x96 | 2 | $0600 |
| CG3 | 100 | 128x96 | 4 | $0600 |
| RG3 | 101 | 128x192 | 2 | $0600 |
| CG6 | 110 | 128x192 | 4 | $0600 |
| RG6 | 111 | 256x192 | 2 | $0600 |
