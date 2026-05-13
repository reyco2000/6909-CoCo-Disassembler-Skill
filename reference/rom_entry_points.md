# CoCo ROM Entry Points Reference

## Color BASIC ($A000-$BFFF)

### Screen / Character Output
| Address | Name | Description |
|---------|------|-------------|
| $A000 | BASIC_WARM | Warm start entry (OK prompt) |
| $A027 | CHROUT | Output char in A to current device |
| $A176 | PUTCHR | Print character in A to screen |
| $A1B1 | LPRINT | LPRINT - print to printer |
| $A1C1 | OUTCHR | Output character with device routing |
| $A282 | GETKEY | Get keyboard input character |
| $A35F | PRNTCR | Print carriage return |
| $A59A | CLS | Clear screen (text mode) |
| $A5C7 | SETGR | Set graphics mode |
| $A928 | POLCAT | Poll keyboard, returns char in A or Z flag |
| $A974 | KEYIN | Key input with cursor blink |

### Number Formatting / Math
| Address | Name | Description |
|---------|------|-------------|
| $BDCC | INTCNV | Convert FP to integer in D |
| $BDD9 | GIVABF | Convert integer in D to FP |
| $B3ED | PRTNUM | Print number in FAC |

### String Operations
| Address | Name | Description |
|---------|------|-------------|
| $B657 | STRINOUT | Output string, pointer in X |

### System
| Address | Name | Description |
|---------|------|-------------|
| $AD19 | EXEC | EXEC command handler |
| $AE38 | LNKBAS | Re-link BASIC program lines |
| $A42D | LINEINPUT | LINE INPUT routine |
| $B44A | CHKRST | Check for reset button |
| $A7E5 | SNDIRQ | Sound/timer IRQ handler |

### Sound
| Address | Name | Description |
|---------|------|-------------|
| $A8C5 | SOUND | SOUND command (freq, duration) |
| $B4F0 | SNDOUT | Low-level sound output |

### Joystick
| Address | Name | Description |
|---------|------|-------------|
| $A7D8 | JOYSTK | Read joystick values |
| $A9DE | JOYIN | Joystick input routine |

### Cassette I/O
| Address | Name | Description |
|---------|------|-------------|
| $A77C | CASON | Turn cassette motor on |
| $A78B | CASOFF | Turn cassette motor off |
| $A7A0 | CSRDON | Read cassette leader |
| $A7CA | BLKIN | Read cassette block |
| $A7D1 | BLKOUT | Write cassette block |

## Extended BASIC ($8000-$9FFF)

### Graphics
| Address | Name | Description |
|---------|------|-------------|
| $8000 | EXTBAS_ENTRY | Extended BASIC cold start |
| $80E5 | PMODE | Set PMODE |
| $80FD | SCREEN | Set SCREEN type |
| $811C | PCLS | Clear graphics screen |
| $812D | COLOR | Set drawing COLOR |
| $8168 | PSET | PSET (x,y) |
| $816D | PRESET | PRESET (x,y) |
| $819F | LINE | LINE drawing |
| $82B9 | CIRCLE | CIRCLE drawing |
| $83A1 | PAINT | PAINT fill |
| $843C | DRAW | DRAW string commands |
| $84ED | GET | GET graphics array |
| $852D | PUT | PUT graphics array |

### Sound
| Address | Name | Description |
|---------|------|-------------|
| $8530 | PLAY | PLAY music string |

### Misc
| Address | Name | Description |
|---------|------|-------------|
| $861E | TIMER | Read TIMER value |
| $8641 | DEL | DEL command |
| $867A | BUTTON | Read fire button |

## Disk BASIC ($C000-$DFFF)

### Disk I/O
| Address | Name | Description |
|---------|------|-------------|
| $C004 | DSKINI | Initialize disk system |
| $B938 | DSKCON | Disk I/O control block handler |
| $B95D | DOSINI | DOS warm initialization |
| $BC77 | GETFIL | Get filename from BASIC |
| $BCA0 | OPNFIL | Open file |
| $BCB0 | CLSFIL | Close file |
| $BE6C | DCNVEC | DOS conversion vector |

### DSKCON Control Block ($00EA-$00F1)
| Offset | Name | Description |
|--------|------|-------------|
| $00EA | DCDRV | Drive number (0-3) |
| $00EB | DCTRK | Track number (0-34) |
| $00EC | DCSEC | Sector number (1-18) |
| $00ED | DCSTA | Status byte |
| $00EE | DTEFP | Transfer address (2 bytes) |

## Super Extended BASIC ($E000+) — CoCo 3

**NOTE:** Addresses below are based on community documentation for the SECB ROM.

### Hi-Res Graphics Commands
| Address | Name | Description |
|---------|------|-------------|
| $E000 | SECB_ENTRY | Super Extended BASIC cold start |
| $E004 | HSCREEN | Set hi-res screen mode (0-4) |
| $E007 | HCLS | Clear hi-res graphics screen |
| $E00A | HCOLOR | Set hi-res foreground drawing color |
| $E00D | HPSET | Set hi-res pixel |
| $E010 | HPRESET | Reset hi-res pixel |
| $E012 | HLINE | Draw hi-res line |
| $E015 | HCIRCLE | Draw hi-res circle |
| $E018 | HPAINT | Hi-res flood fill |
| $E01B | HGET | Capture hi-res screen region to buffer |
| $E01E | HPUT | Display buffer to hi-res screen |
| $E021 | HBUFF | Allocate hi-res graphics buffer |
| $E024 | HPRINT | Print text on hi-res screen |

### Display / Palette
| Address | Name | Description |
|---------|------|-------------|
| $E027 | PALETTE | Set palette register value |
| $E02A | RGB | Set palette RGB color value |
| $E02D | WIDTH | Set text width (32/40/80) |
| $E030 | LOCATE | Position cursor on hi-res text screen |
| $E033 | ATTR | Set text attributes (foreground/background color) |
| $E036 | HPOINT | Read hi-res pixel color |
| $E039 | HSTAT | Return hi-res screen status info |
| $E03C | HDRAW | Hi-res DRAW string commands |
| $E03F | HPLAY | Hi-res PLAY music string |

### CoCo 3 Zero-Page Variables
| Address | Name | Description |
|---------|------|-------------|
| $00E9 | HRESSION | CoCo 3 hi-res screen mode number |
| $00EA | HRESMOD | Hi-res mode flags |
| $00F0 | HCOLOR_FG | Hi-res foreground color |
| $00F1 | HCOLOR_BG | Hi-res background color |

## Useful Zero-Page Locations for ML Programs

| Address | Description |
|---------|-------------|
| $0019 | Single-key buffer from POLCAT |
| $006C-$006D | Cassette buffer pointer |
| $006E | Cassette I/O flag |
| $00E5-$00E8 | Joystick values (0X, 0Y, 1X, 1Y) |
| $011A | TIMER high byte |
| $011B | TIMER low byte |
| $0400-$05FF | Text screen RAM (32x16 = 512 bytes) |

## Common CoCo Programming Patterns

### Keyboard polling loop
```
LOOP    JSR   POLCAT      ; poll keyboard
        BEQ   LOOP        ; Z=1 means no key
        ; A = key pressed
```

### Sound output (1-bit)
```
        LDA   PIA1_CB     ; $FF23
        ORA   #$08        ; bit 3 = sound enable
        STA   PIA1_CB
        LDA   PIA1_DA     ; $FF20
        EORA  #$02        ; toggle bit 1
        STA   PIA1_DA
```

### Set graphics mode (PMODE 4)
```
        LDA   #$F0        ; PMODE 4 VDG bits
        STA   PIA1_DB     ; $FF22
        STA   SAM_V2SET   ; $FFC5 - SAM mode
```
