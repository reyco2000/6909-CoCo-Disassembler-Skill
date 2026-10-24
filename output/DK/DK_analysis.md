# Donkey Kong (CoCo 3), DK.DSK analysis

**Program:** *Donkey Kong* for the Tandy Color Computer 3. The title screen credits **John Kowalski (Sock Master)** with "original Z80 code translated to 6809 and arcade hardware emulation". Donkey Kong is © 1981 Nintendo.

**Files in this folder**

| File | What it is |
|---|---|
| `DK_EMULATOR_listing.asm` | Annotated listing with address and hex columns, in the repo's `AAAA  hex  MNEMONIC OPERANDS ; comment` format |
| `DK_EMULATOR_src.asm` | The same code as source only (LWASM style: `ORG`, `SETDP $10`, `EQU` block, labels) |
| `DONKEY.BAS.txt` | The BASIC loader, detokenized |
| `DK_analysis.md` | This report |

---

## 1. Disk contents (RS-DOS, 35 tracks × 18 sectors)

| File | Type | Size | Contents |
|---|---|---|---|
| `DONKEY.BAS` | BASIC (tokenized) | 1,849 | Title screen, options menu, loader |
| `KONG.` | ML (DECB BIN) | 770 | One segment: 760 bytes at `$F0A5`, the CoCo 3 HPRINT font area, so it is a custom font for the title. EXEC `$B44A` just returns to BASIC. |
| `EMULATOR.BIN` | ML (DECB BIN) | 150,295 | 37 segments; this file fills the rest of the disk |

### EMULATOR.BIN segment layout
```
$FFA2 <- $1E          ; MMU task 0 slot 2 ($4000-$5FFF) = physical page $1E
$5800  2048 bytes     ; -> page $1E offset $1800
$FFA2 <- $1F ; $4000 8192 bytes
...                   ; one 8K block per page, pages $1F..$2D
$FFA2 <- $2E ; $4000 6061 bytes
$FFA2 <- $3A          ; normal page back in
$1019 19103 bytes     ; MAIN PROGRAM $1019-$5AB7   <-- disassembled
EXEC  $1114
```
LOADM writes about 128 KB into physical pages `$1E`–`$2E` by changing the MMU register `$FFA2` between segments. Those pages hold the packed sound samples, the compiled tile and sprite drawing routines with their pointer tables, and colour tables. Only the main program (`$1019`–`$5AB7`) is in the listing.

## 2. BASIC loader (`DONKEY.BAS`)
1. `PCLEAR14`, `LOADM"KONG."` (font), `POKE 65497,1` (fast CPU), `HSCREEN2`, then draws the title and credits.
2. `POKE 65496,1:LOADM"EMULATOR"`: drops back to slow speed for the disk load.
3. Options menu: **N**umber of lives, **B**onus, **D**ifficulty, **L**evel order (US/Japan), **P**alette (RGB/CMP), **S**ound (on/off).
4. `POKE 33000..33004` passes the choices to the machine code, then `EXEC` (address `$1114`):

| Address | BASIC | Used by |
|---|---|---|
| `$80E8` | `N + B*4` (lives 3–6, bonus 7000/10000/15000/20000) | `Setup` → `DipConfig` → `ReadDipSettings` |
| `$80E9` | difficulty | `Setup` patches the RNG step (`$1105`) and an operand at `$3581` |
| `$80EA` | level order | `Setup` copies the Japanese order over `TBL_StageOrder` (`$4E7D`) |
| `$80EB` | palette | `Setup` picks `PaletteRGB` or `PaletteCMP` |
| `$80EC` | sound | on: `UnpackSamples`; off: GIME timer reload patched to 0 (no FIRQ) |

## 3. How the port works

### 3.1 Z80 → 6809 translation
The arcade program was translated one instruction at a time, and it **keeps the arcade memory map** in plain CoCo RAM:

| Arcade address | Use |
|---|---|
| `$6000-$6BFF` | work RAM (`GameMode $6005`, `GameState $600A`, `NumCredits $6001`, scores `$60B2/$60B5/$60B8`, `MarioAlive $6200`, `ScreenNum $6227`, `Lives $6228`, `Level $6229`, ...) |
| `$60C0-$60FF` | task queue (ring buffer, pointers `$60B0`/`$60B1`) |
| `$6400` / `$6700` | fireball / barrel object tables (32 bytes per object) |
| `$6900-$6A7F` | sprite list, 4 bytes per sprite (X, code, attr, Y) |
| `$7400-$77FF` | tile (video) RAM, 32×32, rotated screen |
| `$7C00` / `$7D00-$7D07` / `$7D80` | sound-CPU latches: music / effects (walk, jump, boom, ...) / death |
| `$7D82` / `$7D83` / `$7D86-7` | flip screen / sprite bank / palette bank |

* **Z80 registers** live in the direct page (`DP = $10`): `<$02`/`<$03` = B/C (`<$02` is the DJNZ counter), `X` = HL, `Y` = DE, `<$0A` = IX. The EXX alternate set is kept at `<$0D`–`<$18` (`Z80_EXX`, `$533C`).
* **The Z80 `RST` routines became two-byte `JSR <xx` calls** into the direct page:

| DP call | Name | Z80 behaviour reproduced |
|---|---|---|
| `JSR <$2F` | `RST_RetIfAttract` | return from the caller too if no game is running (`$6007`) |
| `JSR <$38` | `RST_RetIfMarioDead` | ... unless Mario is alive (`$6200`) |
| `JSR <$3F` | `RST_WaitTimer` | `DEC $6009`, return from the caller until it reaches zero |
| `JSR <$47` | `RST_JumpTable` | the RST 28h jump table: an inline `FDB` table follows the JSR, indexed by B |
| `JSR <$4F`/`<$57` | `RST_AddToObjects` | add C to a field of 10 objects |
| `JSR <$64` | `RST_RetIfNotScreen` | return from the caller unless the current screen is in bitmask B |
| `JSR <$77` | `RST_CopySprites` | copy 20 words into the sprite list |

  Jump-table entries that pointed to Z80 address `$0000` now point to `ColdStart` (`$1114`), which marks unused entries.
* **Self-modifying code** is used heavily (sample pointers, palette and difficulty patches, tile renderer). The listing marks each patched instruction with `; SMC: operand patched by ...` and references the patched byte as `LABEL+n`.

### 3.2 Arcade hardware emulation (the new 6809 code)

| Routine | Address | What it emulates |
|---|---|---|
| `Setup` | `$588F` | Fast CPU (`$FFD9`). **HD6309 detect** (`CLRD` clears B only on a 6309; if found, `LDMD #1` switches to native mode). Palette, PIA sound, options, MMU task 1 copy, GIME timer FIRQ (`$01C8` ≈ 7.8 kHz), video 256×225×16, three video buffers, tile→screen table `$0000-$07FF`, compiled-routine pointer tables `$0800-$0FFF` from page `$29` |
| `Reset` / IRQ | `$12ED` | Stack `$6C00`, clears arcade RAM, writes `LDA $FF02 / INC <$20 / RTI` at `$FEF7` (60 Hz VSYNC counter) |
| `MainLoop` | `$136F` | Runs one arcade frame per VSYNC, with frame skipping when behind. Otherwise runs the arcade foreground loop (task queue / game logic). |
| `ArcadeVBlank` | `$111D` | The translated arcade NMI: inputs → `$6010`, RNG, sound latches, coins, game-mode dispatch |
| `ReadJoystick` | `$5628` | Joystick read through the PIA DAC + comparator (thresholds `$D8`/`$24`/`$B4`), 4 directions + button |
| `DrawDirtyTiles` | `$549F` | Compares tile RAM with a shadow copy kept in each video buffer and redraws only the tiles that changed, via **compiled tile routines** (`JSR ,U` with the code page mapped at `$2000`; pointers at `$0C00 + 4*tile`). Blank tile `$10` is cleared with `STU`. |
| `EraseMovedSprites` | `$557F` | Marks the tiles under moved sprites dirty (`$4F`) |
| `DrawSprites` | `$55DD` | **Compiled sprite routines** (`$0800 + 4*code`), screen address = Y·$70 + X |
| `FlipDrawPage` | `$56B8` | Triple buffering: pages `$30`/`$34`/`$3C` mapped at `$8000-$FEFF`, shown via the GIME vertical offset |
| `PaletteBankUpdate` | `$5366` | Arcade palette bank `$7D86/7` → colour tables |
| `SoundDriver` | `$56E1` | Latch changes → `TBL_MusicSamples` (16 tunes) / `TBL_SfxSamples` (10 entries, with priority). Patches the mixer's operands. |
| `FIRQ_SampleMixer` | `$1089` | GIME-timer FIRQ: maps the sample pages in with MMU task 1, adds one music byte and one effect byte, writes the sum to the DAC at `$FF20`. Both pointers are kept in its own operands. |
| `UnpackSamples` | `$59EA` | 1-bit delta-modulation (CVSD-like) decoder, 4 samples per byte. This is the "DECOMPRESSING DATA" step; the border flashes while it runs. |

### 3.3 Game logic (translated arcade code)
* Game mode `$6005` through `TBL_GameMode` (`$1162`): `Mode0_Init`, `Mode1_Attract` (8 states), `Mode2_Credited` (2), `Mode3_Game` (24 states in `TBL_GameState`, `$185A`).
* Task queue (`AddTask $4521`, `Y = task:param`). Handlers are in `TBL_Tasks` (`$13ED`):

| Task | Routine | Parameter |
|---|---|---|
| 0 | `Task0_AddScore` | index into `TBL_ScoreValues` (BCD) |
| 1 | `Task1_ClearScore` | 0 P1, 1 P2, 2 high, 3 all |
| 2 | `Task2_ShowScore` | 0 P1, 1 P2, 2 high, 3 all |
| 3 | `Task3_ShowString` | string number, bit 7 = erase |
| 4 | `Task4_ShowCredits` | – |
| 5 | `Task5_BonusTimer` | 0 = add bonus to score, else count down |
| 6 | `Task6_ShowLivesLevel` | – |

  Every `LDY #$03nn / JSR AddTask` in the listing carries the decoded string as a comment, e.g. `; show "HIGH SCORE"`.
* Strings (`TBL_Strings $4A67`) use the arcade tile code set (0–9 = `$00-$09`, space = `$10`, A–Z = `$11-$2A`, end = `$3F`). The table includes `GAME  OVER`, `PLAYER <I>/<II>`, `HIGH SCORE`, `CREDIT`, `HOW HIGH CAN YOU GET`, `ONLY 1 PLAYER BUTTON`, `1 OR 2 PLAYERS BUTTON`, `PUSH`, `NAME REGISTRATION`, `RANK  SCORE  NAME`, `YOUR NAME WAS REGISTERED`, `INSERT COIN`, `PLAYER  COIN`, `NINTENDO`, `1981`.
* Per-screen jump tables indexed by `ScreenNum $6227` (1 girders, 2 conveyors, 3 elevators, 4 rivets): `TBL_InitStage $2216`, `TBL_JumpOverStage $52A4`, `TBL_StageObjects $3CB5`.

## 4. Key routine index

| Addr | Name | Notes |
|---|---|---|
| `$1114` | `ColdStart` | EXEC entry: interrupts off, `DP=$10` |
| `$12ED` | `Reset` | init + IRQ install, falls into `MainLoop` |
| `$136F` | `MainLoop` | frame scheduler + foreground loop |
| `$13C4` | `TaskDispatch` | task queue consumer |
| `$111D` | `ArcadeVBlank` | translated NMI |
| `$1171` / `$11B1` | `SoundLatchUpdate` / `SoundReset` | arcade sound buffer → latches |
| `$11D2` | `CoinHandler` | coins → BCD credits |
| `$127D` | `ReadDipSettings` | options → arcade DIP values, default high scores |
| `$13FB` | `Blink1UP` | 1UP/2UP blink |
| `$1447` | `CheckExtraLife` | bonus life |
| `$1477` | `UpdateDifficulty` | difficulty from level/time |
| `$1630`–`$1801` | `Task0`…`Task6` | see the task table above |
| `$19D2` / `$19F9` | `ClearScreenAll` / `ClearPlayfield` | |
| `$1B00` | `ShowHighScoreTable` | |
| `$1C1F` | `Draw1UP` | |
| `$2187` | `InitStage` | per-stage object setup, bonus timer = level·10+40 (max 80) |
| `$3C91` / `$529D` | `CheckJumpOver` / `JumpOverCheck` | counts barrels/fireballs under a jumping Mario → points index |
| `$4521` | `AddTask` | |
| `$533C` | `Z80_EXX` | |
| `$5366`…`$56E1` | emulation layer | see §3.2 |
| `$588F` / `$59EA` | `Setup` / `UnpackSamples` | |

Each of the other ~120 subroutines has a header in the listing with its size, the arcade variables it uses and the routines it calls.

## 5. Method and verification
* Extracted the files from the RS-DOS directory and FAT, detokenized the BASIC, and split the BIN into its segments.
* Disassembled with **recursive descent** from `$1114` and the FIRQ handler. The tracer follows `JSR <$47` inline tables, `LEAY tbl,Y / LDX ,Y / JMP ,X` tables, `LDX #ret / PSHS X` return addresses, and vector installs. It reuses the opcode tables in `tools/dasm6809.py` and adds the two HD6309 opcodes used here (`CLRD`, `LDMD`, emitted as `FCB` with a comment).
* Result: 7,237 instructions (15,837 bytes of code), 19 jump tables (238 bytes), 3,028 bytes of data, 168 subroutines.
* **Checks:**
  * The listing covers every byte of `$1019-$5AB7` exactly once, and every `FCB`/`FDB`/`FILL` operand was compared against the image.
  * Every instruction's mnemonic and length matches the repo's `dasm6809.py` decoder.
  * **Not checked: reassembly.** No 6809 assembler was available in the session, so `DK_EMULATOR_src.asm` has not been built with lwasm. It uses `>`/`<` forcing on extended, direct and indexed operands so lwasm should reproduce the bytes, but that is unverified.

## 6. Caveats / open items
* Names come from reading the code plus the published layout of the Donkey Kong arcade memory map. The CoCo-side names (sections 3.1–3.2) were checked against the code. Some game-logic names are best guesses (`UpdateDifficulty`, `CheckJumpOver`, the `TBL_Step6385` states), and many game routines keep generic `SUB_xxxx` names with automatic summaries.
* Not disassembled: the banked pages `$1E-$2E` (compiled tile and sprite code, samples, colour tables) and the 2 KB block loaded at `$5800` in page `$1E`. Disassembling the compiled sprite code would need the page `$29` pointer tables (`$0800-$0FFF`) to locate the routines.
* Two hardware labels in the repo's `tools/dasm6809.py` are wrong and are overridden in this listing:
  * `$FFD8/$FFD9` are SAM **R1** clear/set (CPU rate), not `SAM_R0CLR/SET` (R0 is `$FFD6/$FFD7`).
  * `$FF40` is the disk **drive-control latch** (DSKREG), not the FDC command register (that is `$FF48`).
