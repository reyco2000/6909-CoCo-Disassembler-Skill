; =====================================================================
;  DONKEY KONG for the Tandy Color Computer 3  --  EMULATOR.BIN, main code
;  (c) John Kowalski "Sock Master": "original Z80 code translated to 6809
;  and arcade hardware emulation".  Donkey Kong (c) 1981 Nintendo.
;
;  Source disk: DK.DSK (RS-DOS, 35 tracks)
;    DONKEY.BAS   BASIC loader / title / options menu
;    KONG.        BIN, 760 bytes at $F0A5 = custom HPRINT font, EXEC $B44A
;    EMULATOR.BIN 150,295 bytes, 37 segments:
;       MMU $FFA2 <- $1E..$2E, each followed by an 8K block at $4000
;       (pages $1E-$2E = ~128K of packed graphics / compiled sprites /
;       sound samples), then $FFA2 <- $3A and the program below at
;       $1019-$5AB7, EXEC $1114.
;
;  BASIC passes the menu choices in $80E8-$80EC (POKE 33000..33004):
;    $80E8 lives (N 0-3 => 3-6) + bonus*4 (7000/10000/15000/20000)
;    $80E9 difficulty (0 easy, 1 hard)   $80EA level order (0 US, 1 Japan)
;    $80EB palette (0 RGB, 1 CMP)        $80EC sound (0 on, 1 off)
;
;  HOW IT WORKS
;  * The Z80 game program was translated instruction by instruction.  It
;    keeps the arcade memory map: work RAM $6000-$6BFF, sprite buffer
;    $6900-$6A7F, tile RAM $7400-$77FF, sound latches $7C00/$7D00-$7D07/
;    $7D80, palette bank $7D86/$7D87, flip $7D82 -- all ordinary CoCo RAM.
;  * Z80 registers live in the direct page (DP=$10): <$02/<$03 = B/C (B is
;    the DJNZ counter), X = HL, Y = DE, <$0A = IX; the EXX alternate set is
;    kept in <$0D-<$18 (see Z80_EXX).
;  * Z80 RST helpers became direct-page subroutines (JSR <$xx, 2 bytes):
;      <$2F RST_RetIfAttract  <$38 RST_RetIfMarioDead  <$3F RST_WaitTimer
;      <$47 RST_JumpTable (inline FDB table after the JSR, index in B)
;      <$4F/<$57 RST_AddToObjects  <$64 RST_RetIfNotScreen  <$77 RST_CopySprites
;    Z80 address $0000 (reset) in jump tables became ColdStart ($1114).
;  * Arcade hardware emulation runs once per 60 Hz frame (main loop):
;    the tile RAM is diffed against a shadow copy and changed tiles are
;    drawn by compiled tile routines; sprites are erased/redrawn with
;    compiled sprite routines (JSR ,U into MMU-banked pages at $2000);
;    the screen is drawn into one of three 32K buffers (pages $30/$34/$3C)
;    mapped at $8000-$FEFF, then shown via the GIME vertical offset.
;  * Sound: the arcade sound-CPU latches are turned into sample playback.
;    A GIME timer FIRQ (FIRQ_SampleMixer, patched by SoundDriver) mixes a
;    music stream and an effect stream into the 6-bit DAC at $FF20.
;  * Uses HD6309 native mode when present (Setup).
;
;  Listing produced with tools/dasm6809.py opcode tables + a recursive
;  descent driver (code/data split, jump tables, SMC markers).
;  "SMC:" = an operand rewritten at run time by the instruction named.
; =====================================================================

; ---------------------------------------------------------------
; Symbols (arcade memory map / CoCo 3 hardware) used below
; ---------------------------------------------------------------
NumCredits       EQU    $6001    ; credits (BCD)
CoinSwitch       EQU    $6003
GameMode         EQU    $6005    ; 0 init, 1 attract, 2 credited, 3 game
AttractFlag      EQU    $6007    ; 1 = attract / no game
MinorTimer       EQU    $6008
WaitTimer        EQU    $6009    ; frame countdown (RST_WaitTimer)
GameState        EQU    $600A    ; sub-state of GameMode
PlayerUp         EQU    $600D    ; 0 = player 1, 1 = player 2
Player2Ctrl      EQU    $600E
TwoPlayers       EQU    $600F
InputState       EQU    $6010    ; joystick+jump, bit7 = jump edge
InputPrev        EQU    $6011
RandNum          EQU    $6018    ; random number
RandTimer        EQU    $6019
FrameCounter     EQU    $601A    ; decremented every frame
DipLives         EQU    $6020    ; lives per game (DIP)
DipBonusLife     EQU    $6021    ; extra life at (BCD thousands)
DipCoinsLo       EQU    $6022
DipCoinsPerCredit EQU    $6024
DipCabinet       EQU    $6026
SndWalk          EQU    $6080    ; sound buffer: frames to hold latch
SndJump          EQU    $6081
SndBoom          EQU    $6082
SndCoin          EQU    $6083
SndFx4           EQU    $6084
SndFx5           EQU    $6085
SndDeath         EQU    $6088
MusicReq         EQU    $6089    ; music number request
MusicReq2        EQU    $608A
MusicCur         EQU    $608B
TaskWrPtr        EQU    $60B0    ; task queue write ptr (low byte)
TaskRdPtr        EQU    $60B1    ; task queue read ptr (low byte)
ScoreP1          EQU    $60B2    ; 3 BCD bytes
ScoreP2          EQU    $60B5    ; 3 BCD bytes
HiScore          EQU    $60B8    ; 3 BCD bytes
TaskQueue        EQU    $60C0    ; task ring buffer $60C0-$60FF
HiScoreTable     EQU    $6100
MarioAlive       EQU    $6200    ; bit0 = Mario alive
MarioX           EQU    $6203
MarioY           EQU    $6205
ScreenNum        EQU    $6227    ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
Lives            EQU    $6228    ; lives left
Level            EQU    $6229    ; level number
Difficulty       EQU    $6380
BonusTimer       EQU    $638C    ; bonus timer (BCD)
Fireballs        EQU    $6400    ; fireball objects, 32 bytes each
Barrels          EQU    $6700    ; barrel objects, 32 bytes each
SpriteBuf        EQU    $6900    ; arcade sprite list, 4 bytes/sprite
SpriteRAM        EQU    $7000    ; arcade sprite RAM (DMA dest.)
TileRAM          EQU    $7400    ; arcade tile RAM 32x32
MusicLatch       EQU    $7C00    ; music latch (arcade sound CPU)
SfxWalk          EQU    $7D00    ; walk sound latch
SfxJump          EQU    $7D01    ; jump sound latch
SfxBoom          EQU    $7D02    ; boom sound latch
SfxCoin          EQU    $7D03
Sfx4             EQU    $7D04
Sfx5             EQU    $7D05
Sfx6             EQU    $7D06
SfxDeath         EQU    $7D80    ; death sound / sound IRQ latch
FlipScreen       EQU    $7D82    ; flip screen
SpriteBank       EQU    $7D83
PaletteBank0     EQU    $7D86    ; palette bank bit 0
PaletteBank1     EQU    $7D87    ; palette bank bit 1
CfgLivesBonus    EQU    $80E8    ; BASIC POKE 33000
CfgDifficulty    EQU    $80E9    ; BASIC POKE 33001
CfgLevelOrder    EQU    $80EA    ; BASIC POKE 33002
CfgPalette       EQU    $80EB    ; BASIC POKE 33003
CfgSound         EQU    $80EC    ; BASIC POKE 33004
PIA0_DA          EQU    $FF00
PIA0_CA          EQU    $FF01
PIA0_CB          EQU    $FF03
PIA1_DA          EQU    $FF20
PIA1_CB          EQU    $FF23
DSKREG           EQU    $FF40    ; disk drive control latch
GIME_INIT0       EQU    $FF90
GIME_INIT1       EQU    $FF91
GIME_FIRQEN      EQU    $FF93
GIME_TMRHI       EQU    $FF94
GIME_VMODE       EQU    $FF98
GIME_BORDER      EQU    $FF9A
GIME_VOFFLO      EQU    $FF9D
GIME_HOFFHI      EQU    $FF9E
MMU_T0_P1        EQU    $FFA1
MMU_T0_P4        EQU    $FFA4
MMU_T0_P5        EQU    $FFA5
MMU_T0_P6        EQU    $FFA6
MMU_T0_P7        EQU    $FFA7
MMU_T1_P3        EQU    $FFAB
MMU_T1_P4        EQU    $FFAC
PAL_3            EQU    $FFB3
PAL_5            EQU    $FFB5
SAM_R1SET        EQU    $FFD9    ; SAM R1=1: 1.79 MHz CPU

        ORG    $1019
        SETDP  $10


; =====================================================================
; Direct page variables ($1019-$102E, DP=$10).  <$00-$18 are the
; Z80 register images and are not loaded from disk.
; =====================================================================
                 FCB    $FC,$86
JoyPrev          FCB    $00
JoyNow           FCB    $00
JoyP2            FCB    $00
CoinStartBits    FCB    $00
DipConfig        FCB    $80
VsyncCount       FCB    $00
FrameSkip        FCB    $00
LoopCount        FCB    $00
DrawPage         FCB    $30
DeltaHi          FCB    $00
DeltaLo          FCB    $00
DeltaStep        FCB    $01
SndSrcPage       FCB    $00
SndSrcPage2      FCB    $1E
BitCount         FCB    $04
LastMusic        FCB    $00
LastSfx          FCB    $FF
SfxPriority      FCB    $00
MusicPage        FCB    $04
SfxPage          FCB    $00

; =====================================================================
; Z80 RST equivalents, called with 2-byte JSR <xx.
; RST_RetIfAttract: if $6007 bit0 (attract / no credit) => return from
; the CALLER as well (LEAS 2,S ; RTS) - the Z80 'pop hl ; ret' trick.
; =====================================================================
RST_RetIfAttract LDB    >AttractFlag ; 1 = attract / no game
                 LSRB
                 BCC    L_1037
L_1035           LEAS   2,S
L_1037           RTS

; =====================================================================
; RST_RetIfMarioDead: return from caller unless $6200 (Mario alive) bit0.
; =====================================================================
RST_RetIfMarioDead LDB    >MarioAlive ; bit0 = Mario alive
                 LSRB
                 BCC    L_1035
                 RTS

; =====================================================================
; RST_WaitTimer: DEC $6009 ; return from caller until it reaches 0.
; =====================================================================
RST_WaitTimer    LDX    #WaitTimer
                 DEC    ,X
                 BNE    L_1035
                 RTS

; =====================================================================
; RST_JumpTable (Z80 RST 28h): B = index, the FDB table follows the
; calling JSR.  Pulls the return address as table base and jumps.
; =====================================================================
RST_JumpTable    ASLB
                 PULS   X
                 ABX
                 LDX    ,X+
                 JMP    ,X

; =====================================================================
; RST_AddToObjects: add C (<$03) to byte ,X of 10 objects, stride 4.
; =====================================================================
RST_AddToObjects LDY    #$0004
                 LDA    #$0A
                 STA    <$02

; =====================================================================
; RST_AddToObjectsB (7 instructions)
; =====================================================================
RST_AddToObjectsB LDB    <$03
                 ADDB   ,X
                 STB    ,X
                 LEAX   4,X
                 DEC    <$02
                 BNE    RST_AddToObjectsB
L_1063           RTS

; =====================================================================
; RST_RetIfNotScreen: B = bitmask of stages (bit0 = screen 1 ...).
; Rotates B by the current screen $6227; returns from the caller when the
; current screen is not in the mask.
; =====================================================================
RST_RetIfNotScreen LDX    #ScreenNum
                 LDA    ,X
L_1069           LSRB
                 BCC    L_106E
                 ORB    #$80
L_106E           DECA
                 BNE    L_1069
                 STA    <$02
                 BCS    L_1063
                 PULS   X,PC

; =====================================================================
; RST_CopySprites: copy 20 words from X to the sprite buffer $6908.
; =====================================================================
RST_CopySprites  LDY    #$6908
                 LDA    #$14
                 STU    <$08
L_107F           LDU    ,X++
                 STU    ,Y++
                 DECA
                 BNE    L_107F
                 LDU    <$08
                 RTS

; =====================================================================
; FIRQ_SampleMixer - GIME timer FIRQ (~7.8 kHz, vector $FEF4 = JMP <$89).
; Switches to MMU task 1 so the music sample page appears at $6000 and the
; effect page at $8000, adds one music byte + one effect byte and writes
; the sum to the DAC ($FF20).  Both sample pointers live in the operands of
; the LDA/ADDA below and are advanced in place.  When the effect ends the
; ADDA is patched into a harmless instruction.  A is saved in the operand
; of the final LDA #.
; =====================================================================
FIRQ_SampleMixer STA    <L_10F9+1
                 LDA    >GIME_FIRQEN ; GIME_FIRQEN - FIRQ enable: TMR|HBORD|VBORD|EI2-0
                 LDA    #$21
                 STA    >GIME_INIT1 ; GIME_INIT1 - Init 1: timer input, task select
L_1093           LDA    >$658B ; SMC: operand patched by L_10D2,$10D6,$10DC,$10E7,$10EB,$5723
L_1096           ADDA   >$89FF ; SMC: operand patched by L_109C,$10A0,$10A2,$10A8,$10B7,$10BB,$579F
L_1099           STA    >PIA1_DA ; SMC: operand patched by $10C3,$10C7,$57B1; PIA1_DA
L_109C           DEC    <L_1096+2
                 BHI    L_10D2
                 DEC    <L_1096+2
                 DEC    <L_1096+1
                 BMI    L_10D2
                 LDA    #$9F
                 STA    <L_1096+1
                 LDA    <SfxPage
                 DECA
L_10AD           CMPA   #$00 ; SMC: operand patched by $57A3
                 BGE    L_10CD
                 LDA    #$8B
                 STA    <L_1096
                 LDA    #$44
                 STA    <L_1096+1
                 LDA    #$B7
                 STA    <L_1096+2
                 LDA    #$FF
                 STA    <L_1099
                 LDA    #$20
                 STA    <L_1099+1
                 LDA    #$0E
                 STA    <L_1099+2
                 LDA    #$D2
                 STA    <L_109C
L_10CD           STA    >MMU_T1_P4 ; MMU_T1_P4 - Task1 page4 ($8000-$9FFF)
                 STA    <SfxPage
L_10D2           INC    <L_1093+2
                 BNE    L_10F4
                 INC    <L_1093+1
                 BPL    L_10F4
                 LDA    #$60
                 STA    <L_1093+1
                 LDA    <MusicPage
                 INCA
L_10E1           CMPA   #$05 ; SMC: operand patched by $5727
                 BLS    L_10EF
L_10E5           LDA    #$00 ; SMC: operand patched by $5731
                 STA    <L_1093+2
L_10E9           LDA    #$7E ; SMC: operand patched by $572D
                 STA    <L_1093+1
L_10ED           LDA    #$05 ; SMC: operand patched by $572B
L_10EF           STA    >MMU_T1_P3 ; MMU_T1_P3 - Task1 page3 ($6000-$7FFF)
                 STA    <MusicPage
L_10F4           LDA    #$20
                 STA    >GIME_INIT1 ; GIME_INIT1 - Init 1: timer input, task select
L_10F9           LDA    #$00 ; SMC: operand patched by FIRQ_SampleMixer
                 RTI

; =====================================================================
; UpdateRandom: $6018 += $601A + $6019 (arcade RNG).
; =====================================================================
UpdateRandom     LDB    >RandNum ; random number
                 ADDB   >FrameCounter ; decremented every frame
                 ADDB   >RandTimer
L_1105           ADDB   #$00 ; difficulty: 0 easy / 5 hard (patched by Setup)  [SMC: operand patched by $58E4]
                 STB    >RandNum ; random number
                 RTS

; =====================================================================
; MinorTimerWait: DEC $6008; when 0 fall into RST_WaitTimer, else
; return from caller.
; =====================================================================
MinorTimerWait   DEC    >MinorTimer
                 BNE    L_1112
                 JMP    <RST_WaitTimer
L_1112           PULS   X,PC

; =====================================================================
; ColdStart - EXEC entry.  Interrupts off, DP=$10.
; =====================================================================
ColdStart        ORCC   #$50 ; mask IRQ+FIRQ
                 LDB    #$10
                 TFR    B,DP ; DP = $10 (Z80 register file)
                 JMP    >Reset

; =====================================================================
; ArcadeVBlank - the translated arcade NMI (vertical blank) routine.
; Builds the input byte $6010/$6011 from the CoCo joystick (P1 or P2),
; updates RNG and sound latches, handles coins, then dispatches the game
; mode $6005 through RST_JumpTable:
;   0 Mode0_Init  1 Mode1_Attract  2 Mode2_Credited  3 Mode3_Game
; =====================================================================
ArcadeVBlank     LDD    <$02
                 LDX    <$0A
                 PSHS   A,B,X
                 LDB    >AttractFlag ; 1 = attract / no game
                 BNE    L_114E
                 LDB    >DipCabinet
                 BNE    L_1134
                 LDA    <JoyP2
                 LDB    >Player2Ctrl
                 BNE    L_1136
L_1134           LDA    <JoyNow
L_1136           STA    <$02
                 ANDA   #$0F
                 STA    <$03
                 LDA    >InputPrev
                 COMA
                 ANDA   <$02
                 ANDA   #$10
                 ASLA
                 ROLA
                 ROLA
                 ORA    <$03
                 LDB    <$02
                 STD    >InputState ; joystick+jump, bit7 = jump edge
L_114E           DEC    >FrameCounter ; decremented every frame
                 BSR    UpdateRandom
                 JSR    >CoinHandler
                 BSR    SoundLatchUpdate
                 LDX    #L_116A
                 PSHS   X
                 LDB    >GameMode ; 0 init, 1 attract, 2 credited, 3 game
                 JSR    <RST_JumpTable ; game mode
TBL_GameMode     FDB    Mode0_Init ; 0
                 FDB    Mode1_Attract ; 1
                 FDB    Mode2_Credited ; 2
                 FDB    Mode3_Game ; 3
L_116A           PULS   A,B,X
                 STX    <$0A
                 STD    <$02
                 RTS

; =====================================================================
; SoundLatchUpdate: arcade sound buffer $6080-$6087 => latches
; $7D00-$7D07 (1 while the duration counter is non-zero), $608A/$608B
; => music latch $7C00, $6088 => death sound $7D80.
; =====================================================================
SoundLatchUpdate LDX    #SndWalk
                 LDY    #SfxWalk
                 LDB    >AttractFlag ; 1 = attract / no game
                 BNE    L_11B0
                 LDA    #$08
L_117F           LDB    ,X
                 BEQ    L_1187
                 DEC    ,X
                 LDB    #$01
L_1187           STB    ,Y+
                 LEAX   1,X
                 DECA
                 BNE    L_117F
                 STA    <$02
                 LDX    #MusicCur
                 LDB    ,X
                 BNE    L_119B
                 LDB    ,--X
                 BRA    L_119F
L_119B           DEC    ,X
                 LDB    ,-X
L_119F           STB    >MusicLatch ; music latch (arcade sound CPU)
                 LDX    #SndDeath
                 CLRB
                 CMPB   ,X
                 BEQ    L_11AD
                 DEC    ,X
                 INCB
L_11AD           STB    >SfxDeath ; death sound / sound IRQ latch
L_11B0           RTS

; =====================================================================
; SoundReset: clear all sound latches and the sound buffer.
; =====================================================================
SoundReset       LDA    #$08
                 CLRB
                 LDX    #SfxWalk
                 LDY    #SndWalk
L_11BB           STB    ,X+
                 STB    ,Y+
                 DECA
                 BNE    L_11BB
                 LDA    #$04
L_11C4           STB    ,Y+
                 DECA
                 BNE    L_11C4
                 STA    <$02
                 STB    >SfxDeath ; death sound / sound IRQ latch
                 STB    >MusicLatch ; music latch (arcade sound CPU)
                 RTS

; =====================================================================
; CoinHandler: CoinStartBits bit7 = coin.  Flashes palette 3/5, plays
; the coin sound, counts coins against $6024 (coins per credit) and adds
; one BCD credit to $6001 (max 90), then queues Task4 (show credits).
; =====================================================================
CoinHandler      LDB    <CoinStartBits
                 LDX    #CoinSwitch
                 TSTB
                 BMI    L_11DF
                 LDA    #$01
                 STA    ,X
                 RTS
L_11DF           LDA    >D_5A9B
                 LDB    >D_5A9D
                 STA    >PAL_3 ; PAL_3 - Palette 3 (6-bit RGB)
                 STB    >PAL_5 ; PAL_5 - Palette 5 (6-bit RGB)
                 LDB    ,X
                 BEQ    L_1228
                 PSHS   X
                 LDB    >GameMode ; 0 init, 1 attract, 2 credited, 3 game
                 CMPB   #$03
                 BEQ    L_1200
                 JSR    >SoundReset
                 LDB    #$03
                 STB    >SndCoin
L_1200           PULS   X
                 CLR    ,X
                 INC    ,-X
                 LDY    #DipCoinsPerCredit
                 LDB    ,Y
                 SUBB   ,X
                 BNE    L_1228
                 STB    ,X
                 LEAY   1,Y
                 EXG    Y,X
                 LDA    ,-Y
                 CMPA   #$90
                 BCC    L_1228
                 ADDA   ,X
                 DAA
                 STA    ,Y
                 LDY    #$0400 ; queue ShowCredits(0)
                 JSR    >AddTask
L_1228           RTS
D_1229           FCB    $00,$37,$00,$AA,$AA
D_122E           FCB    $AA,$50,$76,$00

; =====================================================================
; Mode0_Init: clear scores, set attract flag, read DIP settings,
; queue HIGH SCORE strings and score displays, go to mode 1.
; =====================================================================
Mode0_Init       JSR    >ClearPlayfield
                 LDX    #D_1229
                 LDY    #ScoreP1
                 LDB    #$09
L_123E           LDA    ,X+
                 STA    ,Y+
                 DECB
                 BNE    L_123E
                 LDB    #$01
                 STB    >AttractFlag ; 1 = attract / no game
                 STB    >Level ; level number
                 STB    >Lives ; lives left
                 JSR    >Task6_ShowLivesLevel
                 BSR    ReadDipSettings
                 LDB    #$01
                 STB    >FlipScreen ; flip screen
                 STB    >GameMode ; 0 init, 1 attract, 2 credited, 3 game
                 STB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 CLRB
                 STB    >GameState ; sub-state of GameMode
                 JSR    >Draw1UP
                 LDY    #$0304 ; show "HIGH SCORE"
                 JSR    >AddTask
                 LDY    #$0202 ; queue ShowScore(2)
                 JSR    >AddTask
                 LDY    #$0200 ; queue ShowScore(0)
                 JSR    >AddTask
                 RTS

; =====================================================================
; ReadDipSettings: build the arcade DIP switch values from DipConfig
; (set from the BASIC menu): $6020 lives (3-6), $6021 bonus life
; (BCD 07/10/15/20 thousand), $6022-$6025 coin/credit ratios,
; $6026 cabinet; copy the default high-score table to $6100.
; =====================================================================
ReadDipSettings  LDB    <DipConfig
                 STB    <$03
                 LDX    #DipLives
                 ANDB   #$03
                 ADDB   #$03
                 STB    ,X+
                 LDB    <$03
                 RORB
                 RORB
                 LDA    #$07
                 ANDB   #$03
                 BEQ    L_129C
                 LDA    #$05
L_1296           ADDA   #$05
                 DAA
                 DECB
                 BNE    L_1296
L_129C           STA    ,X+
                 LDB    <$03
                 STU    <$08
                 LDU    #$0101
                 STU    <$02
                 LDU    #$0102
                 STU    <$04
                 ANDB   #$70
                 ASLB
                 ROLB
                 ROLB
                 ROLB
                 BEQ    L_12C8
                 BCS    L_12BF
                 INCB
                 STB    <$03
                 LDA    <$04
                 STA    <$05
                 BRA    L_12C8
L_12BF           ADDB   #$02
                 STB    <$02
                 STB    <$04
                 ASLB
                 STB    <$05
L_12C8           LDU    <$04
                 STU    ,X++
                 LDU    <$02
                 STU    ,X++
                 LDB    <DipConfig
                 ROLB
                 LDB    #$01
                 BCS    L_12D8
                 DECB
L_12D8           STB    ,X
                 LDX    #DefaultHiScores
                 LDY    #HiScoreTable
                 LDA    #$55
L_12E3           LDU    ,X++
                 STU    ,Y++
                 DECA
                 BNE    L_12E3
                 LDU    <$08
                 RTS

; =====================================================================
; Reset: stack at $6C00, Setup (GIME / MMU / sound / video), clear
; arcade RAM $6000-$6FFF, sprite RAM $7000, tile RAM $7400 (tile $10 =
; blank), task queue $60C0 = $FF, install IRQ code at $FEF7:
;    LDA $FF02 / INC <$20 / RTI    (60 Hz VSYNC counter)
; =====================================================================
Reset            LDS    #$6C00 ; arcade stack top
                 JSR    >Setup
                 LDA    #$10
                 STA    <$02
                 LDX    #$6000
                 CLRB
L_12FC           CLRA
L_12FD           STB    ,X+
                 DECA
                 BNE    L_12FD
                 DEC    <$02
                 BNE    L_12FC
                 LDA    #$04
                 STA    <$02
                 LDX    #SpriteRAM
L_130D           CLRA
L_130E           STB    ,X+
                 DECA
                 BNE    L_130E
                 DEC    <$02
                 BNE    L_130D
                 LDA    #$04
                 STA    <$02
                 LDB    #$10
                 LDX    #TileRAM
L_1320           CLRA
L_1321           STB    ,X+
                 DECA
                 BNE    L_1321
                 DEC    <$02
                 BNE    L_1320
                 LDX    #TaskQueue
                 LDA    #$40
                 LDB    #$FF
L_1331           STB    ,X+
                 DECA
                 BNE    L_1331
                 LDB    #$C0
                 STB    >TaskWrPtr ; task queue write ptr (low byte)
                 STB    >TaskRdPtr ; task queue read ptr (low byte)
                 CLRB
                 STB    >SpriteBank
                 STB    >PaletteBank0 ; palette bank bit 0
                 STB    >PaletteBank1 ; palette bank bit 1
                 JSR    >PaletteBankUpdate
                 INCB
                 STB    >FlipScreen ; flip screen
                 JSR    >SoundReset
                 LDX    #$FEF7 ; IRQ vector $FEF7:
                 LDD    #$B6FF
                 STD    ,X++
                 LDD    #$020C
                 STD    ,X++
                 LDD    #$203B
                 STD    ,X
                 LDB    #$35 ; PIA0 CB1 VSYNC IRQ on
                 STB    >PIA0_CB ; PIA0_CB
                 ANDCC  #$AF ; interrupts on
                 LDA    #$01
                 STA    <VsyncCount

; =====================================================================
; MainLoop.  The IRQ adds 1 to VsyncCount every 60 Hz frame; each
; pending VSYNC runs one arcade frame: ReadJoystick (consumes one count),
; SoundDriver, ArcadeVBlank.  The screen is redrawn on that frame
; (EraseMovedSprites, DrawDirtyTiles, DrawSprites, FlipDrawPage) unless
; the game is more than 2 frames behind - but at least every 7 frames
; (FrameSkip).  VSYNC is checked on 7 of every 8 loop passes.
; In between, the arcade foreground loop: run one queued task ($60C0 ring,
; read pointer $60B1) or, with an empty queue, Blink1UP / CheckExtraLife
; and once per arcade frame UpdateDifficulty + SUB_14A9.
; =====================================================================
MainLoop         INC    <LoopCount
                 LDA    <LoopCount
                 ANDA   #$07
                 BEQ    L_139C
                 LDA    <VsyncCount
                 BEQ    L_139C
                 DEC    <FrameSkip
                 BEQ    L_1383
                 CMPA   #$02
                 BHI    L_1393
L_1383           JSR    >EraseMovedSprites
                 JSR    >DrawDirtyTiles
                 JSR    >DrawSprites
                 JSR    >FlipDrawPage
                 LDA    #$07
                 STA    <FrameSkip
L_1393           JSR    >ReadJoystick
                 JSR    >SoundDriver
                 JSR    >ArcadeVBlank
L_139C           LDA    #$60
                 LDB    >TaskRdPtr ; task queue read ptr (low byte)
                 TFR    D,X
                 LDB    ,X
                 ASLB
                 BCC    TaskDispatch
                 BSR    Blink1UP
                 JSR    >CheckExtraLife
                 INC    >RandTimer
                 LDX    #$6383
                 LDB    >FrameCounter ; decremented every frame
                 CMPB   ,X
                 BEQ    MainLoop
                 STB    ,X
                 JSR    >UpdateDifficulty
                 JSR    >SUB_14A9
                 BRA    MainLoop

; =====================================================================
; TaskDispatch: queue entry = task number (low 5 bits), parameter.
; Return address is MainLoop.
; =====================================================================
TaskDispatch     ANDB   #$1F
                 CLRA
                 TFR    D,Y
                 LDA    #$FF
                 STA    ,X+
                 LDB    ,X
                 STB    <$03
                 STA    ,X+
                 TFR    X,D
                 CMPB   #$C0
                 BCC    L_13DB
                 LDB    #$C0
L_13DB           STB    >TaskRdPtr ; task queue read ptr (low byte)
                 LDB    <$03
                 LDX    #MainLoop
                 PSHS   X
                 LEAY   >TBL_Tasks,Y
                 LDX    ,Y
                 JMP    ,X

; =====================================================================
; Task table (queued with AddTask, Y = task:param).
; =====================================================================
TBL_Tasks        FDB    Task0_AddScore
                 FDB    Task1_ClearScore
                 FDB    Task2_ShowScore
                 FDB    Task3_ShowString
                 FDB    Task4_ShowCredits
                 FDB    Task5_BonusTimer
                 FDB    Task6_ShowLivesLevel

; =====================================================================
; Blink1UP: every 16 frames toggles the '1UP' / '2UP' indicator.
; =====================================================================
Blink1UP         LDB    >FrameCounter ; decremented every frame
                 STB    <$02
                 ANDB   #$0F
                 BNE    L_143C
                 JSR    <RST_RetIfAttract
                 LDB    >PlayerUp ; 0 = player 1, 1 = player 2
                 BSR    PlayerUpVramAddr
                 LDA    <$02
                 ANDA   #$10
                 BEQ    L_142B
                 LDB    #$10
                 STB    ,X
                 LEAX   <-32,X
                 STB    ,X
                 LEAX   <-32,X
                 STB    ,X
                 LDB    >TwoPlayers
                 BEQ    L_143C
                 LDB    >PlayerUp ; 0 = player 1, 1 = player 2
                 EORB   #$01
                 BSR    PlayerUpVramAddr
L_142B           INCB
                 STB    ,X
                 LEAX   <-32,X
                 LDA    #$25
                 STA    ,X
                 LEAX   <-32,X
                 LDA    #$20
                 STA    ,X
L_143C           RTS

; =====================================================================
; PlayerUpVramAddr (5 instructions)
; Uses:  $7740 $74E0
; =====================================================================
PlayerUpVramAddr LDX    #$7740
                 TSTB
                 BEQ    L_143C
                 LDX    #$74E0
                 RTS

; =====================================================================
; CheckExtraLife: compare the current player's score with the bonus
; threshold $6021 and award one life ($6228) once ($622D).
; =====================================================================
CheckExtraLife   LDB    >$622D
                 BNE    L_143C
                 LDX    #$60B3
                 LDB    >PlayerUp ; 0 = player 1, 1 = player 2
                 BEQ    L_1457
                 LDX    #$60B6
L_1457           LDB    ,X+
                 LDA    ,X
                 LSRA
                 RORB
                 LSRA
                 RORB
                 LSRA
                 RORB
                 LSRA
                 RORB
                 LDX    #DipBonusLife
                 CMPB   ,X
                 BCS    L_143C
                 LDB    #$01
                 STB    >$622D
                 LDX    #Lives
                 INC    ,X
                 JMP    >Task6_ShowLivesLevel

; =====================================================================
; UpdateDifficulty: internal difficulty $6380 from level $6229 and time.
; =====================================================================
UpdateDifficulty LDX    #$6384
                 LDB    ,X
                 INC    ,X
                 TSTB
                 BNE    L_14A8
                 LDX    #$6381
                 LDA    ,X
                 STA    <$02
                 INC    ,X
                 ANDA   #$07
                 BNE    L_14A8
                 LDB    <$02
                 LDA    <$02
                 LSRB
                 RORA
                 LSRB
                 RORA
                 LSRB
                 RORA
                 STA    <$02
                 LDB    >Level ; level number
                 ADDB   <$02
                 CMPB   #$05
                 BCS    L_14A5
                 LDB    #$05
L_14A5           STB    >Difficulty
L_14A8           RTS

; =====================================================================
; SUB_14A9 (38 instructions)
; Uses:  $6350 $62B8 $62B9 $6A29 $66A0 $62BA $63A0
; Calls: RST_RetIfNotScreen RST_RetIfMarioDead SUB_14FA
; =====================================================================
SUB_14A9         LDB    #$03
                 JSR    <RST_RetIfNotScreen
                 JSR    <RST_RetIfMarioDead
                 LDB    >$6350
                 RORB
                 BCS    L_14A8
                 LDX    #$62B8
                 DEC    ,X
                 BNE    L_14A8
                 LDA    #$04
                 STA    ,X
                 LDB    >$62B9
                 RORB
                 BCC    L_14A8
                 LDX    #$6A29
                 LDA    #$40
                 LDU    #$66A0
                 RORB
                 BCC    L_14F0
                 LDB    #$02
                 STB    9,U
                 STB    10,U
                 ADDA   #$02
                 BSR    SUB_14FA
                 LDX    #$62BA
                 DEC    ,X
                 BNE    L_14A8
                 LDB    #$01
                 STB    >$62B9
                 STB    >$63A0
L_14EA           LDB    #$10
                 STB    >$62BA
                 RTS
L_14F0           LDB    #$02
                 STB    9,U
                 CLR    10,U
                 BSR    SUB_14FA
                 BRA    L_14EA

; =====================================================================
; SUB_14FA (7 instructions)
; Uses:  RandTimer
; =====================================================================
SUB_14FA         STA    ,X
                 LDB    >RandTimer
                 RORB
                 BCS    L_1505
                 INCA
                 STA    ,X
L_1505           RTS

; =====================================================================
; SUB_1506 (122 instructions)
; Uses:  ScreenNum $6908 $63A3 $6910 $63B7 $6391 FrameCounter $6390 $6393 SndBoom $690B $75C4 $6905 $7623 ...
; Calls: RST_AddToObjects RST_CopySprites SUB_161C
; =====================================================================
SUB_1506         LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 CMPB   #$02
                 BNE    L_151F
                 LDX    #$6908
                 LDB    >$63A3
                 STB    <$03
                 JSR    <RST_AddToObjects
                 LDB    >$6910
                 SUBB   #$3B
                 STB    >$63B7
L_151F           LDB    >$6391
                 BNE    L_152E
                 LDB    >FrameCounter ; decremented every frame
                 BNE    L_158F
                 LDB    #$01
                 STB    >$6391
L_152E           LDX    #$6390
                 INC    ,X
                 LDB    ,X
                 CMPB   #$80
                 BEQ    L_156D
                 LDB    >$6393
                 BNE    L_158F
                 LDB    ,X
                 STB    <$02
                 ANDB   #$1F
                 BNE    L_158F
                 LDX    #D_4DE7
                 LDA    <$02
                 ANDA   #$20
                 BNE    L_1552
                 LDX    #D_4E0F
L_1552           JSR    <RST_CopySprites
                 LDB    #$03
                 STB    >SndBoom
L_1559           LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 RORB
                 BCC    L_157E
                 RORB
                 BCS    L_158F
                 LDX    #$690B
                 LDA    #$FC
                 STA    <$03
                 JSR    <RST_AddToObjects
                 BRA    L_158F
L_156D           CLRB
                 STB    ,X+
                 STB    ,X
                 LDB    >$6393
                 BNE    L_158F
                 LDX    #D_4DB7
                 JSR    <RST_CopySprites
                 BRA    L_1559
L_157E           LDX    #$6908
                 LDA    #$44
                 STA    <$03
                 RORB
                 BCC    L_158D
                 LDB    >$63B7
                 STB    <$03
L_158D           JSR    <RST_AddToObjects
L_158F           LDB    >$6390
                 STB    <$03
                 LDY    #$0020
                 LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 CMPB   #$04
                 BEQ    L_15CE
                 LDB    <$03
                 BEQ    L_15AB
                 LDB    #$EF
                 LDA    <$03
                 ANDA   #$40
                 BNE    L_15AD
L_15AB           LDB    #$10
L_15AD           LDX    #$75C4
                 BSR    SUB_161C
                 LDB    >$6905
L_15B5           STB    >$6905
                 LDA    <$03
                 ANDA   #$40
                 BEQ    L_15CD
                 STB    <$02
                 LDB    <$03
                 ANDB   #$07
                 BNE    L_15CD
                 LDB    <$02
                 EORB   #$03
                 STB    >$6905
L_15CD           RTS
L_15CE           LDB    #$10
                 LDX    #$7623
                 BSR    SUB_161C
                 LDX    #$7583
                 BSR    SUB_161C
                 LDA    <$03
                 ANDA   #$40
                 BEQ    L_1613
                 LDB    >MarioX
                 CMPB   #$80
                 BCC    L_15FD
                 LDB    #$DF
                 LDX    #$7623
                 BSR    SUB_161C
L_15EE           LDB    >$6901
                 ORB    #$80
                 STB    >$6901
                 LDB    >$6905
                 ORB    #$80
                 BRA    L_15B5
L_15FD           LDB    #$EF
                 LDX    #$7583
                 BSR    SUB_161C
L_1604           LDB    >$6901
                 ANDB   #$7F
                 STB    >$6901
                 LDB    >$6905
                 ANDB   #$7F
                 BRA    L_15B5
L_1613           LDB    >MarioX
                 CMPB   #$80
                 BCC    L_1604
                 BRA    L_15EE

; =====================================================================
; SUB_161C (11 instructions)
; =====================================================================
SUB_161C         LDA    #$03
                 STA    <$02
L_1620           STB    ,X
                 STB    <$01
                 TFR    Y,D
                 LEAX   D,X
                 LDB    <$01
                 DECB
                 DEC    <$02
                 BNE    L_1620
                 RTS

; =====================================================================
; Task 0 - AddScore: B = index into TBL_ScoreValues (3-byte BCD),
; adds to the current player's score ($60B2 / $60B5), redraws it and
; updates the high score $60B8 when beaten.
; =====================================================================
Task0_AddScore   STB    <$03
                 JSR    <RST_RetIfAttract
                 BSR    GetScorePtr
                 LDB    <$03
                 ADDB   <$03
                 ADDB   <$03
                 LDX    #TBL_ScoreValues
                 ABX
                 CLRA
                 LDB    #$03
L_1643           LDA    ,Y
                 ADCA   ,X+
                 DAA
                 STA    ,Y+
                 DECB
                 BNE    L_1643
                 PSHS   Y
                 LEAY   -1,Y
                 LDB    >PlayerUp ; 0 = player 1, 1 = player 2
                 BSR    DrawScore
                 PULS   Y
                 LEAY   -1,Y
                 LDX    #$60BA
                 LDA    #$03
L_165F           LDB    ,Y
                 CMPB   ,X
                 BCS    L_166E
                 BNE    L_166F
                 LEAY   -1,Y
                 LEAX   -1,X
                 DECA
                 BNE    L_165F
L_166E           RTS
L_166F           BSR    GetScorePtr
                 LDX    #HiScore
L_1674           LDB    ,Y+
                 STB    ,X+
                 DECA
                 BNE    L_1674
                 JMP    >L_16FA

; =====================================================================
; GetScorePtr: Y = $60B2 (player 1) or $60B5 (player 2).
; =====================================================================
GetScorePtr      LDY    #ScoreP1
                 LDB    >PlayerUp ; 0 = player 1, 1 = player 2
                 BEQ    L_168B
                 LDY    #ScoreP2
L_168B           RTS

; =====================================================================
; DrawScore: draw the 6 BCD digits at Y to tile RAM (U).
; =====================================================================
DrawScore        LDU    #$7781
                 TSTB
                 BEQ    DrawBCD
                 LDU    #$7521
                 BRA    DrawBCD
L_1697           LDU    #$7641

; =====================================================================
; DrawBCD (15 instructions)
; Calls: DrawDigit
; =====================================================================
DrawBCD          TFR    Y,X
                 LDD    #$0304
                 STD    <$02
L_16A1           LDB    ,X
                 RORB
                 RORB
                 RORB
                 RORB
                 BSR    DrawDigit
                 LDB    ,X
                 BSR    DrawDigit
                 LEAX   -1,X
                 DEC    <$02
                 BNE    L_16A1
                 RTS

; =====================================================================
; DrawDigit (4 instructions)
; =====================================================================
DrawDigit        ANDB   #$0F
                 STB    ,U
                 LEAU   <-32,U
                 RTS

; =====================================================================
; Task 1 - ClearScore: B = 0 P1, 1 P2, 2 high score, 3 all.
; =====================================================================
Task1_ClearScore CMPB   #$03
                 BCC    L_16DD
                 PSHS   B
                 LDX    #ScoreP1
                 TSTB
                 BEQ    L_16CB
                 LDX    #ScoreP2
L_16CB           CMPB   #$02
                 BNE    L_16D2
                 LDX    #HiScore
L_16D2           CLRB
                 STB    ,X+
                 STB    ,X+
                 STB    ,X
                 PULS   B
                 BRA    Task2_ShowScore
L_16DD           DECB
                 PSHS   CC,B
                 BSR    Task1_ClearScore
                 PULS   CC,B
                 BNE    L_16DD
                 RTS

; =====================================================================
; Task 2 - ShowScore: B = 0 P1, 1 P2, 2 high score, 3 all.
; =====================================================================
Task2_ShowScore  CMPB   #$03
                 BEQ    L_1701
                 LDY    #$60B4
                 TSTB
                 BEQ    L_16F6
                 LDY    #$60B7
L_16F6           CMPB   #$02
                 BNE    DrawScore
L_16FA           LDY    #$60BA
                 JMP    >L_1697
L_1701           DECB
                 PSHS   CC,B
                 BSR    Task2_ShowScore
                 PULS   CC,B
                 BNE    L_1701
                 RTS

; =====================================================================
; Task 3 - ShowString: B = string number (bit7 set = erase).
; TBL_Strings -> FDB vram address, tile codes..., $3F end.  Text runs
; in the rotated arcade screen: next column = -32 bytes.
; =====================================================================
Task3_ShowString LDX    #TBL_Strings
                 ASLB
                 PSHS   CC,B
                 ANDB   #$7F
                 ABX
                 LDY    ,X
                 LDX    ,Y++
                 STD    <$02
L_171B           LDB    ,Y
                 CMPB   #$3F
                 BNE    L_1723
                 PULS   X,PC
L_1723           STB    ,X
                 PULS   CC,B
                 BCC    L_172D
                 LDA    #$10
                 STA    ,X
L_172D           PSHS   CC,B
                 LEAY   1,Y
                 LEAX   <-32,X
                 BRA    L_171B

; =====================================================================
; Task 4 - ShowCredits (only in attract mode).
; =====================================================================
Task4_ShowCredits LDB    >AttractFlag ; 1 = attract / no game
                 RORB
                 BCS    ShowCredits
L_173C           RTS

; =====================================================================
; ShowCredits (94 instructions)
; Uses:  NumCredits $74BF BonusTimer $63B8 $62B0 $7465 MusicReq $7486 $74A6 $74E6 $74C6
; Calls: Task3_ShowString Task0_AddScore
; =====================================================================
ShowCredits      LDX    #TBL_TilePalette
                 STX    >L_54C6+2
                 LDB    #$05
                 BSR    Task3_ShowString
                 LDX    #NumCredits
                 LDU    #$74BF
                 LDA    #$01
                 STA    <$02
                 JMP    >L_16A1

; =====================================================================
; Task 5 - BonusTimer: B=0 add the remaining bonus to the score;
; else count the bonus timer $638C down and draw the bonus box.
; =====================================================================
Task5_BonusTimer TSTB
                 BEQ    L_17CE
                 LDA    >BonusTimer ; bonus timer (BCD)
                 LBNE   L_17E7
                 LDB    >$63B8
                 BNE    L_173C
                 LDD    #$000A
                 STD    <$02
                 LDB    >$62B0
L_176B           INC    <$02
                 SUBB   <$03
                 BNE    L_176B
                 LDB    <$02
                 LDA    <$02
                 ASLA
                 ROLB
                 ASLA
                 ROLB
                 ASLA
                 ROLB
                 ASLA
                 ROLB
                 STB    >BonusTimer ; bonus timer (BCD)
                 LDX    #D_4C62
                 LDY    #$7465
                 LDB    #$06
                 STB    <$01
L_178B           LDU    #$001D
                 LDB    #$03
L_1790           LDA    ,X+
                 STA    ,Y+
                 DECB
                 BNE    L_1790
                 TFR    Y,D
                 LEAU   D,U
                 TFR    U,Y
                 DEC    <$01
                 BNE    L_178B
                 LDA    >BonusTimer ; bonus timer (BCD)
L_17A4           STA    <$03
                 ANDA   #$0F
                 STA    <$02
                 LDB    <$03
                 LSRB
                 LSRB
                 LSRB
                 LSRB
                 BNE    L_17C5
                 LDB    #$03
                 STB    >MusicReq ; music number request
                 LDB    #$70
                 STB    >$7486
                 STB    >$74A6
                 ADDB   <$02
                 STB    <$02
                 LDB    #$10
L_17C5           STB    >$74E6
                 LDB    <$02
                 STB    >$74C6
                 RTS
L_17CE           LDB    >BonusTimer ; bonus timer (BCD)
                 STB    <$02
                 PSHS   B
                 ANDB   #$0F
                 JSR    >Task0_AddScore
                 PULS   B
                 STB    <$02
                 LSRB
                 LSRB
                 LSRB
                 LSRB
                 ADDB   #$0A
                 JMP    >Task0_AddScore
L_17E7           SUBA   #$01
                 BNE    L_17F2
                 LDX    #$63B8
                 LDB    #$01
                 STB    ,X
L_17F2           TFR    A,B
                 ANDB   #$0F
                 CMPB   #$0F
                 BNE    L_17FC
                 SUBA   #$06
L_17FC           STA    >BonusTimer ; bonus timer (BCD)
                 BRA    L_17A4

; =====================================================================
; Task 6 - ShowLivesLevel: Mario icons for the spare lives and
; 'L=nn' for the level $6229 (max 99).
; =====================================================================
Task6_ShowLivesLevel STB    <$03
                 JSR    <RST_RetIfAttract
                 LDA    #$06
                 LDX    #$7783
                 LDB    #$10
L_180C           STB    ,X
                 LEAX   <-32,X
                 DECA
                 BNE    L_180C
                 LDB    >Lives ; lives left
                 SUBB   <$03
                 BEQ    L_182B
                 STB    <$02
                 LDX    #$7783
L_1820           LDA    #$FF
                 STA    ,X
                 LEAX   <-32,X
                 DEC    <$02
                 BNE    L_1820
L_182B           LDX    #$7503
                 LDA    #$1C
                 STA    ,X
                 LDX    #$74E3
                 LDA    #$34
                 STA    ,X
                 LDA    >Level ; level number
                 CMPA   #$64
                 BCS    L_1845
                 LDA    #$63
                 STA    >Level ; level number
L_1845           LDB    #$FF
L_1847           INCB
                 SUBA   #$0A
                 BCC    L_1847
                 ADDA   #$0A
                 STA    >$74A3
                 STB    >$74C3
                 RTS

; =====================================================================
; Mode3_Game: game state machine on $600A.
; =====================================================================
Mode3_Game       LDB    >GameState ; sub-state of GameMode
                 JSR    <RST_JumpTable
TBL_GameState    FDB    L_1B2B
                 FDB    L_1B54
                 FDB    L_1B8E
                 FDB    L_1BBB
                 FDB    L_1BDE
                 FDB    L_1BFE
                 FDB    L_1C2F
                 FDB    L_1C48
                 FDB    L_1DDD
                 FDB    ColdStart
                 FDB    L_1E9B
                 FDB    L_24E0
                 FDB    L_2CEB
                 FDB    L_2524
                 FDB    L_25B7
                 FDB    L_2617
                 FDB    L_266F
                 FDB    L_2683
                 FDB    L_268C
                 FDB    L_269D
                 FDB    L_2718
                 FDB    L_2788
                 FDB    L_2914
                 FDB    L_2CDC

; =====================================================================
; Mode1_Attract: attract mode state machine on $600A; a credit
; ($6001) switches to mode 2.
; =====================================================================
Mode1_Attract    LDX    #GameState
                 LDB    >NumCredits ; credits (BCD)
                 BNE    L_18A6
                 LDB    ,X
                 JSR    <RST_JumpTable
TBL_AttractState FDB    L_18C6
                 FDB    L_18AE
                 FDB    L_24E0
                 FDB    L_2CE8
                 FDB    L_2524
                 FDB    L_1919
                 FDB    L_1931
                 FDB    L_19C9
L_18A6           CLR    ,X
                 LDX    #GameMode
                 INC    ,X
                 RTS
L_18AE           JSR    >MinorTimerWait
                 CLRB
                 STB    >$6392
                 STB    >$63A0
                 LDB    #$01
                 STB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 STB    >Level ; level number
                 STB    >Lives ; lives left
                 JMP    >L_1E9D
L_18C6           LDX    #PaletteBank0
                 CLR    ,X+
                 CLR    ,X
                 JSR    >PaletteBankUpdate
                 LDY    #$031B ; show "INSERT COIN "
                 JSR    >AddTask
                 LEAY   1,Y
                 JSR    >AddTask
                 JSR    >ShowHighScoreTable
                 LDX    #WaitTimer
                 LDA    #$02
                 STA    ,X+
                 INC    ,X
                 JSR    >ClearPlayfield
                 JSR    >Draw1UP
                 LDB    >TwoPlayers
                 CMPB   #$01
                 BNE    L_18F8
                 JSR    >SUB_1BAB
L_18F8           LDY    >DipCoinsLo
                 LDX    #$756C
                 BSR    SUB_1901

; =====================================================================
; SUB_1901 (93 instructions)
; Uses:  $758E $768C GameState $638B $638A PAL_3 PAL_5 $6908 $690B WaitTimer
; Calls: ClearPlayfield AddTask RST_CopySprites RST_AddToObjects MinorTimerWait
; =====================================================================
SUB_1901         TFR    Y,D
                 STB    ,X++
                 STA    ,X
                 SUBA   #$0A
                 BNE    L_1911
                 STA    ,X
                 INCA
                 STA    >$758E
L_1911           LDY    #$0201
                 LDX    #$768C
                 RTS
L_1919           JSR    >ClearPlayfield
                 LDX    #GameState
                 INC    ,X
                 RTS
L_1922           LDB    >$638B
                 STB    <$03
                 LDB    >$638A
                 DECB
                 STB    >$638A
                 JMP    >L_193F
L_1931           LDB    >$638A
                 BNE    L_1922
                 LDB    #$60
                 STB    >$638A
                 LDA    #$5F
                 STA    <$03
L_193F           CMPB   #$00
                 BEQ    L_19B8
                 LDB    <$03
                 LDA    <$03
                 ASLA
                 ROLB
                 TFR    B,A
                 ASLA
                 ROLB
                 STB    >$638B
                 CMPB   #$D7
                 BNE    L_1962
                 LDA    <VsyncCount
L_1956           CMPA   <VsyncCount
                 BEQ    L_1956
                 LDA    >D_5A9B
                 LDB    >D_5A9D
                 BRA    L_1972
L_1962           CMPB   #$7D
                 BNE    L_197E
                 LDA    <VsyncCount
L_1968           CMPA   <VsyncCount
                 BEQ    L_1968
                 LDA    >D_5A9E
                 LDB    >D_5AA2
L_1972           STA    >PAL_3 ; PAL_3 - Palette 3 (6-bit RGB)
                 STB    >PAL_5 ; PAL_5 - Palette 5 (6-bit RGB)
                 LDX    #D_545F
                 STX    >L_54C6+2
L_197E           LDX    #D_5135
L_1981           LDB    #$B0
                 LDA    ,X+
                 STA    <$02
                 LDY    ,X++
L_198A           STB    ,Y+
                 DEC    <$02
                 BNE    L_198A
                 LDB    ,X
                 BNE    L_1981
                 LDY    #$031E ; show "~~ NINTENDO"
                 JSR    >AddTask
                 LEAY   1,Y
                 JSR    >AddTask
                 LDX    #D_4DE7
                 JSR    <RST_CopySprites
                 LDX    #$6908
                 LDA    #$44
                 STA    <$03
                 JSR    <RST_AddToObjects
                 LDX    #$690B
                 LDA    #$78
                 STA    <$03
                 JSR    <RST_AddToObjects
                 RTS
L_19B8           LDX    #WaitTimer
                 LDA    #$02
                 STA    ,X+
                 INC    ,X
                 LDX    #$638A
                 CLR    ,X+
                 CLR    ,X
                 RTS
L_19C9           JSR    >MinorTimerWait
                 LDX    #GameState
                 CLR    ,X
                 RTS

; =====================================================================
; ClearScreenAll: tile RAM <- $10 (blank), sprite buffer <- 0.
; =====================================================================
ClearScreenAll   LDX    #TileRAM
                 LDA    #$04
                 STA    <$03
L_19D9           CLRA
                 LDB    #$10
L_19DC           STB    ,X+
                 DECA
                 BNE    L_19DC
                 DEC    <$03
                 BNE    L_19D9
                 LDX    #SpriteBuf
                 LDA    #$02
                 STA    <$03
L_19EC           LDA    #$C0
                 CLRB
L_19EF           STB    ,X+
                 DECA
                 BNE    L_19EF
                 DEC    <$03
                 BNE    L_19EC
                 RTS

; =====================================================================
; ClearPlayfield: blank the playfield columns, keep score area.
; =====================================================================
ClearPlayfield   LDX    #$7404
                 LDA    #$20
                 STA    <$03
L_1A00           LDA    #$1C
                 LDB    #$10
L_1A04           STB    ,X+
                 DECA
                 BNE    L_1A04
                 LEAX   4,X
                 DEC    <$03
                 BNE    L_1A00
                 LDX    #$7522
                 LDA    #$02
                 STA    <$03
                 LDB    #$10
L_1A18           LDA    #$0E
L_1A1A           STB    ,X
                 LEAX   <32,X
                 DECA
                 BNE    L_1A1A
                 LDX    #$7523
                 DEC    <$03
                 BNE    L_1A18
                 LDX    #SpriteBuf
                 CLRA
                 CLRB
L_1A2E           STB    ,X+
                 DECA
                 BNE    L_1A2E
                 LDA    #$80
L_1A35           STB    ,X+
                 DECA
                 BNE    L_1A35
                 RTS

; =====================================================================
; Mode2_Credited: 'PUSH ... BUTTON' screen, wait for 1P/2P start.
; =====================================================================
Mode2_Credited   LDB    >GameState ; sub-state of GameMode
                 JSR    <RST_JumpTable
TBL_CreditState  FDB    L_1A44
                 FDB    L_1A8C
L_1A44           BSR    ClearPlayfield
                 CLRB
                 STB    >AttractFlag ; 1 = attract / no game
                 LDY    #$030C ; show "PUSH"
                 JSR    >AddTask
                 LDX    #GameState
                 INC    ,X
                 JSR    >ShowHighScoreTable
                 CLRB
                 LDX    #PaletteBank0
                 STB    ,X+
                 STB    ,X
                 JSR    >PaletteBankUpdate

; =====================================================================
; WaitStartButton (65 instructions)
; Uses:  NumCredits FrameCounter $6048 DipLives Player2Ctrl $6040 GameState GameMode
; Calls: Task3_ShowString ShowCredits WaitStartButton SUB_1B19 AddTask ClearPlayfield
; =====================================================================
WaitStartButton  LDD    #$0409
                 STA    <$02
                 STB    <$05
                 LDB    >NumCredits ; credits (BCD)
                 CMPB   #$01
                 BEQ    L_1A78
                 LDA    #$0C
                 STA    <$02
                 INC    <$05
L_1A78           LDB    >FrameCounter ; decremented every frame
                 ANDB   #$07
                 BNE    L_1A87
                 LDB    <$05
                 JSR    >Task3_ShowString
                 JSR    >ShowCredits
L_1A87           LDB    <CoinStartBits
                 ANDB   <$02
                 RTS
L_1A8C           BSR    WaitStartButton
                 CMPB   #$04
                 BEQ    L_1A97
                 CMPB   #$08
                 BEQ    L_1AAA
                 RTS
L_1A97           JSR    >SUB_1B19
                 LDX    #$6048
                 LDA    #$08
                 CLRB
L_1AA0           STB    ,X+
                 DECA
                 BNE    L_1AA0
                 LDX    #$0000
                 BRA    L_1ACD
L_1AAA           BSR    SUB_1B19
                 BSR    SUB_1B19
                 LDY    #$6048
                 LDB    >DipLives ; lives per game (DIP)
                 STB    ,Y+
                 LDX    #D_1AF9
                 LDB    #$07
L_1ABC           LDA    ,X+
                 STA    ,Y+
                 DECB
                 BNE    L_1ABC
                 LDY    #$0101 ; queue ClearScore(1)
                 JSR    >AddTask
                 LDX    #$0001
L_1ACD           STX    >Player2Ctrl
                 JSR    >ClearPlayfield
                 LDY    #$6040
                 LDB    >DipLives ; lives per game (DIP)
                 STB    ,Y+
                 LDX    #D_1AF9
                 LDB    #$07
L_1AE1           LDA    ,X+
                 STA    ,Y+
                 DECB
                 BNE    L_1AE1
                 LDY    #$0100 ; queue ClearScore(0)
                 JSR    >AddTask
                 CLRB
                 STB    >GameState ; sub-state of GameMode
                 LDB    #$03
                 STB    >GameMode ; 0 init, 1 attract, 2 credited, 3 game
                 RTS
D_1AF9           FCB    $01,$4E,$7D,$01,$00,$00,$00

; =====================================================================
; ShowHighScoreTable: queue credits + strings $14-$19.
; =====================================================================
ShowHighScoreTable LDY    #$0400 ; queue ShowCredits(0)
                 JSR    >AddTask
                 LDY    #$0314
                 LDA    #$06
                 STA    <$02
L_1B0F           JSR    >AddTask
                 LEAY   1,Y
                 DEC    <$02
                 BNE    L_1B0F
                 RTS

; =====================================================================
; SUB_1B19 (63 instructions)
; Uses:  NumCredits FlipScreen GameState Player2Ctrl DipCabinet $6040 Lives $622A ScreenNum WaitTimer TwoPlayers PaletteBank0 PaletteBank1
; Calls: AddTask ClearScreenAll SoundReset PaletteBankUpdate
; =====================================================================
SUB_1B19         LDX    #NumCredits
                 LDA    #$99
                 ADDA   ,X
                 DAA
                 STA    ,X
                 LDY    #$0400 ; queue ShowCredits(0)
                 JSR    >AddTask
                 RTS
L_1B2B           JSR    >ClearScreenAll
                 JSR    >SoundReset
                 LDY    #FlipScreen
                 LDB    #$01
                 STB    ,Y
                 LDX    #GameState
                 LDB    >Player2Ctrl
                 BNE    L_1B46
                 LDA    #$01
                 STA    ,X
                 RTS
L_1B46           LDB    >DipCabinet
                 DECB
                 BEQ    L_1B4F
                 CLRB
                 STB    ,Y
L_1B4F           LDA    #$03
                 STA    ,X
                 RTS
L_1B54           LDX    #$6040
                 LDY    #Lives
                 LDB    #$08
L_1B5D           LDA    ,X+
                 STA    ,Y+
                 DECB
                 BNE    L_1B5D
                 LDX    >$622A
                 LDB    ,X
                 STB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 LDX    #WaitTimer
                 LDY    #GameState
                 LDB    >TwoPlayers
                 BEQ    L_1B83
                 LDA    #$78
                 STA    ,X
                 EXG    Y,X
                 LDA    #$02
                 STA    ,X
                 RTS
L_1B83           LDA    #$01
                 STA    ,X
                 EXG    Y,X
                 LDA    #$05
                 STA    ,X
                 RTS
L_1B8E           CLRB
                 STB    >PaletteBank0 ; palette bank bit 0
                 STB    >PaletteBank1 ; palette bank bit 1
                 JSR    >PaletteBankUpdate
                 LDY    #$0302 ; show "PLAYER ~~~"
                 JSR    >AddTask
                 LDY    #$0201 ; queue ShowScore(1)
                 JSR    >AddTask
                 LDB    #$05
                 STB    >GameState ; sub-state of GameMode

; =====================================================================
; SUB_1BAB (44 instructions)
; Uses:  $74E0 $74C0 $74A0 $6048 Lives $622A ScreenNum WaitTimer GameState PaletteBank0 PaletteBank1
; Calls: PaletteBankUpdate AddTask SUB_1BAB
; =====================================================================
SUB_1BAB         LDB    #$02
                 STB    >$74E0
                 LDB    #$25
                 STB    >$74C0
                 LDB    #$20
                 STB    >$74A0
                 RTS
L_1BBB           LDX    #$6048
                 LDY    #Lives
                 LDB    #$08
L_1BC4           LDA    ,X+
                 STA    ,Y+
                 DECB
                 BNE    L_1BC4
                 LDX    >$622A
                 LDB    ,X
                 STB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 LDB    #$78
                 STB    >WaitTimer ; frame countdown (RST_WaitTimer)
                 LDB    #$04
                 STB    >GameState ; sub-state of GameMode
                 RTS
L_1BDE           CLRB
                 STB    >PaletteBank0 ; palette bank bit 0
                 STB    >PaletteBank1 ; palette bank bit 1
                 JSR    >PaletteBankUpdate
                 LDY    #$0303 ; show "PLAYER ~~~"
                 JSR    >AddTask
                 LDY    #$0201 ; queue ShowScore(1)
                 JSR    >AddTask
                 BSR    SUB_1BAB
                 LDB    #$05
                 STB    >GameState ; sub-state of GameMode
                 RTS
L_1BFE           LDY    #$0304 ; show "HIGH SCORE"
                 JSR    >AddTask
                 LDY    #$0202 ; queue ShowScore(2)
                 JSR    >AddTask
                 LDY    #$0200 ; queue ShowScore(0)
                 JSR    >AddTask
                 LDY    #$0600 ; queue ShowLivesLevel(0)
                 JSR    >AddTask
                 LDX    #GameState
                 INC    ,X

; =====================================================================
; Draw1UP: tiles 1,U,P at the top of the screen.
; =====================================================================
Draw1UP          LDB    #$01
                 STB    >$7740
                 LDB    #$25
                 STB    >$7720
                 LDB    #$20
                 STB    >$7700
                 RTS
L_1C2F           JSR    <RST_WaitTimer
                 JSR    >ClearPlayfield
                 LDX    #WaitTimer
                 LDA    #$01
                 STA    ,X+
                 INC    ,X
                 LDY    #$622C
                 LDB    ,Y
                 BNE    L_1C47
                 INC    ,X
L_1C47           RTS

; =====================================================================
; Game state 7: sub-steps on $6385 (TBL_Step6385).
; =====================================================================
L_1C48           LDB    >$6385
                 JSR    <RST_JumpTable
TBL_Step6385     FDB    L_1C5D
                 FDB    L_1C97
                 FDB    L_1CCA
                 FDB    L_44D4
                 FDB    L_1CEC
                 FDB    L_44D4
                 FDB    L_1D5D
                 FDB    L_1DB0
L_1C5D           CLRB
                 STB    >PaletteBank0 ; palette bank bit 0
                 INCB
                 STB    >PaletteBank1 ; palette bank bit 1
                 JSR    >PaletteBankUpdate
                 LDY    #D_4C25
                 JSR    >SUB_1FD6
                 LDB    #$10
                 STB    >$76A3
                 STB    >$7663
                 LDB    #$D4
                 STB    >$75AA
                 CLRB
                 STB    >$62AF
                 LDX    #D_4C9C
                 STX    >$63C2
                 LDX    #D_4CB3
                 STX    >$63C4
                 LDB    #$40
                 STB    >WaitTimer ; frame countdown (RST_WaitTimer)
                 LDX    #$6385
                 INC    ,X
                 RTS
L_1C97           JSR    <RST_WaitTimer
                 LDX    #D_4C74
                 JSR    <RST_CopySprites
                 LDX    #$6908
                 LDA    #$30
                 STA    <$03
                 JSR    <RST_AddToObjects
                 LDX    #$690B
                 LDA    #$99
                 STA    <$03
                 JSR    <RST_AddToObjects
                 LDB    #$1F
                 STB    >$638E
                 CLRB
                 STB    >$690C
                 LDX    #MusicReq2
                 LDA    #$01
                 STA    ,X+
                 LDA    #$03
                 STA    ,X
                 LDX    #$6385
                 INC    ,X
                 RTS
L_1CCA           JSR    >SUB_44DC
                 LDB    >$62AF
                 ANDB   #$0F
                 BNE    L_1CD7
                 JSR    >SUB_44B0
L_1CD7           LDB    >$690B
                 CMPB   #$5D
                 BCC    L_1CEB
                 LDB    #$20
                 STB    >WaitTimer ; frame countdown (RST_WaitTimer)
                 LDX    #$6385
                 INC    ,X
                 STX    >$63C0
L_1CEB           RTS
L_1CEC           LDB    >FrameCounter ; decremented every frame
                 RORB
                 BCS    L_1CEB
                 LDX    >$63C2
                 LDB    ,X
                 CMPB   #$7F
                 BEQ    L_1D08
                 LEAX   1,X
                 STX    >$63C2
                 STB    <$03
                 LDX    #$690B
                 JSR    <RST_AddToObjects
                 RTS
L_1D08           LDX    #D_4DB7
                 JSR    <RST_CopySprites
                 LDY    #SpriteBuf
                 LDB    #$08
L_1D13           LDA    ,X+
                 STA    ,Y+
                 DECB
                 BNE    L_1D13
                 LDX    #$6908
                 LDA    #$50
                 STA    <$03
                 JSR    <RST_AddToObjects
                 LDX    #$690B
                 LDA    #$FC
                 STA    <$03
                 JSR    <RST_AddToObjects
L_1D2C           JSR    >SUB_44B0
                 LDB    >$638E
                 CMPB   #$0A
                 BNE    L_1D2C
                 LDB    #$03
                 STB    >SndBoom
                 LDY    #D_4D14
                 JSR    >SUB_1FD6
                 LDB    #$10
                 STB    >$74AA
                 STB    >$748A
                 LDB    #$05
                 STB    >$638D
                 LDB    #$20
                 STB    >WaitTimer ; frame countdown (RST_WaitTimer)
                 LDX    #$6385
                 INC    ,X
                 STX    >$63C0
                 RTS
L_1D5D           LDB    >FrameCounter ; decremented every frame
                 RORB
                 BCS    L_1D81
                 LDX    >$63C4
                 LDB    ,X
                 CMPB   #$7F
                 BEQ    L_1D82
                 LEAX   1,X
                 STX    >$63C4
                 LDX    #$690B
                 STB    <$03
                 JSR    <RST_AddToObjects
                 LDX    #$6908
                 LDA    #$FF
                 STA    <$03
                 JSR    <RST_AddToObjects
L_1D81           RTS
L_1D82           LDX    #D_4CB3
                 STX    >$63C4
                 LDB    #$03
                 STB    >SndBoom
                 LDX    #D_4CC4
                 LDB    >$638D
                 DECB
                 ASLB
                 ASLB
                 ASLB
                 ASLB
                 ABX
                 TFR    X,Y
                 JSR    >SUB_1FD6
                 LDX    #$638D
                 DEC    ,X
                 BNE    L_1DAF
                 LDB    #$B0
                 STB    >WaitTimer ; frame countdown (RST_WaitTimer)
                 LDX    #$6385
                 INC    ,X
L_1DAF           RTS
L_1DB0           LDX    #MusicReq2
                 LDB    >WaitTimer ; frame countdown (RST_WaitTimer)
                 CMPB   #$90
                 BNE    L_1DC9
                 LDA    #$0F
                 STA    ,X+
                 LDA    #$03
                 STA    ,X
                 LDX    #$6919
                 INC    ,X
                 BRA    L_1DD2
L_1DC9           CMPB   #$18
                 BNE    L_1DD2
                 LDX    #$6919
                 DEC    ,X
L_1DD2           JSR    <RST_WaitTimer
                 CLRB
                 STB    >$6385
                 INC    ,X+
                 INC    ,X
                 RTS
L_1DDD           JSR    >SoundReset
                 JSR    <RST_WaitTimer
                 JSR    >ClearPlayfield
                 LDA    #$06
                 LDB    >MarioAlive ; bit0 = Mario alive
                 TFR    D,Y
                 JSR    >AddTask
                 LDX    #PaletteBank0
                 LDA    #$01
                 STA    ,X+
                 CLR    ,X
                 JSR    >PaletteBankUpdate
                 LDX    #MusicReq2
                 LDA    #$02
                 STA    ,X+
                 LDA    #$03
                 STA    ,X
                 LDX    #$63A7
                 CLR    ,X
                 LDX    #$76DC
                 STX    >$63A8
                 LDB    >$622E
                 CMPB   #$06
                 BCS    L_1E1D
                 LDB    #$05
                 STB    >$622E
L_1E1D           LDB    >$622F
                 STB    <$02
                 LDB    >$622B
                 CMPB   <$02
                 BEQ    L_1E2E
                 LDX    #$622E
                 INC    ,X
L_1E2E           STB    >$622F
                 LDB    >$622E
                 STB    <$02
                 LDX    #$75BC
L_1E39           LDA    #$50
L_1E3B           STA    ,X
                 INCA
                 STA    ,-X
                 INCA
                 STA    ,-X
                 INCA
                 STA    ,-X
                 CMPA   #$67
                 BEQ    L_1E50
                 INCA
                 LEAX   <35,X
                 BRA    L_1E3B
L_1E50           LDB    >$63A7
                 INCB
                 STB    >$63A7
                 DECB
                 ASLB
                 ASLB
                 PSHS   X
                 LDX    #D_511D
                 LDU    >$63A8
                 ABX
                 LDB    ,X+
                 STB    <96,U
                 LDB    ,X+
                 STB    <64,U
                 LDB    ,X
                 STB    <32,U
                 LDA    #$8B
                 STA    <-32,U
                 TFR    U,X
                 LEAX   -4,X
                 STX    >$63A8
                 PULS   X
                 LEAX   >-161,X
                 DEC    <$02
                 BNE    L_1E39
                 LDY    #$0307 ; show "HOW HIGH CAN YOU GET ~ "
                 JSR    >AddTask
                 LDX    #WaitTimer
                 LDA    #$A0
                 STA    ,X+
                 INC    ,X
                 INC    ,X
                 RTS
L_1E9B           JSR    <RST_WaitTimer
L_1E9D           JSR    >ClearPlayfield
                 CLRB
                 STB    >BonusTimer ; bonus timer (BCD)
                 LDY    #$0501 ; queue BonusTimer(1)
                 JSR    >AddTask
                 LDX    #PaletteBank0
                 CLR    ,X+
                 LDA    #$01
                 STA    ,X
                 LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 DECB
                 BEQ    L_1EE5
                 DECB
                 BEQ    L_1EF3
                 DECB
                 BEQ    L_1F0A
                 JSR    >SUB_1F60
                 LDX    #PaletteBank0
                 LDA    #$01
                 STA    ,X
                 JSR    >PaletteBankUpdate
                 LDB    #$0B
                 STB    >MusicReq ; music number request
                 LDY    #D_50B8
L_1ED6           JSR    >SUB_1FD6
                 LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 CMPB   #$04
                 BNE    L_1EE2
                 BSR    SUB_1F1A
L_1EE2           JMP    >L_5314
L_1EE5           JSR    >PaletteBankUpdate
                 LDY    #D_4F11
                 LDB    #$08
                 STB    >MusicReq ; music number request
                 BRA    L_1ED6
L_1EF3           LDY    #D_4F8A
                 LDX    #PaletteBank0
                 LDA    #$01
                 STA    ,X+
                 CLR    ,X
                 JSR    >PaletteBankUpdate
                 LDB    #$09
                 STB    >MusicReq ; music number request
                 BRA    L_1ED6
L_1F0A           JSR    >PaletteBankUpdate
                 BSR    SUB_1F43
                 LDB    #$0A
                 STB    >MusicReq ; music number request
                 LDY    #D_5012
                 BRA    L_1ED6

; =====================================================================
; SUB_1F1A (13 instructions)
; =====================================================================
SUB_1F1A         LDA    #$08
                 STA    <$02
                 LDX    #D_1F33
L_1F21           LDB    #$B8
                 LDA    #$02
                 LDY    ,X++
L_1F28           STB    ,Y+
                 DECB
                 DECA
                 BNE    L_1F28
                 DEC    <$02
                 BNE    L_1F21
                 RTS
D_1F33           FDB    $76CA,$76CF,$76D4,$76D9
                 FDB    $752A,$752F,$7534,$7539

; =====================================================================
; SUB_1F43 (3 instructions)
; Uses:  $770D $760D
; Calls: SUB_1F4B
; =====================================================================
SUB_1F43         LDX    #$770D
                 BSR    SUB_1F4B
                 LDX    #$760D

; =====================================================================
; SUB_1F4B (12 instructions)
; =====================================================================
SUB_1F4B         LDA    #$11
                 LDB    #$FD
L_1F4F           STB    ,X+
                 DECA
                 BNE    L_1F4F
                 LEAX   15,X
                 LDA    #$11
                 LDB    #$FC
L_1F5A           STB    ,X+
                 DECA
                 BNE    L_1F5A
                 RTS

; =====================================================================
; SUB_1F60 (3 instructions)
; Uses:  $7687 $7547
; Calls: SUB_1F68
; =====================================================================
SUB_1F60         LDX    #$7687
                 BSR    SUB_1F68
                 LDX    #$7547

; =====================================================================
; SUB_1F68 (51 instructions)
; Uses:  WaitTimer SpriteBuf ScreenNum $690B $6908 $6903
; Calls: InitStage SUB_3891 RST_CopySprites RST_AddToObjects RST_AddToObjectsB
; =====================================================================
SUB_1F68         LDA    #$04
                 LDB    #$FD
L_1F6C           STB    ,X+
                 DECA
                 BNE    L_1F6C
                 LEAX   <28,X
                 LDA    #$04
                 LDB    #$FC
L_1F78           STB    ,X+
                 DECA
                 BNE    L_1F78
                 RTS
L_1F7E           JSR    >InitStage
                 JSR    >SUB_3891
                 LDX    #WaitTimer
                 LDA    #$40
                 STA    ,X+
                 INC    ,X
                 LDX    #D_4DB7
                 JSR    <RST_CopySprites
                 LDY    #SpriteBuf
                 LDB    #$08
L_1F98           LDA    ,X+
                 STA    ,Y+
                 DECB
                 BNE    L_1F98
                 LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 CMPB   #$04
                 BEQ    L_1FB4
                 LSRB
                 LSRB
                 BCS    L_1FD5
                 LDX    #$690B
                 LDA    #$FC
                 STA    <$03
                 JSR    <RST_AddToObjects
                 RTS
L_1FB4           LDX    #$6908
                 LDA    #$44
                 STA    <$03
                 JSR    <RST_AddToObjects
                 LDY    #$0004
                 LDX    #$0210
                 STX    <$02
                 LDX    #SpriteBuf
                 JSR    <RST_AddToObjectsB
                 LDX    #$02F8
                 STX    <$02
                 LDX    #$6903
                 JSR    <RST_AddToObjectsB
L_1FD5           RTS

; =====================================================================
; SUB_1FD6 (185 instructions)
; Uses:  $63B3 $63AB $63B4 $63AF $63B1 $63B2 $63B0 $63AD $63B5
; Calls: SUB_443F
; =====================================================================
SUB_1FD6         LDB    ,Y
                 STB    >$63B3
                 CMPB   #$AA
                 BEQ    L_1FD5
                 LEAY   1,Y
                 LDD    ,Y+
                 TFR    D,X
                 STD    <$02
                 PSHS   Y
                 JSR    >SUB_443F
                 PULS   Y
                 STX    >$63AB
                 LDB    <$02
                 ANDB   #$07
                 STB    >$63B4
                 LDB    <$03
                 ANDB   #$07
                 STB    >$63AF
                 LEAY   1,Y
                 LDB    ,Y+
                 TFR    B,A
                 SUBB   <$02
                 BCC    L_200A
                 NEGB
L_200A           STB    >$63B1
                 LDB    ,Y
                 TFR    D,X
                 SUBB   <$03
                 STB    >$63B2
                 LDB    ,Y
                 ANDB   #$07
                 STB    >$63B0
                 PSHS   Y
                 JSR    >SUB_443F
                 PULS   Y
                 STX    >$63AD
                 LDB    >$63B3
                 CMPB   #$02
                 BPL    L_208D
                 LDB    >$63B2
                 SUBB   #$10
                 STB    <$02
                 LDB    >$63AF
                 ADDB   <$02
                 STB    >$63B2
                 LDB    >$63AF
                 ADDB   #$F0
                 LDX    >$63AB
                 STB    ,X+
                 SUBB   #$30
                 STB    ,X
                 LDB    >$63B3
                 CMPB   #$01
                 BNE    L_2056
                 CLRB
                 STB    >$63B2
L_2056           LDB    >$63B2
                 SUBB   #$08
                 STB    >$63B2
                 BCS    L_2068
                 LEAX   1,X
                 LDA    #$C0
                 STA    ,X
                 BRA    L_2056
L_2068           LDB    >$63B0
                 ADDB   #$D0
                 LDX    >$63AD
                 STB    ,X
                 LDB    >$63B3
                 CMPB   #$01
                 BNE    L_207D
                 LDA    #$C0
                 STA    -1,X
L_207D           LDB    >$63B0
                 BEQ    L_2088
                 ADDB   #$E0
                 LEAX   1,X
                 STB    ,X
L_2088           LEAY   1,Y
                 JMP    >SUB_1FD6
L_208D           LDB    >$63B3
                 CMPB   #$02
                 LBNE   L_211F
                 LDB    >$63AF
                 ADDB   #$F0
                 STB    >$63B5
                 LDX    >$63AB
L_20A1           LDB    >$63B5
                 STB    ,X+
                 TFR    X,D
                 ANDB   #$1F
                 BEQ    L_20B7
                 LDB    >$63B5
                 CMPB   #$F0
                 BEQ    L_20B7
                 SUBB   #$10
                 STB    ,X
L_20B7           LEAX   <31,X
                 LDB    >$63B1
                 SUBB   #$08
                 BCS    L_2105
                 STB    >$63B1
                 LDB    >$63B2
                 BEQ    L_20A1
                 LDB    >$63B5
                 STB    ,X+
                 TFR    X,D
                 ANDB   #$1F
                 BEQ    L_20DB
                 LDB    >$63B5
                 SUBB   #$10
                 STB    ,X
L_20DB           LEAX   <31,X
                 LDB    >$63B1
                 SUBB   #$08
                 BCS    L_2105
                 STB    >$63B1
                 LDB    >$63B2
                 BMI    L_210A
                 LDB    >$63B5
                 INCB
                 STB    >$63B5
                 CMPB   #$F8
                 BNE    L_20FF
                 LEAX   1,X
                 LDB    #$F0
                 STB    >$63B5
L_20FF           TFR    X,D
                 ANDB   #$1F
                 BNE    L_20A1
L_2105           LEAY   1,Y
                 JMP    >SUB_1FD6
L_210A           LDB    >$63B5
                 DECB
                 STB    >$63B5
                 CMPB   #$F0
                 BPL    L_211C
                 LEAX   -1,X
                 LDB    #$F7
                 STB    >$63B5
L_211C           JMP    >L_20A1
L_211F           LDB    >$63B3
                 CMPB   #$03
                 BNE    L_2151
                 LDX    >$63AB
                 LDB    #$B3
                 STB    ,X
                 LEAX   <32,X
                 LDB    >$63B1
                 SUBB   #$10
L_2135           BCS    L_2148
                 STB    >$63B1
                 LDB    #$B1
                 STB    ,X
                 LEAX   <32,X
                 LDB    >$63B1
                 SUBB   #$08
                 BRA    L_2135
L_2148           LDB    #$B2
                 STB    ,X
                 LEAY   1,Y
                 JMP    >SUB_1FD6
L_2151           LDB    >$63B3
                 CMPB   #$07
                 BPL    L_2105
                 CMPB   #$04
                 BEQ    L_217F
                 CMPB   #$05
                 BEQ    L_2183
                 LDB    #$FE
L_2162           STB    >$63B5
                 LDX    >$63AB
L_2168           LDB    >$63B5
                 STB    ,X
                 LEAX   <32,X
                 LDB    >$63B1
                 SUBB   #$08
                 STB    >$63B1
                 BCC    L_2168
                 LEAY   1,Y
                 JMP    >SUB_1FD6
L_217F           LDB    #$10
                 BRA    L_2162
L_2183           LDB    #$B0
                 BRA    L_2162

; =====================================================================
; InitStage: clear Mario ($6200) and object tables ($6280-$6AFF),
; load defaults, bonus timer = level*10+40 (max 80, i.e. 8000), then the
; per-screen setup through TBL_InitStage.
; =====================================================================
InitStage        LDA    #$27
                 LDX    #MarioAlive
                 CLRB
L_218D           STB    ,X+
                 DECA
                 BNE    L_218D
                 LDA    #$11
                 STA    <$03
                 LDX    #$6280
L_2199           LDA    #$80
L_219B           STB    ,X+
                 DECA
                 BNE    L_219B
                 DEC    <$03
                 BNE    L_2199
                 LDX    #D_51C9
                 LDY    #$6280
                 LDA    #$20
                 STU    <$08
L_21AF           LDU    ,X++
                 STU    ,Y++
                 DECA
                 BNE    L_21AF
                 LDU    <$08
                 LDB    >Level ; level number
                 LDA    #$0A
                 MUL
                 ADDB   #$28
                 CMPB   #$51
                 BCS    L_21C6
                 LDB    #$50
L_21C6           LDX    #$62B0
                 LDA    #$03
L_21CB           STB    ,X+
                 DECA
                 BNE    L_21CB
                 ASLB
                 STB    <$02
                 LDB    #$DC
                 SUBB   <$02
                 CMPB   #$28
                 BCC    L_21DD
                 LDB    #$28
L_21DD           STB    ,X+
                 STB    ,X
                 LDX    #$6209
                 LDA    #$04
                 STA    ,X+
                 LDA    #$08
                 STA    ,X
                 LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 STB    <$03
                 ANDB   #$04
                 BNE    L_2212
                 LDX    #$6A00
                 LDB    #$4F
                 LDA    #$03
                 STA    <$02
L_21FE           STB    ,X+
                 LDA    #$3A
                 STA    ,X+
                 LDA    #$0F
                 STA    ,X+
                 LDA    #$18
                 STA    ,X+
                 ADDB   #$10
                 DEC    <$02
                 BNE    L_21FE
L_2212           LDB    <$03
                 JSR    <RST_JumpTable
TBL_InitStage    FDB    ColdStart
                 FDB    InitStage_Girders
                 FDB    InitStage_Conveyors
                 FDB    InitStage_Elevators
                 FDB    InitStage_Rivets
InitStage_Girders LDX    #D_5209
                 LDY    #$69A8
                 LDB    #$10
L_2229           LDA    ,X+
                 STA    ,Y+
                 DECB
                 BNE    L_2229
                 LDX    #D_5219
                 LDY    #$6407
                 LDD    #$051C
                 STD    <$02
                 JSR    >SUB_24CA
                 LDX    #D_5221
                 JSR    >SUB_249E
                 LDX    #D_522D
                 LDY    #$69FC
                 LDB    #$04
L_224E           LDA    ,X+
                 STA    ,Y+
                 DECB
                 BNE    L_224E
                 LDX    #D_5239
                 JSR    >SUB_2440
                 LDX    #D_2276
                 LDY    #$6707
                 LDD    #$081C
                 STD    <$02
                 JSR    >SUB_24CA
                 LDY    #$6807
                 LDA    #$02
                 STA    <$02
                 JSR    >SUB_24CA
                 RTS
D_2276           FCB    $00,$00,$02,$02
InitStage_Conveyors LDX    #D_5219
                 LDY    #$6407
                 LDD    #$051C
                 STD    <$02
                 JSR    >SUB_24CA
                 JSR    >SUB_241C
                 LDX    #D_5245
                 LDY    #$65A7
                 LDD    #$060C
                 STD    <$02
                 JSR    >SUB_24CA
                 LDU    #$65A0
                 LDX    #$69B8
                 LDY    #$0010
                 LDA    #$06
                 STA    <$02
                 JSR    >SUB_2472
                 LDX    #D_5227
                 JSR    >SUB_249E
                 LDX    #D_5231
                 LDY    #$69FC
                 LDB    #$04
L_22BB           LDA    ,X+
                 STA    ,Y+
                 DECB
                 BNE    L_22BB
                 LDX    #D_5249
                 LDY    #$6944
                 LDB    #$08
L_22CB           LDA    ,X+
                 STA    ,Y+
                 DECB
                 BNE    L_22CB
                 LDX    #D_5251
                 LDY    #$69E4
                 LDB    #$18
L_22DB           LDA    ,X+
                 STA    ,Y+
                 DECB
                 BNE    L_22DB
                 LDX    #D_523D
                 JSR    >SUB_2440
                 LDX    #D_5269
                 LDY    #$6A0C
                 LDB    #$0C
L_22F1           LDA    ,X+
                 STA    ,Y+
                 DECB
                 BNE    L_22F1
                 LDB    #$01
                 STB    >$62B9
                 RTS
InitStage_Elevators LDX    #D_5219
                 LDY    #$6407
                 LDD    #$051C
                 STD    <$02
                 JSR    >SUB_24CA
                 JSR    >SUB_241C
                 LDX    #$6600
                 LDB    #$01
                 LDA    #$06
L_2317           STB    ,X
                 LEAX   <16,X
                 DECA
                 BNE    L_2317
                 LDA    #$02
                 STA    <$03
                 LDB    #$08
L_2325           LDA    #$03
                 LDX    #$660D
L_232A           STB    ,X
                 LEAX   <16,X
                 DECA
                 BNE    L_232A
                 DEC    <$03
                 BNE    L_2325
                 LDX    #D_5291
                 LDY    #$6603
                 LDD    #$060E
                 STA    <$02
                 JSR    >SUB_248F
                 LDX    #D_528D
                 LDY    #$6607
                 LDD    #$060C
                 STD    <$02
                 JSR    >SUB_24CA
                 LDU    #$6600
                 LDX    #$6958
                 LDA    #$06
                 STA    <$02
                 LDY    #$0010
                 JSR    >SUB_2472
                 LDX    #D_5275
                 LDY    #$6A0C
                 LDB    #$06
L_236E           LDU    ,X++
                 STU    ,Y++
                 DECB
                 BNE    L_236E
                 LDU    #Fireballs
                 LDD    #$0158
                 STA    ,U
                 STB    3,U
                 STB    14,U
                 LDB    #$80
                 STB    5,U
                 STB    15,U
                 STA    <32,U
                 LDD    #$EB60
                 STA    <35,U
                 STA    <46,U
                 STB    <37,U
                 STB    <47,U
                 LDY    #$6970
                 LDX    #D_23AA
                 LDB    #$10
L_23A2           LDA    ,X+
                 STA    ,Y+
                 DECB
                 BNE    L_23A2
                 RTS
D_23AA           FCB    $37,$45,$0F,$60,$37,$C5,$0F,$F7
                 FCB    $77,$45,$0F,$60,$77,$C5,$0F,$F7
InitStage_Rivets LDX    #D_521D
                 LDY    #$6407
                 LDD    #$051C
                 STD    <$02
                 JSR    >SUB_24CA
                 LDX    #D_5241
                 BSR    SUB_2440
                 LDX    #D_5281
                 LDY    #$6A0C
                 LDB    #$0C
L_23D7           LDA    ,X+
                 STA    ,Y+
                 DECB
                 BNE    L_23D7
                 LDX    #D_2418
                 LDY    #$64A3
                 LDD    #$021E
                 STA    <$02
                 JSR    >SUB_248F
                 LDX    #D_2414
                 LDY    #$64A7
                 LDD    #$021C
                 STD    <$02
                 JSR    >SUB_24CA
                 LDU    #$64A0
                 LDA    #$01
                 STA    ,U
                 STA    <32,U
                 LDX    #$6950
                 LDA    #$02
                 STA    <$02
                 LDY    #$0020
                 BSR    SUB_2472
                 RTS
D_2414           FCB    $3F,$0C,$08,$08
D_2418           FCB    $73,$50,$8D,$50

; =====================================================================
; SUB_241C (12 instructions)
; Uses:  $6507 $6500 $6980
; Calls: SUB_24CA SUB_2472
; =====================================================================
SUB_241C         LDX    #D_243C
                 LDY    #$6507
                 LDD    #$0A0C
                 STD    <$02
                 JSR    >SUB_24CA
                 LDU    #$6500
                 LDX    #$6980
                 LDA    #$0A
                 STA    <$02
                 LDY    #$0010
                 BSR    SUB_2472
                 RTS
D_243C           FCB    $3B,$00,$02,$02

; =====================================================================
; SUB_2440 (19 instructions)
; Uses:  $6683 $6687 $6680 $6A18
; Calls: SUB_248F SUB_24CA SUB_2472
; =====================================================================
SUB_2440         LDY    #$6683
                 LDD    #$020E
                 STA    <$02
                 BSR    SUB_248F
                 LDX    #D_5235
                 LDY    #$6687
                 LDD    #$020C
                 STD    <$02
                 JSR    >SUB_24CA
                 LDU    #$6680
                 LDA    #$01
                 STA    ,U
                 STA    <16,U
                 LDX    #$6A18
                 LDA    #$02
                 STA    <$02
                 LDY    #$0010
                 BSR    SUB_2472
                 RTS

; =====================================================================
; SUB_2472 (15 instructions)
; =====================================================================
SUB_2472         LDB    3,U
                 ANDB   #$FE
                 STB    ,X
                 LDB    7,U
                 STB    1,X
                 LDB    5,U
                 STB    3,X
                 LEAX   4,X
                 STB    <$01
                 TFR    Y,D
                 LEAU   D,U
                 LDB    <$01
                 DEC    <$02
                 BNE    SUB_2472
                 RTS

; =====================================================================
; SUB_248F (8 instructions)
; =====================================================================
SUB_248F         LDA    ,X+
                 STA    ,Y++
                 LDA    ,X+
                 STA    ,Y
                 LEAY   B,Y
                 DEC    <$02
                 BNE    SUB_248F
                 RTS

; =====================================================================
; SUB_249E (21 instructions)
; Uses:  $66A0 $6A28
; =====================================================================
SUB_249E         LDU    #$66A0
                 LDY    #$6A28
                 LDA    #$01
                 STA    ,U
                 LDB    ,X+
                 STB    3,U
                 ANDB   #$FE
                 STB    ,Y
                 LDB    ,X+
                 STB    7,U
                 STB    1,Y
                 LDB    ,X+
                 STB    8,U
                 LDB    ,X+
                 STB    5,U
                 STB    3,Y
                 LDB    ,X+
                 STB    9,U
                 LDB    ,X
                 STB    10,U
                 RTS

; =====================================================================
; SUB_24CA (215 instructions)
; Uses:  ScreenNum MarioAlive $694C GameState $639D $694D $639E WaitTimer SndDeath Player2Ctrl $622C Lives $6040 ScoreP1 ...
; Calls: RST_WaitTimer AddTask SUB_3195 RST_JumpTable SUB_453E SUB_455A SoundReset SUB_26AC SUB_2B55
; =====================================================================
SUB_24CA         PSHS   X
                 LDA    #$04
L_24CE           LDB    ,X+
                 STB    ,Y+
                 DECA
                 BNE    L_24CE
                 PULS   X
                 LDA    <$03
                 LEAY   A,Y
                 DEC    <$02
                 BNE    SUB_24CA
                 RTS
L_24E0           JSR    <RST_WaitTimer
                 LDD    #$E016
                 STD    <$02
                 LDA    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 CMPA   #$03
                 BEQ    L_24F3
                 LDD    #$F03F
                 STD    <$02
L_24F3           LDU    #MarioAlive
                 LDX    #$694C
                 LDA    #$01
                 STA    ,U
                 STB    3,U
                 ANDB   #$FE
                 STB    ,X
                 LDA    #$80
                 STA    7,U
                 STA    1,X
                 LDA    #$02
                 STA    8,U
                 LDA    <$02
                 STA    5,U
                 STA    3,X
                 LDA    #$01
                 STA    15,U
                 LDX    #GameState
                 INC    ,X
                 LDY    #$0601 ; queue ShowLivesLevel(1)
                 JSR    >AddTask
                 RTS
L_2524           JSR    >SUB_3195
                 LDB    >$639D
                 JSR    <RST_JumpTable
TBL_252C         FDB    L_2532
                 FDB    L_2556
                 FDB    L_25A1
L_2532           JSR    <RST_WaitTimer
                 LDX    #$694D
                 LDB    #$F0
                 ROL    ,X
                 RORB
                 STB    ,X
                 LDX    #$639D
                 INC    ,X
                 LDB    #$0D
                 STB    >$639E
                 LDB    #$08
                 STB    >WaitTimer ; frame countdown (RST_WaitTimer)
                 JSR    >SUB_453E
                 LDB    #$03
                 STB    >SndDeath
                 RTS
L_2556           JSR    <RST_WaitTimer
                 LDB    #$08
                 STB    >WaitTimer ; frame countdown (RST_WaitTimer)
                 LDX    #$639E
                 DEC    ,X
                 BEQ    L_258C
                 LDX    #$694D
                 LDB    ,X
                 RORB
                 LDB    #$02
                 RORB
                 STB    <$02
                 EORB   ,X
                 STB    ,X+
                 LDB    <$02
                 ANDB   #$80
                 LDA    -1,X
                 ORA    #$40
                 EORB   ,X
                 BPL    L_2589
                 CMPA   #$79
                 BEQ    L_2589
                 CMPA   #$F9
                 BEQ    L_2589
                 ANDA   #$BF
L_2589           STD    -1,X
                 RTS
L_258C           LDX    #$694D
                 LDB    #$F4
                 ROL    ,X
                 RORB
                 STB    ,X
                 LDX    #$639D
                 INC    ,X
                 LDB    #$80
                 STB    >WaitTimer ; frame countdown (RST_WaitTimer)
                 RTS
L_25A1           JSR    <RST_WaitTimer
                 JSR    >SUB_455A
                 LDX    #GameState
                 LDB    >Player2Ctrl
                 BEQ    L_25B0
                 INC    ,X
L_25B0           INC    ,X
                 LDA    #$01
                 STA    ,-X
                 RTS
L_25B7           JSR    >SoundReset
                 CLRB
                 STB    >$622C
                 LDX    #Lives
                 DEC    ,X
                 LDB    ,X
                 LDY    #$6040
                 LDA    #$04
                 STU    <$08
L_25CD           LDU    ,X++
                 STU    ,Y++
                 DECA
                 BNE    L_25CD
                 LDU    <$08
                 TSTB
                 BNE    L_2608
                 LDB    #$01
                 LDX    #ScoreP1
                 JSR    >SUB_26AC
                 LDX    #$76D4
                 LDB    >TwoPlayers
                 BEQ    L_25F2
                 LDY    #$0302 ; show "PLAYER ~~~"
                 JSR    >AddTask
                 LEAX   -1,X
L_25F2           JSR    >SUB_2B55
                 LDY    #$0300 ; show "GAME  OVER"
                 JSR    >AddTask
                 LDX    #WaitTimer
                 LDA    #$C0
                 STA    ,X+
                 LDA    #$10
                 STA    ,X
                 RTS
L_2608           LDB    #$08
                 LDA    >TwoPlayers
                 BEQ    L_2611
                 LDB    #$17
L_2611           STB    <$03
                 STB    >GameState ; sub-state of GameMode
                 RTS
L_2617           JSR    >SoundReset
                 CLRB
                 STB    >$622C
                 LDX    #Lives
                 DEC    ,X
                 LDB    ,X
                 LDY    #$6048
                 LDA    #$04
                 STU    <$08
L_262D           LDU    ,X++
                 STU    ,Y++
                 DECA
                 BNE    L_262D
                 LDU    <$08
                 TSTB
                 BNE    L_2660
                 LDB    #$03
                 LDX    #ScoreP2
                 BSR    SUB_26AC
                 LDY    #$0303 ; show "PLAYER ~~~"
                 JSR    >AddTask
                 LDY    #$0300 ; show "GAME  OVER"
                 JSR    >AddTask
                 LDX    #$76D3
                 JSR    >SUB_2B55
                 LDX    #WaitTimer
                 LDA    #$C0
                 STA    ,X+
                 LDA    #$11
                 STA    ,X
                 RTS
L_2660           LDB    #$17
                 LDA    >$6040
                 BNE    L_2669
                 LDB    #$08
L_2669           STB    <$03
                 STB    >GameState ; sub-state of GameMode
                 RTS
L_266F           JSR    <RST_WaitTimer
                 LDB    #$17
                 LDA    >$6048
L_2676           INC    ,X
                 TSTA
                 BNE    L_267D
                 LDB    #$14
L_267D           STB    <$03
                 STB    >GameState ; sub-state of GameMode
                 RTS
L_2683           JSR    <RST_WaitTimer
                 LDB    #$17
                 LDA    >$6040
                 BRA    L_2676
L_268C           LDB    >DipCabinet
                 STB    >FlipScreen ; flip screen
                 CLRB
                 STB    >GameState ; sub-state of GameMode
                 LDX    #$0101
                 STX    >PlayerUp ; 0 = player 1, 1 = player 2
                 RTS
L_269D           CLRB
                 STB    >PlayerUp ; 0 = player 1, 1 = player 2
                 STB    >Player2Ctrl
                 STB    >GameState ; sub-state of GameMode
                 INCB
                 STB    >FlipScreen ; flip screen
                 RTS

; =====================================================================
; SUB_26AC (260 instructions)
; Uses:  $61C6 $61B1 $61A5 $61C7 Player2Ctrl PlayerUp $611C DipCabinet FlipScreen WaitTimer GameState GameMode AttractFlag PaletteBank0 ...
; Calls: RST_RetIfAttract ShowCredits RST_WaitTimer ClearPlayfield AddTask PaletteBankUpdate SUB_28F7 DrawBCD
; =====================================================================
SUB_26AC         LDY    #$61C6
                 STB    ,Y
                 JSR    <RST_RetIfAttract
                 LEAY   1,Y
                 LDB    #$03
L_26B8           LDA    ,X+
                 STA    ,Y+
                 DECB
                 BNE    L_26B8
                 LDA    #$03
                 LDX    #$61B1
L_26C4           LDB    ,-Y
                 LSRB
                 LSRB
                 LSRB
                 LSRB
                 STB    ,X+
                 LDB    ,Y
                 ANDB   #$0F
                 STB    ,X+
                 DECA
                 BNE    L_26C4
                 LDA    #$0E
                 LDB    #$10
L_26D9           STB    ,X+
                 DECA
                 BNE    L_26D9
                 LDB    #$3F
                 STB    ,X
                 LDA    #$05
                 STA    <$02
                 LDX    #$61A5
                 LDY    #$61C7
L_26ED           LDB    ,Y+
                 SUBB   ,X+
                 LDB    ,Y+
                 SBCB   ,X+
                 LDB    ,Y
                 SBCB   ,X
                 BCS    L_2717
                 LDA    #$19
                 STA    <$01
L_26FF           LDA    ,X
                 LDB    ,Y
                 STB    ,X
                 STA    ,Y
                 LEAX   -1,X
                 LEAY   -1,Y
                 DEC    <$01
                 BNE    L_26FF
                 LEAX   -11,X
                 LEAY   -11,Y
                 DEC    <$02
                 BNE    L_26ED
L_2717           RTS
L_2718           JSR    >ShowCredits
                 JSR    <RST_WaitTimer
                 JSR    >ClearPlayfield
                 CLRB
                 STB    >Player2Ctrl
                 STB    >PlayerUp ; 0 = player 1, 1 = player 2
                 LDX    #$611C
                 LDY    #$0022
                 LDA    #$05
                 LDB    #$01
L_2732           CMPB   ,X
                 BEQ    L_2757
                 LEAX   <34,X
                 DECA
                 BNE    L_2732
                 LDX    #$611C
                 LDD    #$0503
L_2742           CMPB   ,X
                 BEQ    L_274E
                 LEAX   <34,X
                 DECA
                 BNE    L_2742
                 BRA    L_2779
L_274E           LDB    #$01
                 STB    >Player2Ctrl
                 STB    >PlayerUp ; 0 = player 1, 1 = player 2
                 CLRB
L_2757           LDX    #DipCabinet
                 ORB    ,X
                 STB    >FlipScreen ; flip screen
                 CLR    >WaitTimer ; frame countdown (RST_WaitTimer)
                 LDX    #GameState
                 INC    ,X
                 LDY    #$030D
                 LDA    #$0C
                 STA    <$02
L_276F           JSR    >AddTask
                 LEAY   1,Y
                 DEC    <$02
                 BNE    L_276F
                 RTS
L_2779           LDB    #$01
                 STB    >FlipScreen ; flip screen
                 STB    >GameMode ; 0 init, 1 attract, 2 credited, 3 game
                 STB    >AttractFlag ; 1 = attract / no game
                 CLR    >GameState ; sub-state of GameMode
                 RTS
L_2788           JSR    >ShowCredits
                 LDX    #WaitTimer
                 LDB    ,X
                 BNE    L_27E8
                 STB    >PaletteBank0 ; palette bank bit 0
                 STB    >PaletteBank1 ; palette bank bit 1
                 JSR    >PaletteBankUpdate
                 LDA    #$01
                 STA    ,X
                 LDX    #$6030
                 LDA    #$0A
                 STA    ,X+
                 CLR    ,X+
                 LDA    #$10
                 STA    ,X+
                 LDA    #$1E
                 STA    ,X+
                 LDA    #$3E
                 STA    ,X+
                 CLR    ,X
                 LDX    #$75E8
                 STX    >$6036
                 LDX    #$611C
                 LDB    >Player2Ctrl
                 ASLB
                 INCB
                 STB    <$03
                 LDA    #$04
L_27C8           LDB    ,X
                 CMPB   <$03
                 BEQ    L_27D4
                 LEAX   <34,X
                 DECA
                 BNE    L_27C8
L_27D4           STX    >$6038
                 LDY    #$FFF3
                 LEAX   -13,X
                 STX    >$603A
                 LDB    >$6035
                 STB    <$03
                 JSR    >SUB_28F7
L_27E8           LDX    #$6034
                 DEC    ,X
                 BNE    L_280A
                 LDA    #$3E
                 STA    ,X
                 DEC    ,-X
                 LBEQ   L_28B8
                 LDB    ,X
                 LDA    #$FF
L_27FD           INCA
                 SUBB   #$0A
                 BCC    L_27FD
                 ADDB   #$0A
                 STB    >$7552
                 STA    >$7572
L_280A           LDX    #$6030
                 LDA    ,X
                 STA    <$02
                 LDA    #$0A
                 STA    ,X
                 LDB    >InputState ; joystick+jump, bit7 = jump edge
                 BMI    L_2850
                 ANDB   #$03
                 BNE    L_2824
                 INCB
                 STB    ,X
                 JMP    >L_2884
L_2824           DEC    <$02
                 BEQ    L_282E
                 LDB    <$02
                 STB    ,X
                 BRA    L_2884
L_282E           ANDB   #$02
                 BNE    L_2845
                 LDB    >$6035
                 INCB
                 CMPB   #$1E
                 BNE    L_283B
                 CLRB
L_283B           STB    >$6035
                 STB    <$03
                 JSR    >SUB_28F7
                 BRA    L_2884
L_2845           LDB    >$6035
                 SUBB   #$01
                 BPL    L_283B
                 LDB    #$1D
                 BRA    L_283B
L_2850           LDB    >$6035
                 CMPB   #$1C
                 BEQ    L_2870
                 CMPB   #$1D
                 BEQ    L_28B8
                 LDX    >$6036
                 TSTB
                 CMPX   #$7588
                 BEQ    L_2884
                 ADDB   #$11
                 STB    ,X
                 LEAX   <-32,X
L_286B           STX    >$6036
                 BRA    L_2884
L_2870           LDX    >$6036
                 LEAX   <32,X
                 CMPX   #$7608
                 BNE    L_287E
                 LDX    #$75E8
L_287E           LDB    #$10
                 STB    ,X
                 BRA    L_286B
L_2884           LDX    #$6032
                 DEC    ,X
                 BNE    L_28F6
                 LDB    >$6031
                 BNE    L_28AC
                 LDB    #$01
                 STB    >$6031
                 LDY    #D_122E
L_2899           LDX    >$6038
                 STX    <$0A
                 LDX    4,X
                 TFR    X,U
                 JSR    >DrawBCD
                 LDB    #$10
                 STB    >$6032
                 BRA    L_28F6
L_28AC           CLRB
                 STB    >$6031
                 LDY    >$6038
                 LEAY   3,Y
                 BRA    L_2899
L_28B8           LDY    >$6038
                 CLRB
                 STB    ,Y
                 LDX    #WaitTimer
                 LDA    #$80
                 STA    ,X+
                 DEC    ,X
                 LDA    #$0C
                 LDX    #$75E8
                 LDY    >$603A
L_28D1           LDB    ,X
                 STB    ,Y+
                 LEAX   <-32,X
                 DECA
                 BNE    L_28D1
                 STY    <$0A
                 LDA    #$05
                 STA    <$02
                 LDY    #$0314 ; show #14
L_28E6           JSR    >AddTask
                 LEAY   1,Y
                 DEC    <$02
                 BNE    L_28E6
                 LDY    #$031A ; show "YOUR NAME WAS REGISTERED~"
                 JSR    >AddTask
L_28F6           RTS

; =====================================================================
; SUB_28F7 (109 instructions)
; Uses:  $6974 ScreenNum $6388 WaitTimer $690B $690C $6924 $692C $62AF $6910 $6908 $62A0 $63A3
; Calls: SUB_453E RST_JumpTable SUB_3195 SUB_2A0F RST_CopySprites RST_RetIfNotScreen RST_AddToObjects RST_WaitTimer SUB_3A32
; =====================================================================
SUB_28F7         PSHS   X,Y
                 ASL    <$03
                 LDX    #D_4A2B
                 LDB    <$03
                 ABX
                 TFR    X,Y
                 LDX    #$6974
                 LDB    ,Y+
                 STB    ,X
                 LDA    #$72
                 STA    1,X
                 LDB    ,Y
                 STB    3,X
                 PULS   X,Y,PC
L_2914           JSR    >SUB_453E
                 LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 LSRB
                 BCC    L_292E
                 LDB    >$6388
                 JSR    <RST_JumpTable
TBL_2922         FDB    L_2954
                 FDB    L_2974
                 FDB    L_2993
                 FDB    L_2A42
                 FDB    L_2A6A
                 FDB    L_2AB0
L_292E           LSRB
                 BCC    L_2940
                 LDB    >$6388
                 JSR    <RST_JumpTable
TBL_2936         FDB    L_29AB
                 FDB    L_29C4
                 FDB    L_2A42
                 FDB    L_2A6A
                 FDB    L_2AB0
L_2940           JSR    >SUB_3195
                 LDB    >$6388
                 JSR    <RST_JumpTable
TBL_2948         FDB    L_2ADF
                 FDB    L_44D4
                 FDB    L_2B73
                 FDB    L_2BB5
                 FDB    L_2BC7
                 FDB    L_2C19
L_2954           JSR    >SUB_2A0F
                 LDX    #D_4DB7
                 JSR    <RST_CopySprites
                 LDB    #$20
                 STB    >WaitTimer ; frame countdown (RST_WaitTimer)
L_2961           LDX    #$6388
                 INC    ,X
                 LDB    #$01
                 JSR    <RST_RetIfNotScreen
                 LDX    #$690B
                 LDA    #$FC
                 STA    <$03
                 JSR    <RST_AddToObjects
                 RTS
L_2974           JSR    <RST_WaitTimer
                 LDX    #D_4D1A
                 JSR    <RST_CopySprites
                 LDB    #$20
                 STB    >WaitTimer ; frame countdown (RST_WaitTimer)
                 LDX    #$6388
                 INC    ,X
                 LDB    #$04
                 JSR    <RST_RetIfNotScreen
                 LDX    #$690B
                 LDA    #$04
                 STA    <$03
                 JSR    <RST_AddToObjects
                 RTS
L_2993           JSR    <RST_WaitTimer
                 LDX    #D_4C74
                 JSR    <RST_CopySprites
                 LDB    #$66
                 STB    >$690C
                 CLRB
                 STB    >$6924
                 STB    >$692C
                 STB    >$62AF
                 BRA    L_2961
L_29AB           BSR    SUB_2A0F
                 LDB    >$6910
                 SUBB   #$3B
                 LDX    #D_4DB7
                 JSR    <RST_CopySprites
                 LDX    #$6908
                 STB    <$03
                 JSR    <RST_AddToObjects
                 LDX    #$6388
                 INC    ,X
                 RTS
L_29C4           CLRB
                 STB    >$62A0
                 LDB    >$63A3
                 STB    <$03
                 LDB    >$6910
                 CMPB   #$5A
                 BCC    L_29EB
                 LDA    <$03
                 BPL    L_29DD
L_29D8           LDB    #$01
                 STB    >$62A0
L_29DD           JSR    >SUB_3A32
                 LDB    >$63A3
                 STB    <$03
                 LDX    #$6908
                 JSR    <RST_AddToObjects
                 RTS
L_29EB           CMPB   #$5D
                 BCS    L_29F5
                 LDA    <$03
                 BPL    L_29D8
                 BRA    L_29DD
L_29F5           LDX    #D_4C74
                 JSR    <RST_CopySprites
                 LDB    #$66
                 STB    >$690C
                 CLRB
                 STB    >$6924
                 STB    >$692C
                 STB    >$62AF
                 LDX    #$6388
                 INC    ,X
                 RTS

; =====================================================================
; SUB_2A0F (49 instructions)
; Uses:  $6A20 $6905 $75C4 MusicReq2 $6913 SpriteBuf $6904 $690C $6924 $692C $6A21 $6388 WaitTimer
; Calls: SoundReset SUB_161C SUB_44DC SUB_2A80 SUB_2A99
; =====================================================================
SUB_2A0F         JSR    >SoundReset
                 LDX    #$6A20
                 LDA    #$80
                 STA    ,X+
                 LDA    #$76
                 STA    ,X+
                 LDA    #$09
                 STA    ,X+
                 LDA    #$20
                 STA    ,X
                 LDA    #$13
                 STA    >$6905
                 LDX    #$75C4
                 LDY    #$0020
                 LDB    #$10
                 JSR    >SUB_161C
                 LDX    #MusicReq2
                 LDA    #$07
                 STA    ,X+
                 LDA    #$03
                 STA    ,X
                 RTS
L_2A42           JSR    >SUB_44DC
                 LDB    >$6913
                 CMPB   #$2C
                 BCC    L_2A69
                 CLRB
                 STB    >SpriteBuf ; arcade sprite list, 4 bytes/sprite
                 STB    >$6904
                 STB    >$690C
                 LDB    #$6B
                 STB    >$6924
                 DECB
                 STB    >$692C
                 LDX    #$6A21
                 INC    ,X
                 LDX    #$6388
                 INC    ,X
L_2A69           RTS
L_2A6A           JSR    >SUB_44DC
                 BSR    SUB_2A80
                 LEAX   1,X
                 LEAY   1,Y
                 BSR    SUB_2A99
                 LDB    #$40
                 STB    >WaitTimer ; frame countdown (RST_WaitTimer)
                 LDX    #$6388
                 INC    ,X
                 RTS

; =====================================================================
; SUB_2A80 (12 instructions)
; Uses:  $692F
; =====================================================================
SUB_2A80         LDY    #$0003
                 LDX    #$692F
                 LDA    #$0A
L_2A89           LDB    ,X
                 LEAX   -3,X
                 CMPB   #$19
                 BCC    L_2A93
                 CLR    ,X
L_2A93           LEAX   -1,X
                 DECA
                 BNE    L_2A89
                 RTS

; =====================================================================
; SUB_2A99 (76 instructions)
; Uses:  $622A ScreenNum $6388 WaitTimer MusicReq2 $7623 $7583 $76DA $76D5 $76D0 $76CB $6908 $6905 $6390 ...
; Calls: RST_WaitTimer AddTask SoundReset SUB_161C SUB_2B55 SUB_1FD6 RST_CopySprites RST_AddToObjects
; =====================================================================
SUB_2A99         LDA    #$0A
                 STA    <$02
L_2A9D           LDB    ,X
                 BEQ    L_2AA3
                 PULS   X,PC
L_2AA3           STB    <$01
                 TFR    Y,D
                 LEAX   D,X
                 LDB    <$01
                 DEC    <$02
                 BNE    L_2A9D
                 RTS
L_2AB0           JSR    <RST_WaitTimer
                 LDX    >$622A
                 LEAX   1,X
                 LDB    ,X
                 CMPB   #$7F
                 BNE    L_2AC2
                 LDX    #D_4E8B
                 LDB    ,X
L_2AC2           STX    >$622A
                 STB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 LDY    #$0500 ; queue BonusTimer(0)
                 JSR    >AddTask
                 CLRB
                 STB    >$6388
                 LDX    #WaitTimer
                 LDA    #$30
                 STA    ,X+
                 LDA    #$08
                 STA    ,X
                 RTS
L_2ADF           JSR    >SoundReset
                 LDX    #MusicReq2
                 LDA    #$0E
                 STA    ,X+
                 LDA    #$03
                 STA    ,X
                 LDB    #$10
                 LDY    #$0020
                 LDX    #$7623
                 JSR    >SUB_161C
                 LDX    #$7583
                 JSR    >SUB_161C
                 LDX    #$76DA
                 BSR    SUB_2B55
                 LDY    #D_4E5F
                 JSR    >SUB_1FD6
                 LDX    #$76D5
                 BSR    SUB_2B55
                 LDY    #D_4E65
                 JSR    >SUB_1FD6
                 LDX    #$76D0
                 BSR    SUB_2B55
                 LDY    #D_4E6B
                 JSR    >SUB_1FD6
                 LDX    #$76CB
                 BSR    SUB_2B55
                 LDY    #D_4E71
                 JSR    >SUB_1FD6
                 LDX    #D_4DB7
                 JSR    <RST_CopySprites
                 LDX    #$6908
                 LDA    #$44
                 STA    <$03
                 JSR    <RST_AddToObjects
                 LDA    #$13
                 STA    >$6905
                 LDB    #$20
                 STB    >WaitTimer ; frame countdown (RST_WaitTimer)
                 LDB    #$80
                 STB    >$6390
                 LDX    #$6388
                 INC    ,X
                 STX    >$63C0
                 RTS

; =====================================================================
; SUB_2B55 (212 instructions)
; Uses:  $6390 $6908 WaitTimer $6388 SndFx4 $690B $691B $6919 $6A24 $76C6 $6903 $62AF SndBoom $6A25 ...
; Calls: RST_CopySprites RST_AddToObjects RST_WaitTimer SUB_2B55 SUB_1FD6 RST_AddToObjectsB SUB_4459 AddTask ClearScreenAll SUB_360F ...
; =====================================================================
SUB_2B55         LDY    #$FFDB
                 LDA    #$0E
                 STA    <$03
                 LDB    #$10
L_2B5F           LDA    #$05
L_2B61           STB    ,X+
                 DECA
                 BNE    L_2B61
                 STB    <$01
                 TFR    Y,D
                 LEAX   D,X
                 LDB    <$01
                 DEC    <$03
                 BNE    L_2B5F
                 RTS
L_2B73           LDX    #$6390
                 INC    ,X
                 BEQ    L_2B9C
                 LDB    ,X
                 ANDB   #$07
                 BNE    L_2B9B
                 LDY    #D_4DE7
                 LDA    ,X
                 ANDA   #$08
                 BNE    L_2B8E
                 LDY    #D_4E0F
L_2B8E           EXG    Y,X
                 JSR    <RST_CopySprites
                 LDX    #$6908
                 LDA    #$44
                 STA    <$03
                 JSR    <RST_AddToObjects
L_2B9B           RTS
L_2B9C           LDX    #D_4DB7
                 JSR    <RST_CopySprites
                 LDX    #$6908
                 LDA    #$44
                 STA    <$03
                 JSR    <RST_AddToObjects
                 LDB    #$20
                 STB    >WaitTimer ; frame countdown (RST_WaitTimer)
                 LDX    #$6388
                 INC    ,X
                 RTS
L_2BB5           JSR    <RST_WaitTimer
                 LDX    #D_4E37
                 JSR    <RST_CopySprites
                 LDB    #$03
                 STB    >SndFx4
                 LDX    #$6388
                 INC    ,X
                 RTS
L_2BC7           LDX    #$690B
                 LDA    #$01
                 STA    <$03
                 JSR    <RST_AddToObjects
                 LDB    >$691B
                 CMPB   #$D0
                 BNE    L_2C18
                 LDB    #$20
                 STB    >$6919
                 LDX    #$6A24
                 LDA    #$7F
                 STA    ,X+
                 LDA    #$39
                 STA    ,X+
                 LDA    #$01
                 STA    ,X+
                 LDA    #$D8
                 STA    ,X
                 LDX    #$76C6
                 JSR    >SUB_2B55
                 LDY    #D_4E77
                 JSR    >SUB_1FD6
                 LDY    #$0004
                 LDD    #$0228
                 STD    <$02
                 LDX    #$6903
                 JSR    <RST_AddToObjectsB
                 CLRB
                 STB    >$62AF
                 LDB    #$03
                 STB    >SndBoom
                 LDX    #$6388
                 INC    ,X
L_2C18           RTS
L_2C19           LDX    #$62AF
                 DEC    ,X
                 LBEQ   L_2CA7
                 LDB    ,X
                 ANDB   #$07
                 BNE    L_2C18
                 LDX    #$6A25
                 LDB    ,X
                 EORB   #$80
                 STB    ,X
                 LDX    #$6919
                 LDA    ,X
                 ANDA   #$DF
                 STA    <$02
                 CLRB
                 JSR    >SUB_4459
                 ORB    #$20
                 STB    ,X
                 LDX    #$62AF
                 LDB    ,X
                 CMPB   #$E0
                 BNE    L_2C6C
                 LDB    #$50
                 STB    >$694F
                 CLRB
                 STB    >$694D
                 LDB    #$9F
                 STB    >$694C
                 LDB    >MarioX
                 CMPB   #$80
                 BCC    L_2C6A
                 LDB    #$80
                 STB    >$694D
                 LDB    #$5F
                 STB    >$694C
L_2C6A           LDB    ,X
L_2C6C           CMPB   #$C0
                 BNE    L_2CA6
                 LDX    #MusicReq2
                 LDA    #$0C
                 STA    ,X
                 LDB    >Level ; level number
                 RORB
                 BCS    L_2C81
                 LDA    #$05
                 STA    ,X
L_2C81           LEAX   1,X
                 LDA    #$03
                 STA    ,X
                 LDX    #$6A23
                 LDA    #$40
                 STA    ,X
                 LDA    #$09
                 STA    ,-X
                 LDA    #$76
                 STA    ,-X
                 LDA    #$8F
                 STA    ,-X
                 LDB    >MarioX
                 CMPB   #$80
                 BCC    L_2CA6
                 LDB    #$6F
                 STB    >$6A20
L_2CA6           RTS
L_2CA7           LDX    >$622A
                 LEAX   1,X
                 LDB    ,X
                 CMPB   #$7F
                 BNE    L_2CB7
                 LDX    #D_4E8B
                 LDB    ,X
L_2CB7           STX    >$622A
                 STB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 LDX    #Level
                 INC    ,X
                 LDY    #$0500 ; queue BonusTimer(0)
                 JSR    >AddTask
                 CLRB
                 STB    >$622E
                 STB    >$6388
                 LDX    #WaitTimer
                 LDA    #$E0
                 STA    ,X+
                 LDA    #$08
                 STA    ,X
                 RTS
L_2CDC           JSR    >ClearScreenAll
                 LDB    >Player2Ctrl
                 ADDB   #$12
                 STB    >GameState ; sub-state of GameMode
                 RTS
L_2CE8           JSR    >SUB_360F
L_2CEB           JSR    >SUB_3195
                 JSR    >SUB_328B
                 JSR    >SUB_2E4D
                 JSR    >SUB_337D
                 JSR    >SUB_40F7
                 JSR    >SUB_4065
                 JSR    >SUB_456C
                 JSR    >SUB_426B
                 JSR    >SUB_392B
                 JSR    >SUB_4239
                 JSR    >SUB_4325
                 JSR    >SUB_3630
                 JSR    >SUB_2DA7
                 JSR    >SUB_3EDD
                 JSR    >SUB_3351
                 JSR    >SUB_3B3C
                 JSR    >SUB_3A23
                 BSR    SUB_2D48
                 JSR    >SUB_1506
                 JSR    >SUB_3C3B
                 JSR    >SUB_3C52
                 JSR    >SUB_3258
                 BSR    SUB_2D77
                 JSR    >SUB_4413
                 LDB    >MarioAlive ; bit0 = Mario alive
                 BNE    L_2D47
                 JSR    >SoundReset
                 LDA    #$03
                 STA    >SndBoom
L_2D3E           LDX    #GameState
                 INC    ,X
                 LDA    #$40
                 STA    ,-X
L_2D47           RTS

; =====================================================================
; SUB_2D48 (23 instructions)
; Uses:  MarioX $6A0C MarioY $6343 $6342 $6340
; =====================================================================
SUB_2D48         LDB    >MarioX
                 LDA    #$03
                 LDX    #$6A0C
L_2D50           CMPB   ,X
                 BEQ    L_2D5A
                 LEAX   4,X
                 DECA
                 BNE    L_2D50
                 RTS
L_2D5A           LDB    >MarioY
                 LEAX   3,X
                 CMPB   ,X
                 BNE    L_2D76
                 LDA    ,--X
                 ANDA   #$08
                 BNE    L_2D76
                 LEAX   -1,X
                 STX    >$6343
                 CLRB
                 STB    >$6342
                 INCB
                 STB    >$6340
L_2D76           RTS

; =====================================================================
; SUB_2D77 (17 instructions)
; Uses:  $6386 $6387 $6216
; Calls: RST_JumpTable
; =====================================================================
SUB_2D77         LDB    >$6386
                 JSR    <RST_JumpTable
TBL_2D7C         FDB    L_2D8F
                 FDB    L_2D86
                 FDB    L_2D90
                 FDB    L_2D9D
                 FDB    ColdStart
L_2D86           CLRB
                 STB    >$6387
                 LDB    #$02
                 STB    >$6386
L_2D8F           RTS
L_2D90           LDX    #$6387
                 DEC    ,X
                 BNE    L_2D8F
                 LDB    #$03
                 STB    >$6386
                 RTS
L_2D9D           LDB    >$6216
                 BNE    L_2D8F
                 PULS   X
                 JMP    >L_2D3E

; =====================================================================
; SUB_2DA7 (82 instructions)
; Uses:  MarioX $6291 MarioY $6292 $6290 $6340 $6342 $6225 $6216
; Calls: RST_RetIfNotScreen SUB_316B
; =====================================================================
SUB_2DA7         LDB    #$08
                 JSR    <RST_RetIfNotScreen
                 LDB    >MarioX
                 CMPB   #$4B
                 BEQ    L_2DBD
                 CMPB   #$B3
                 BEQ    L_2DBD
                 LDB    >$6291
                 DECB
                 BEQ    L_2DC3
L_2DBC           RTS
L_2DBD           LDB    #$01
                 STB    >$6291
                 RTS
L_2DC3           STB    >$6291
                 STB    <$02
                 LDB    >MarioY
                 DECB
                 CMPB   #$D0
                 BCC    L_2DBC
                 TFR    B,A
                 ROLA
                 ROLB
                 BCC    L_2DDC
                 LDA    <$02
                 ORA    #$04
                 STA    <$02
L_2DDC           TFR    B,A
                 ROLA
                 ROLB
                 ROLA
                 ROLB
                 BCC    L_2DEA
                 LDA    <$02
                 ORA    #$02
                 STA    <$02
L_2DEA           ANDB   #$07
                 CMPB   #$06
                 BNE    L_2DF6
                 LDA    <$02
                 ORA    #$02
                 STA    <$02
L_2DF6           LDB    >MarioX
                 ROLB
                 BCC    L_2E02
                 LDA    <$02
                 ORA    #$01
                 STA    <$02
L_2E02           LDX    #$6292
                 TFR    X,D
                 ADDB   <$02
                 TFR    D,X
                 LDB    ,X
                 BEQ    L_2E47
                 CLR    ,X
                 LDX    #$6290
                 DEC    ,X
                 LDB    <$02
                 RORB
                 BCS    L_2E48
                 LDX    #$02CB
L_2E1E           TSTB
                 BEQ    L_2E26
L_2E21           LEAX   5,X
                 DECB
                 BNE    L_2E21
L_2E26           LEAX   >29696,X
                 LDB    #$10
                 STB    ,X
                 STB    ,-X
                 LEAX   2,X
                 STB    ,X
                 LDB    #$01
                 STB    >$6340
                 STB    >$6342
                 STB    >$6225
                 LDB    >$6216
                 BNE    L_2E47
                 JSR    >SUB_316B
L_2E47           RTS
L_2E48           LDX    #$012B
                 BRA    L_2E1E

; =====================================================================
; SUB_2E4D (337 instructions)
; Uses:  $6216 $621E $6217 $6215 InputState MarioY MarioX $6207 $621A $6218 $6202 $6210 $6204 $6206 ...
; Calls: SUB_3864 SUB_37B6 SUB_37F6 SUB_3850 SUB_3F7B CheckJumpOver SUB_3DA2 SUB_316B SUB_4459 SUB_3165 ...
; =====================================================================
SUB_2E4D         LDB    >$6216
                 DECB
                 LBEQ   L_2F6C
                 LDB    >$621E
                 LBNE   L_2F00
                 LDB    >$6217
                 DECB
                 BEQ    L_2E70
                 LDB    >$6215
                 DECB
                 BEQ    L_2ED9
                 LDB    >InputState ; joystick+jump, bit7 = jump edge
                 ROLB
                 LBCS   L_2F20
L_2E70           JSR    >SUB_3864
                 LDB    >InputState ; joystick+jump, bit7 = jump edge
                 DEC    <$05
                 BEQ    L_2E82
                 TFR    B,A
                 ANDA   #$01
                 LBNE   L_304C
L_2E82           DEC    <$04
                 BEQ    L_2E8E
                 TFR    B,A
                 ANDA   #$02
                 LBNE   L_306B
L_2E8E           LDB    >$6217
                 DECB
                 BEQ    L_2EF0
                 LDB    >MarioY
                 ADDB   #$08
                 STB    <$04
                 LDB    >MarioX
                 ORB    #$03
                 ANDB   #$FB
                 LDX    #$0015
                 STX    <$02
                 JSR    >SUB_37B6
                 PSHS   B
                 LDX    #$6207
                 LDB    ,X
                 ANDB   #$80
                 ORB    #$06
                 STB    ,X
                 LDX    #$621A
                 LDB    #$04
                 CMPB   <$03
                 LDA    #$01
                 STA    ,X
                 BCC    L_2EC6
                 DEC    ,X
L_2EC6           PULS   B
                 TSTB
                 BEQ    L_2EF4
                 LDB    ,X
                 BNE    L_2EF0
                 LEAX   1,X
                 LDA    <$04
                 STA    ,X+
                 LDA    <$02
                 STA    ,X
L_2ED9           LDB    >InputState ; joystick+jump, bit7 = jump edge
                 ANDB   #$08
                 LBNE   L_30BF
                 LDB    >$6215
                 BEQ    L_2EF0
L_2EE7           LDB    >InputState ; joystick+jump, bit7 = jump edge
                 ANDB   #$04
                 LBNE   L_30D2
L_2EF0           LDY    <$04
                 RTS
L_2EF4           LEAX   1,X
                 LDA    <$02
                 STA    ,X+
                 LDA    <$04
                 STA    ,X
                 BRA    L_2EE7
L_2F00           LDX    #$621E
                 DEC    ,X
                 BNE    L_2F6B
                 LDB    >$6218
                 STB    >$6217
                 LDX    #$6207
                 LDB    ,X
                 ANDB   #$80
                 STB    ,X
                 CLRB
                 STB    >$6202
                 LDY    <$04
                 JMP    >L_3180
L_2F20           LDB    #$01
                 STB    >$6216
                 LDB    >InputState ; joystick+jump, bit7 = jump edge
                 LDX    #$0080
                 RORB
                 BCS    L_2F37
                 LDX    #$FF80
                 RORB
                 BCS    L_2F37
                 LDX    #$0000
L_2F37           STX    <$02
                 TFR    X,D
                 LDX    #$6210
                 STD    ,X++
                 LDA    #$01
                 STA    ,X+
                 LDA    #$48
                 STA    ,X+
                 CLRB
                 STB    ,X
                 STB    >$6204
                 STB    >$6206
                 LDB    >$6207
                 ANDB   #$80
                 ORB    #$0E
                 STB    >$6207
                 LDB    >MarioY
                 STB    >$620E
                 LDX    #SndJump
                 LDA    #$03
                 STA    ,X
                 LDY    <$04
L_2F6B           RTS
L_2F6C           LDU    #MarioAlive
                 LDB    >MarioX
                 STB    11,U
                 LDB    >MarioY
                 STB    12,U
                 JSR    >SUB_37F6
                 JSR    >SUB_3864
                 DEC    <$04
                 BNE    L_2FA5
                 CLR    <16,U
                 LDA    #$80
                 STA    <17,U
                 LDA    7,U
                 ORA    #$80
                 STA    7,U
L_2F91           LDB    >$6220
                 DECB
                 BEQ    L_2FA0
                 JSR    >SUB_3850
                 STX    <18,U
                 CLR    <20,U
L_2FA0           JSR    >SUB_37F6
                 BRA    L_2FB7
L_2FA5           DEC    <$05
                 BNE    L_2FB7
                 LDD    #$FF80
                 STD    <16,U
                 LDA    7,U
                 ANDA   #$7F
                 STA    7,U
                 BRA    L_2F91
L_2FB7           LDY    <$04
                 JSR    >SUB_3F7B
                 DECB
                 BEQ    L_2FEE
                 LDB    >$621F
                 DECB
                 BEQ    L_302F
                 LDB    >$6214
                 SUBB   #$14
                 BNE    L_2FE5
                 LDB    #$01
                 STB    >$621F
                 JSR    >CheckJumpOver
                 TSTB
                 LBEQ   L_3180
                 STB    >$6342
                 LDB    #$01
                 STB    >$6340
                 STB    >$6225
L_2FE5           INCB
                 BNE    L_2FEB
                 JSR    >SUB_3DA2
L_2FEB           JMP    >L_3180
L_2FEE           DEC    <$02
                 BEQ    L_3004
                 INCB
                 STB    >$621F
                 CLRB
                 LDX    #$6210
                 LDA    #$05
L_2FFC           STB    ,X+
                 DECA
                 BNE    L_2FFC
                 JMP    >L_3180
L_3004           STB    >$6216
                 LDB    >$6220
                 EORB   #$01
                 STB    >MarioAlive ; bit0 = Mario alive
                 LDX    #$6207
                 LDB    ,X
                 ANDB   #$80
                 ORB    #$0F
                 STB    ,X
                 LDB    #$04
                 STB    >$621E
                 CLRB
                 STB    >$621F
                 LDB    >$6225
                 DECB
                 BNE    L_302C
                 JSR    >SUB_316B
L_302C           JMP    >L_3180
L_302F           LDB    >MarioY
                 LDX    #$620E
                 SUBB   #$0F
                 CMPB   ,X
                 LBCS   L_3180
                 LDB    #$01
                 STB    >$6220
                 LDX    #SndFx4
                 LDA    #$03
                 STA    ,X
                 JMP    >L_3180
L_304C           LDA    #$01
                 STA    <$02
                 LDY    <$04
                 LDB    >$620F
                 BNE    L_3099
                 LDB    >$6202
                 STB    <$02
                 LDB    #$05
                 JSR    >SUB_4459
                 STB    >$6202
                 ANDB   #$03
                 ORB    #$80
                 BRA    L_3086
L_306B           LDA    #$FF
                 STA    <$02
                 LDY    <$04
                 LDB    >$620F
                 BNE    L_3099
                 LDB    >$6202
                 STB    <$02
                 LDB    #$01
                 JSR    >SUB_4459
                 STB    >$6202
                 ANDB   #$03
L_3086           LDX    #$6207
                 STB    ,X
                 RORB
                 BCC    L_3091
                 JSR    >SUB_3165
L_3091           LDB    #$02
                 STB    >$620F
                 JMP    >L_3180
L_3099           LDX    #MarioX
                 LDB    ,X
                 ADDB   <$02
                 STB    ,X
                 LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 DECB
                 BNE    L_30B7
                 LDA    ,X
                 LDB    >MarioY
                 TFR    D,X
                 JSR    >SUB_376C
                 LDB    <$07
                 STB    >MarioY
L_30B7           LDX    #$620F
                 DEC    ,X
                 JMP    >L_3180
L_30BF           LDY    <$04
                 LDB    >$620F
                 LBNE   L_315F
                 LDB    #$03
                 STB    >$620F
                 LDB    #$02
                 BRA    L_30E1
L_30D2           LDY    <$04
                 LDB    >$620F
                 BNE    L_314B
                 LDB    #$04
                 STB    >$620F
                 LDB    #$FE
L_30E1           LDX    #MarioY
                 ADDB   ,X
                 STB    ,X
                 STB    <$02
                 LDB    >$6222
                 EORB   #$01
                 STB    >$6222
                 BNE    L_3127
                 LDB    <$02
                 ADDB   #$08
                 LDX    #$621C
                 CMPB   ,X
                 BEQ    L_313D
                 SUBB   ,-X
                 BEQ    L_313D
                 LDA    #$05
                 STA    <$02
                 SUBB   #$08
                 BEQ    L_3113
                 DEC    <$02
                 SUBB   #$04
                 BEQ    L_3113
                 DEC    <$02
L_3113           LDB    #$80
                 LDX    #$6207
                 ANDB   ,X
                 EORB   #$80
                 ORB    <$02
                 STB    ,X
L_3120           LDB    #$01
                 STB    >$6215
                 BRA    L_3180
L_3127           LDB    ,--X
                 ORB    #$03
                 ANDB   #$FB
                 STB    ,X
                 LDB    >$6224
                 EORB   #$01
                 STB    >$6224
                 BNE    L_3120
                 BSR    SUB_3165
                 BRA    L_3120
L_313D           LDB    #$06
                 STB    >$6207
                 CLRB
                 STB    >$6219
                 STB    >$6215
                 BRA    L_3180
L_314B           LDB    >$621A
                 BEQ    L_315F
                 STB    >$6219
                 LDB    >$621C
                 SUBB   #$13
                 LDX    #MarioY
                 CMPB   ,X
                 BCC    L_3164
L_315F           LDX    #$620F
                 DEC    ,X
L_3164           RTS

; =====================================================================
; SUB_3165 (3 instructions)
; Uses:  SndWalk
; =====================================================================
SUB_3165         LDB    #$03
                 STB    >SndWalk ; sound buffer: frames to hold latch
                 RTS

; =====================================================================
; SUB_316B (19 instructions)
; Uses:  $6225 ScreenNum MusicReq2 $694C MarioX $6207 MarioY
; =====================================================================
SUB_316B         STB    >$6225
                 LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 DECB
                 BEQ    L_317F
                 LDX    #MusicReq2
                 LDA    #$0D
                 STA    ,X+
                 LDA    #$03
                 STA    ,X
L_317F           RTS
L_3180           LDX    #$694C
                 LDB    >MarioX
                 ANDB   #$FE
                 STB    ,X+
                 LDB    >$6207
                 STB    ,X++
                 LDB    >MarioY
                 STB    ,X
                 RTS

; =====================================================================
; SUB_3195 (85 instructions)
; Uses:  $6340 $6341 $6342 SndFx5 Level RandNum $6343 MarioY MarioX $6A30
; Calls: RST_JumpTable AddTask RST_RetIfNotScreen
; =====================================================================
SUB_3195         LDB    >$6340
                 JSR    <RST_JumpTable
TBL_MarioJump    FDB    L_3248
                 FDB    L_31A2
                 FDB    L_3249
                 FDB    ColdStart
L_31A2           LDB    #$40
                 STB    >$6341
                 LDB    #$02
                 STB    >$6340
                 LDB    >$6342
                 RORB
                 BCS    L_3201
                 RORB
                 BCS    L_31D3
                 RORB
                 BCS    L_31CA
                 LDX    #SndFx5
                 LDA    #$03
                 STA    ,X
                 LDB    >Level ; level number
                 DECB
                 BEQ    L_31D3
                 DECB
                 BEQ    L_31DD
                 BRA    L_31E7
L_31CA           LDB    >RandNum ; random number
                 RORB
                 BCS    L_31DD
                 RORB
                 BCS    L_31E7
L_31D3           LDA    #$7D
                 STA    <$02
                 LDY    #$0003
                 BRA    L_31EF
L_31DD           LDA    #$7E
                 STA    <$02
                 LDY    #$0005
                 BRA    L_31EF
L_31E7           LDA    #$7F
                 STA    <$02
                 LDY    #$0008 ; queue AddScore(8)
L_31EF           JSR    >AddTask
                 LDX    >$6343
                 LDB    ,X
                 CLR    ,X
                 LEAX   3,X
                 LDA    ,X
                 STA    <$03
                 BRA    L_322C
L_3201           LDY    #$0001
                 LDA    #$7B
                 STA    <$02
                 RORB
                 BCC    L_321F
                 LDY    #$0003
                 LDA    #$7D
                 STA    <$02
                 RORB
                 BCC    L_321F
                 LDY    #$0005
                 LDA    #$7F
                 STA    <$02
L_321F           JSR    >AddTask
                 LDB    >MarioY
                 ADDB   #$14
                 STB    <$03
                 LDB    >MarioX
L_322C           LDX    #$6A30
                 STB    ,X+
                 LDA    <$02
                 STA    ,X+
                 LDA    #$07
                 STA    ,X+
                 LDA    <$03
                 STA    ,X
                 LDB    #$05
                 JSR    <RST_RetIfNotScreen
                 LDX    #SndFx5
                 LDA    #$03
                 STA    ,X
L_3248           RTS
L_3249           LDX    #$6341
                 DEC    ,X
                 BNE    L_3248
                 CLRB
                 STB    >$6A30
                 STB    >$6340
                 RTS

; =====================================================================
; SUB_3258 (24 instructions)
; Uses:  ScreenNum MarioY MarioX $694D $6290 GameState
; =====================================================================
SUB_3258         LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 TFR    B,A
                 ANDA   #$04
                 BNE    L_327F
                 RORB
                 LDB    >MarioY
                 BCS    L_327A
                 CMPB   #$51
                 BCC    L_3248
                 LDB    >MarioX
                 ROLB
L_326F           LDB    #$00
                 BCS    L_3275
                 LDB    #$80
L_3275           STB    >$694D
                 BRA    L_3284
L_327A           CMPB   #$31
                 BCS    L_326F
                 RTS
L_327F           LDB    >$6290
                 BNE    L_3294
L_3284           LDB    #$16
                 STB    >GameState ; sub-state of GameMode
                 PULS   X,PC

; =====================================================================
; SUB_328B (5 instructions)
; Uses:  $6350
; Calls: SUB_3295
; =====================================================================
SUB_328B         LDB    >$6350
                 BEQ    L_3294
                 BSR    SUB_3295
                 PULS   X,PC
L_3294           RTS

; =====================================================================
; SUB_3295 (85 instructions)
; Uses:  $6345 $6351 $69B8 $69D0 $6980 $6353 $6354 $6342 $6A2C MusicReq2 $6346 $6A2D $6350 $6340 ...
; Calls: RST_JumpTable
; =====================================================================
SUB_3295         LDB    >$6345
                 JSR    <RST_JumpTable
TBL_329A         FDB    L_32A0
                 FDB    L_330B
                 FDB    L_332B
L_32A0           LDB    >$6351
                 LDX    #$69B8
                 CMPB   #$65
                 BEQ    L_32B2
                 LDX    #$69D0
                 BCS    L_32B2
                 LDX    #$6980
L_32B2           LDU    >$6351
                 CLRA
                 LDB    >$6353
                 TFR    D,Y
                 LDB    >$6354
                 BEQ    L_32CD
L_32C0           LEAX   4,X
                 STB    <$01
                 TFR    Y,D
                 LEAU   D,U
                 LDB    <$01
                 DECB
                 BNE    L_32C0
L_32CD           CLR    ,U
                 LDB    #$02
                 LDA    <21,U
                 BEQ    L_32D8
                 LDB    #$04
L_32D8           STB    >$6342
                 STU    <$08
                 LDU    #$6A2C
                 LDB    ,X
                 CLR    ,X
                 STB    ,U
                 LDB    #$60
                 STB    1,U
                 LEAX   3,X
                 LDB    ,X
                 STB    3,U
                 LDU    <$08
                 LDX    #$6345
                 INC    ,X+
                 LDA    #$06
                 STA    ,X+
                 LDA    #$05
                 STA    ,X
                 LDX    #MusicReq2
                 LDA    #$06
                 STA    ,X+
                 LDA    #$03
                 STA    ,X
                 RTS
L_330B           LDX    #$6346
                 DEC    ,X
                 BNE    L_332A
                 LDA    #$06
                 STA    ,X+
                 DEC    ,X
                 BEQ    L_3324
                 LDX    #$6A2D
                 LDB    ,X
                 EORB   #$01
                 STB    ,X
                 RTS
L_3324           LDA    #$04
                 STA    ,X
                 INC    ,--X
L_332A           RTS
L_332B           LDX    #$6346
                 DEC    ,X
                 BNE    L_3350
                 LDA    #$0C
                 STA    ,X+
                 DEC    ,X
                 BEQ    L_3340
                 LDX    #$6A2D
                 INC    ,X
                 RTS
L_3340           CLRB
                 STB    ,--X
                 STB    >$6350
                 INCB
                 STB    >$6340
                 LDX    #$6A2C
                 STX    >$6343
L_3350           RTS

; =====================================================================
; SUB_3351 (17 instructions)
; Uses:  $6221 $6204 $6206 $6210 $6211 $6212 $6213 $6214 $6216 $621F MarioY $620E
; =====================================================================
SUB_3351         LDB    >$6221
                 BEQ    L_337C
                 CLRB
                 STB    >$6204
                 STB    >$6206
                 STB    >$6221
                 STB    >$6210
                 STB    >$6211
                 STB    >$6212
                 STB    >$6213
                 STB    >$6214
                 INCB
                 STB    >$6216
                 STB    >$621F
                 LDB    >MarioY
                 STB    >$620E
L_337C           RTS

; =====================================================================
; SUB_337D (227 instructions)
; Uses:  ScreenNum Barrels $6980 MarioY
; Calls: Z80_EXX SUB_376C SUB_3827 SUB_38F6 SUB_37F6 SUB_3E8A SUB_3850 SUB_3706 SUB_356C
; =====================================================================
SUB_337D         LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 DECB
                 BNE    L_337C
                 LDU    #Barrels
                 LDX    #$6980
                 LDY    #$0020
                 LDA    #$0A
                 STA    <$02
L_3391           LDB    ,U
                 DECB
                 BEQ    L_33A7
                 LEAX   3,X
L_3398           LEAX   1,X
                 STB    <$01
                 TFR    Y,D
                 LEAU   D,U
                 LDB    <$01
                 DEC    <$02
                 BNE    L_3391
                 RTS
L_33A7           LDB    1,U
                 DECB
                 LBEQ   L_34EE
                 LDB    2,U
                 RORB
                 BCS    L_33BC
                 RORB
                 BCS    L_33F0
                 RORB
                 BCS    L_33FC
                 JMP    >L_3467
L_33BC           JSR    >Z80_EXX
                 INC    5,U
                 LDB    <23,U
                 CMPB   5,U
                 BNE    L_33DE
                 LDB    <21,U
                 TFR    B,A
                 ROLA
                 ROLB
                 ROLA
                 ROLB
                 ADDB   #$15
                 STB    7,U
                 LDB    2,U
                 EORB   #$07
                 STB    2,U
                 JMP    >L_35C5
L_33DE           LDB    15,U
                 DECB
                 BNE    L_33EB
                 LDB    7,U
                 EORB   #$01
                 STB    7,U
                 LDB    #$04
L_33EB           STB    15,U
                 JMP    >L_35C5
L_33F0           JSR    >Z80_EXX
                 LDX    #$0100
                 STX    <$02
                 INC    3,U
                 BRA    L_3406
L_33FC           JSR    >Z80_EXX
                 LDX    #$FF04
                 STX    <$02
                 DEC    3,U
L_3406           LDA    3,U
                 LDB    5,U
                 TFR    D,X
                 ANDA   #$07
                 CMPA   #$03
                 LBEQ   L_3558
                 TFR    X,D
                 SUBB   #$03
                 TFR    D,X
                 JSR    >SUB_376C
                 LDD    <$06
                 ADDB   #$03
                 TFR    D,X
                 STB    5,U
                 JSR    >SUB_3827
                 JSR    >SUB_38F6
                 LDB    3,U
                 CMPB   #$1C
                 BCS    L_3442
                 CMPB   #$E4
                 LBCS   L_35C5
                 CLRB
                 STB    <16,U
                 LDA    #$60
                 STA    <17,U
                 BRA    L_344D
L_3442           CLRB
                 LDA    #$FF
                 STA    <16,U
                 LDA    #$A0
                 STA    <17,U
L_344D           LDA    #$FF
                 STA    <18,U
                 LDA    #$F0
                 STA    <19,U
                 STB    <20,U
                 STB    14,U
                 STB    4,U
                 STB    6,U
                 LDA    #$08
                 STA    2,U
                 JMP    >L_35C5
L_3467           JSR    >Z80_EXX
                 JSR    >SUB_37F6
                 JSR    >SUB_3E8A
                 TSTB
                 BNE    L_3495
                 LDB    3,U
                 ADDB   #$08
                 CMPB   #$10
                 BCS    L_348D
                 JSR    >SUB_38F6
                 LDB    <16,U
                 ANDB   #$01
                 ASLB
                 ASLB
                 STB    <$03
                 JSR    >SUB_3827
                 JMP    >L_35C5
L_348D           CLRB
                 STB    ,U
                 STB    3,U
                 JMP    >L_35C5
L_3495           INC    14,U
                 LDB    14,U
                 DECB
                 BEQ    L_34AE
                 DECB
                 BEQ    L_34CB
                 LDB    #$04
                 LDA    <16,U
                 DECA
                 BNE    L_34A9
                 LDB    #$02
L_34A9           STB    2,U
                 JMP    >L_35C5
L_34AE           LDB    <21,U
                 BNE    L_34BE
                 LDX    #MarioY
                 LDB    5,U
                 SUBB   #$16
                 CMPB   ,X
                 BCC    L_34CB
L_34BE           LDB    <16,U
                 BNE    L_34E4
                 STB    <17,U
                 LDA    #$FF
                 STA    <16,U
L_34CB           JSR    >SUB_3850
                 TFR    X,D
                 LSRA
                 RORB
                 LSRA
                 RORB
                 TFR    D,X
                 STD    <18,U
                 CLRB
                 STB    <20,U
                 STB    4,U
                 STB    6,U
                 JMP    >L_35C5
L_34E4           LDA    #$01
                 STA    <16,U
                 CLR    <17,U
                 BRA    L_34CB
L_34EE           JSR    >Z80_EXX
                 JSR    >SUB_37F6
                 TFR    X,D
                 SUBA   #$1A
                 LDB    <25,U
                 STB    <$02
                 CMPA   <$02
                 BCS    L_350A
                 JSR    >SUB_3E8A
                 TSTB
                 BNE    L_351C
                 JSR    >SUB_38F6
L_350A           LDB    3,U
                 ADDB   #$08
                 CMPB   #$10
                 LBCC   L_33DE
                 CLRB
                 STB    ,U
                 STB    3,U
                 JMP    >L_35C5
L_351C           LDB    5,U
                 CMPB   #$E0
                 BCS    L_3542
                 LDB    7,U
                 ANDB   #$FC
                 ORB    #$01
                 STB    7,U
                 CLRB
                 STB    1,U
                 STB    2,U
                 LDA    #$FF
                 STD    <16,U
                 STB    <18,U
                 LDA    #$B0
                 STA    <19,U
                 LDA    #$01
                 STA    14,U
                 BRA    L_354E
L_3542           JSR    >SUB_3850
                 JSR    >SUB_3706
                 LDB    5,U
                 STB    <25,U
                 CLRB
L_354E           STB    <20,U
                 STB    4,U
                 STB    6,U
                 JMP    >L_35C5
L_3558           TFR    X,D
                 ADDB   #$05
                 STY    <$04
                 STB    <$04
                 TFR    A,B
                 LDX    #$0015
                 STX    <$02
                 BSR    SUB_356C
                 BRA    L_35C5

; =====================================================================
; SUB_356C (51 instructions)
; Uses:  $6348 MarioY Difficulty RandNum InputState MarioX
; Calls: SUB_37B6 Z80_EXX
; =====================================================================
SUB_356C         JSR    >SUB_37B6
                 DECB
                 BNE    L_35C4
                 LDB    <$02
                 SUBB   #$05
                 STB    <23,U
                 LDB    >$6348
                 BEQ    L_35BC
                 LDB    >MarioY
L_3581           SUBB   #$10 ; difficulty operand: $10 easy / $04 hard (patched by Setup)  [SMC: operand patched by $58E1]
                 STY    <$04
                 CMPB   <$04
                 BCS    L_35C4
                 LDB    >Difficulty
                 RORB
                 INCB
                 STB    <$02
                 LDB    >RandNum ; random number
                 STB    <$03
                 ANDB   #$03
                 CMPB   <$02
                 BCC    L_35C4
                 LDX    #InputState
                 LDB    >MarioX
                 CMPB   <$05
                 BEQ    L_35BC
                 BCC    L_35B0
                 LDA    ,X
                 ANDA   #$01
                 BEQ    L_35B6
                 BRA    L_35BC
L_35B0           LDA    ,X
                 ANDA   #$02
                 BNE    L_35BC
L_35B6           LDB    <$03
                 ANDB   #$18
                 BNE    L_35C4
L_35BC           INC    7,U
                 LDA    2,U
                 ORA    #$01
                 STA    2,U
L_35C4           RTS
L_35C5           JSR    >Z80_EXX
                 LDB    3,U
                 ANDB   #$FE
                 STB    ,X+
                 LDB    7,U
                 STB    ,X++
                 LDB    5,U
                 STB    ,X
                 JMP    >L_3398
D_35D9           FCB    $80,$FE,$01,$C0,$04,$50,$02,$10
                 FCB    $82,$60,$02,$10,$82,$CA,$01,$10
                 FCB    $81,$FF,$02,$38,$01,$80,$02,$FF
                 FCB    $04,$80,$04,$60,$80,$11,$D1,$21
                 FCB    $21,$CC,$63,$7E,$07,$83,$5F,$1A
                 FCB    $32,$10,$60,$2C,$7E,$35,$A7,$C0
                 FCB    $1C,$1A,$77,$2D,$34,$C9

; =====================================================================
; SUB_360F (16 instructions)
; Uses:  $63CC InputState
; =====================================================================
SUB_360F         LDY    #D_35D9
                 LDX    #$63CC
                 LDB    ,X+
                 ASLB
                 LEAY   B,Y
                 LDB    ,Y
                 STB    >InputState ; joystick+jump, bit7 = jump edge
                 LDB    ,X
                 DEC    ,X
                 TSTB
                 BNE    L_362F
                 LEAY   1,Y
                 LDB    ,Y
                 STB    ,X
                 INC    ,-X
L_362F           RTS

; =====================================================================
; SUB_3630 (26 instructions)
; Uses:  FrameCounter $6280 $6288 $621A
; Calls: RST_RetIfNotScreen RST_JumpTable SUB_3671
; =====================================================================
SUB_3630         LDB    #$02
                 JSR    <RST_RetIfNotScreen
                 LDB    >FrameCounter ; decremented every frame
                 RORB
                 LDX    #$6280
                 LDB    ,X
                 BCS    L_3644
                 LDX    #$6288
                 LDB    ,X
L_3644           PSHS   X
                 JSR    <RST_JumpTable
TBL_3648         FDB    L_3654
                 FDB    L_3687
                 FDB    L_36C7
                 FDB    L_36D3
                 FDB    ColdStart
                 FDB    ColdStart
L_3654           PULS   X
                 LEAX   1,X
                 DEC    ,X
                 BNE    L_3668
                 INC    ,-X
                 LEAX   2,X
                 BSR    SUB_3671
                 LDB    #$01
                 STB    >$621A
                 RTS
L_3668           LEAX   1,X
                 BSR    SUB_3671
                 CLRB
                 STB    >$621A
                 RTS

; =====================================================================
; SUB_3671 (65 instructions)
; Uses:  MarioY $6216 MarioX $6222 RandNum
; Calls: SUB_36F3 SUB_3671 SUB_5334
; =====================================================================
SUB_3671         LDB    >MarioY
                 CMPB   #$7A
                 BCC    L_3684
                 LDB    >$6216
                 BNE    L_3684
                 LDB    >MarioX
                 CMPB   ,X
                 BEQ    L_3686
L_3684           PULS   X,PC
L_3686           RTS
L_3687           PULS   X
                 LEAX   4,X
                 DEC    ,X
                 BNE    L_3686
                 LDB    #$04
                 STB    ,X
                 INC    ,-X
                 JSR    >SUB_36F3
                 LDB    #$78
                 CMPB   ,X
                 BNE    L_36A4
                 LEAX   -3,X
                 INC    ,X
                 LEAX   3,X
L_36A4           LEAX   -1,X
                 BSR    SUB_3671
                 LDB    >MarioY
                 CMPB   #$68
                 BCC    L_36BA
L_36AF           LDX    #MarioY
                 INC    ,X
                 JSR    >SUB_5334
                 INC    ,X
                 RTS
L_36BA           RORB
                 BCS    L_36AF
                 RORB
                 LDB    #$01
                 BCS    L_36C3
                 CLRB
L_36C3           STB    >$6222
                 RTS
L_36C7           PULS   X
                 LDB    >RandNum ; random number
                 ANDB   #$3C
                 BNE    L_36D2
                 INC    ,X
L_36D2           RTS
L_36D3           PULS   X
                 LEAX   4,X
                 DEC    ,X
                 BNE    L_36F2
                 LDA    #$02
                 STA    ,X
                 DEC    ,-X
                 BSR    SUB_36F3
                 LDB    #$68
                 CMPB   ,X
                 BNE    L_36F2
                 CLRB
                 LDA    #$80
                 STA    <$02
                 STA    ,--X
                 STB    ,-X
L_36F2           RTS

; =====================================================================
; SUB_36F3 (8 instructions)
; Uses:  $694B $6947
; =====================================================================
SUB_36F3         TFR    X,D
                 LDA    ,X
                 LDY    #$694B
                 ANDB   #$08
                 BNE    L_3703
                 LDY    #$6947
L_3703           STA    ,Y
                 RTS

; =====================================================================
; SUB_3706 (45 instructions)
; Uses:  $6348 Difficulty Level RandNum MarioX
; Calls: RST_JumpTable
; =====================================================================
SUB_3706         LDB    >$6348
                 BEQ    L_371B
                 LDB    >Difficulty
                 DECB
                 JSR    <RST_JumpTable
TBL_3711         FDB    L_372F
                 FDB    L_372F
                 FDB    L_373C
                 FDB    L_373C
                 FDB    L_3751
L_371B           LDA    >Level ; level number
                 LDB    #$01
                 DECA
                 STA    <$02
                 BEQ    L_3732
                 LDB    #$B1
                 DEC    <$02
                 BEQ    L_3732
                 LDB    #$E9
                 BRA    L_3732
L_372F           LDB    >RandNum ; random number
L_3732           STB    <17,U
                 ANDB   #$01
                 DECB
                 STB    <16,U
                 RTS
L_373C           LDB    >RandNum ; random number
                 STB    <17,U
                 LDB    >MarioX
                 CMPB   3,U
                 LDB    #$01
                 BCC    L_374D
                 LDB    #$FF
L_374D           STB    <16,U
                 RTS
L_3751           LDB    >MarioX
                 SUBB   3,U
                 STB    <$01
                 LDA    #$FF
                 BCS    L_375D
                 INCA
L_375D           ROL    <$01
                 ROLB
                 ROLA
                 ROL    <$01
                 ROLB
                 ROLA
                 STA    <16,U
                 STB    <17,U
                 RTS

; =====================================================================
; SUB_376C (38 instructions)
; =====================================================================
SUB_376C         LDB    #$0F
                 STX    <$06
                 ANDB   <$06
                 DEC    <$02
                 BEQ    L_3780
                 CMPB   #$0F
                 BCS    L_37AB
                 LDA    #$FF
                 STA    <$02
                 BRA    L_3788
L_3780           CMPB   #$01
                 BCC    L_37AB
                 LDA    #$01
                 STA    <$02
L_3788           LDB    #$F0
                 CMPB   <$07
                 BEQ    L_37A7
                 LDB    #$4C
                 CMPB   <$07
                 BEQ    L_37AC
                 LDB    <$07
                 LDA    <$07
                 ANDA   #$20
                 BEQ    L_37A3
L_379C           SUBB   <$02
L_379E           STB    <$07
                 LDX    <$06
                 RTS
L_37A3           ADDB   <$02
                 BRA    L_379E
L_37A7           LDA    <$06
                 BMI    L_379C
L_37AB           RTS
L_37AC           LDB    <$06
                 CMPB   #$98
                 BCS    L_37AB
                 LDB    <$07
                 BRA    L_37A3

; =====================================================================
; SUB_37B6 (30 instructions)
; Uses:  $6300
; =====================================================================
SUB_37B6         LDX    #$6300
L_37B9           CMPB   ,X+
                 BEQ    L_37C3
                 DEC    <$03
                 BNE    L_37B9
                 BRA    L_37F0
L_37C3           PSHS   X
                 DEC    <$03
                 LEAX   <20,X
                 STB    <$05
                 LDB    <$04
                 CMPB   ,X
                 BEQ    L_37E1
                 LEAX   <21,X
                 CMPB   ,X
                 BEQ    L_37E8
                 STB    <$04
                 LDB    <$05
                 PULS   X
                 BRA    L_37B9
L_37E1           LEAX   <21,X
                 LDB    #$01
                 BRA    L_37EC
L_37E8           CLRB
                 LEAX   <-21,X
L_37EC           LDA    ,X
                 STA    <$02
L_37F0           PULS   X
                 LDY    <$04
                 RTS

; =====================================================================
; SUB_37F6 (27 instructions)
; =====================================================================
SUB_37F6         LDB    4,U
                 ADDB   <17,U
                 STB    4,U
                 LDB    3,U
                 ADCB   <16,U
                 STB    3,U
                 LDB    6,U
                 SUBB   <19,U
                 LDA    5,U
                 SBCA   <18,U
                 TFR    D,X
                 LDB    <20,U
                 CLRA
                 ROLB
                 INCB
                 ROLA
                 ASLB
                 ROLA
                 ASLB
                 ROLA
                 ASLB
                 ROLA
                 STD    <$02
                 LEAX   D,X
                 STX    5,U
                 INC    <20,U
                 RTS

; =====================================================================
; SUB_3827 (24 instructions)
; Calls: SUB_4459
; =====================================================================
SUB_3827         LDB    15,U
                 DECB
                 BNE    L_384D
                 CLRB
                 ASL    7,U
                 ROLB
                 ASL    8,U
                 ROLB
                 STB    <$02
                 LDB    #$03
                 ORB    <$03
                 JSR    >SUB_4459
                 RORB
                 LDA    7,U
                 ANDA   #$7F
                 BCC    L_3845
                 ORA    #$80
L_3845           ROR    8,U
                 RORB
                 RORA
                 STA    7,U
                 LDB    #$04
L_384D           STB    15,U
                 RTS

; =====================================================================
; SUB_3850 (12 instructions)
; =====================================================================
SUB_3850         LDA    <20,U
                 ROLA
                 ROLA
                 ROLA
                 ROLA
                 TFR    A,B
                 ROLA
                 ANDA   #$0F
                 ANDB   #$F0
                 SUBD   <18,U
                 TFR    D,X
                 RTS

; =====================================================================
; SUB_3864 (22 instructions)
; Uses:  MarioX ScreenNum MarioY
; =====================================================================
SUB_3864         LDD    #$0100
                 STB    <$05
                 LDB    >MarioX
                 CMPB   #$16
                 BCS    L_388E
                 DECA
                 INC    <$05
                 CMPB   #$EA
                 BCC    L_388E
                 DEC    <$05
                 LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 RORB
                 BCC    L_388E
                 LDB    >MarioY
                 CMPB   #$58
                 BCC    L_388E
                 LDB    >MarioX
                 CMPB   #$6C
                 BCC    L_388E
                 INCA
L_388E           STA    <$04
                 RTS

; =====================================================================
; SUB_3891 (44 instructions)
; Uses:  $6310 ScreenNum $6300
; =====================================================================
SUB_3891         LDY    #$6310
                 STY    <$0A
                 LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 LDX    #D_4F11
                 DECB
                 BEQ    L_38B0
                 LDX    #D_4F8A
                 DECB
                 BEQ    L_38B0
                 LDX    #D_5012
                 DECB
                 BEQ    L_38B0
                 LDX    #D_50B8
L_38B0           LDU    #$6300
L_38B3           LDB    ,X
                 BEQ    L_38C2
                 DECB
                 BEQ    L_38D6
                 CMPB   #$A9
                 BEQ    L_388E
                 LEAX   5,X
                 BRA    L_38B3
L_38C2           LEAX   1,X
                 LDB    ,X+
                 STB    ,U
                 LDB    ,X++
                 STB    <21,U
                 LDB    ,X+
                 STB    <42,U
                 LEAU   1,U
                 BRA    L_38B3
L_38D6           LEAX   1,X
                 LDB    ,X+
                 STY    <$04
                 LDY    <$0A
                 STB    ,Y
                 LDB    ,X++
                 STB    <21,Y
                 LDB    ,X+
                 STB    <42,Y
                 LEAY   1,Y
                 STY    <$0A
                 LDY    <$04
                 BRA    L_38B3

; =====================================================================
; SUB_38F6 (24 instructions)
; Uses:  $62B9 SndBoom $6348
; =====================================================================
SUB_38F6         LDB    5,U
                 CMPB   #$E8
                 BCC    L_38FD
L_38FC           RTS
L_38FD           LDB    3,U
                 CMPB   #$2A
                 BCC    L_38FC
                 CMPB   #$20
                 BCS    L_38FC
                 LDB    <21,U
                 BEQ    L_3912
                 LDB    #$03
                 STB    >$62B9
                 CLRB
L_3912           STB    ,U
                 STB    3,U
                 LDA    #$03
                 STA    >SndBoom
                 PULS   X
                 LDB    >$6348
                 LBNE   L_35C5
                 INCB
                 STB    >$6348
                 JMP    >L_35C5

; =====================================================================
; SUB_392B (26 instructions)
; Uses:  $65A0 $69B8
; Calls: RST_RetIfNotScreen SUB_3961 SUB_39C8
; =====================================================================
SUB_392B         LDB    #$02
                 JSR    <RST_RetIfNotScreen
                 BSR    SUB_3961
                 JSR    >SUB_39C8
                 LDU    #$65A0
                 LDA    #$06
                 STA    <$02
                 LDX    #$69B8
L_393E           LDB    ,U
                 BEQ    L_395D
                 LDB    3,U
                 ANDB   #$FE
                 STB    ,X+
                 LDB    7,U
                 STB    ,X++
                 LDB    5,U
                 STB    ,X+
L_3950           STB    <$01
                 TFR    Y,D
                 LEAU   D,U
                 LDB    <$01
                 DEC    <$02
                 BNE    L_393E
                 RTS
L_395D           LEAX   4,X
                 BRA    L_3950

; =====================================================================
; SUB_3961 (48 instructions)
; Uses:  $639B $639A $65A0 $62A3 $62A6
; Calls: UpdateRandom
; =====================================================================
SUB_3961         LDX    #$639B
                 LDB    ,X
                 BNE    L_39C5
                 LDB    >$639A
                 BEQ    L_39C7
                 LDA    #$06
                 STA    <$02
                 LDY    #$0010
                 LDU    #$65A0
L_3978           LDA    ,U
                 ANDA   #$01
                 BEQ    L_3986
                 LEAU   <16,U
                 DEC    <$02
                 BNE    L_3978
                 RTS
L_3986           JSR    <UpdateRandom
                 CMPB   #$60
                 LDA    #$7C
                 STA    5,U
                 BCS    L_3996
                 LDB    >$62A3
                 DECB
                 BNE    L_39AA
L_3996           LDA    #$CC
                 STA    5,U
                 LDB    >$62A6
                 ROLB
L_399E           LDA    #$07
                 STA    3,U
                 BCC    L_39B0
                 LDA    #$F8
                 STA    3,U
                 BRA    L_39B0
L_39AA           JSR    <UpdateRandom
                 CMPB   #$68
                 BRA    L_399E
L_39B0           LDD    #$014B
                 STA    ,U
                 STB    7,U
                 LDD    #$0803
                 STD    9,U
                 LDB    #$7C
                 STB    >$639B
                 CLRB
                 STB    >$639A
L_39C5           DEC    ,X
L_39C7           RTS

; =====================================================================
; SUB_39C8 (43 instructions)
; Uses:  $65A0 $63A6 $63A5 $63A4 $69B8
; =====================================================================
SUB_39C8         LDU    #$65A0
                 LDY    #$0010
                 LDA    #$06
                 STA    <$02
L_39D3           LDA    ,U
                 ANDA   #$01
                 BEQ    L_39F0
                 LDB    3,U
                 STB    <$06
                 ADDB   #$07
                 CMPB   #$0E
                 BCS    L_3A0C
                 LDB    5,U
                 CMPB   #$7C
                 BEQ    L_39F8
                 LDB    >$63A6
                 ADDB   <$06
                 STB    3,U
L_39F0           LEAU   <16,U
                 DEC    <$02
                 BNE    L_39D3
                 RTS
L_39F8           LDB    <$06
                 CMPB   #$80
                 BEQ    L_3A0C
                 LDB    >$63A5
                 BCC    L_3A06
                 LDB    >$63A4
L_3A06           ADDB   <$06
                 STB    3,U
                 BRA    L_39F0
L_3A0C           LDX    #$69B8
                 LDB    #$06
                 SUBB   <$02
L_3A13           BEQ    L_3A1A
                 LEAX   4,X
                 DECB
                 BRA    L_3A13
L_3A1A           CLRB
                 STB    ,U
                 STB    3,U
                 STB    ,X
                 BRA    L_39F0

; =====================================================================
; SUB_3A23 (7 instructions)
; Calls: RST_RetIfNotScreen SUB_3A32 SUB_3A62 SUB_3AAD SUB_3F2A
; =====================================================================
SUB_3A23         LDB    #$02
                 JSR    <RST_RetIfNotScreen
                 BSR    SUB_3A32
                 BSR    SUB_3A62
                 JSR    >SUB_3AAD
                 JSR    >SUB_3F2A
                 RTS

; =====================================================================
; SUB_3A32 (20 instructions)
; Uses:  FrameCounter $62A0 $62A1 $63A3 $69E4
; Calls: SUB_3B1C SUB_3B2A SUB_3ADB
; =====================================================================
SUB_3A32         LDB    >FrameCounter ; decremented every frame
                 RORB
                 BCS    L_3A46
                 LDX    #$62A0
                 DEC    ,X
                 BNE    L_3A46
                 LDA    #$80
                 STA    ,X+
                 JSR    >SUB_3B1C
L_3A46           LDX    #$62A1
                 JSR    >SUB_3B2A
                 STB    >$63A3
                 LDB    >FrameCounter ; decremented every frame
                 ANDB   #$1F
                 CMPB   #$01
                 BNE    L_3A61
                 LDY    #$69E4
                 EXG    Y,X
                 JSR    >SUB_3ADB
L_3A61           RTS

; =====================================================================
; SUB_3A62 (33 instructions)
; Uses:  $62A3 MarioY FrameCounter $63A5 $63A4 $69EC $69ED
; Calls: SUB_3B1C SUB_3B2A SUB_3ADB
; =====================================================================
SUB_3A62         LDX    #$62A3
                 LDB    >MarioY
                 CMPB   #$C0
                 BCS    L_3AA3
                 LDB    >FrameCounter ; decremented every frame
                 RORB
                 BCS    L_3A7D
                 DEC    ,-X
                 BNE    L_3A7D
                 LDA    #$C0
                 STA    ,X+
                 JSR    >SUB_3B1C
L_3A7D           LDX    #$62A3
                 JSR    >SUB_3B2A
                 STB    >$63A5
                 NEGB
                 STB    >$63A4
                 LDB    >FrameCounter ; decremented every frame
                 ANDB   #$1F
                 BNE    L_3AA2
                 LEAX   -1,X
                 LDY    #$69EC
                 EXG    Y,X
                 BSR    SUB_3ADB
                 ANDB   #$7F
                 LDX    #$69ED
                 STB    ,X
L_3AA2           RTS
L_3AA3           LDA    ,X
                 BMI    L_3A7D
                 LDA    #$FF
                 STA    ,X
                 BRA    L_3A7D

; =====================================================================
; SUB_3AAD (20 instructions)
; Uses:  FrameCounter $62A5 $62A6 $63A6 $69F4
; Calls: SUB_3B1C SUB_3B2A SUB_3ADB
; =====================================================================
SUB_3AAD         LDB    >FrameCounter ; decremented every frame
                 RORB
                 BCS    L_3AC0
                 LDX    #$62A5
                 DEC    ,X
                 BNE    L_3AC0
                 LDA    #$FF
                 STA    ,X+
                 BSR    SUB_3B1C
L_3AC0           LDX    #$62A6
                 JSR    >SUB_3B2A
                 STB    >$63A6
                 LDB    >FrameCounter ; decremented every frame
                 ANDB   #$1F
                 CMPB   #$02
                 BNE    L_3ADA
                 LDY    #$69F4
                 EXG    Y,X
                 BSR    SUB_3ADB
L_3ADA           RTS

; =====================================================================
; SUB_3ADB (36 instructions)
; =====================================================================
SUB_3ADB         LEAX   1,X
                 LDB    ,Y
                 ROLB
                 BCS    L_3AFF
                 LDB    ,X
                 INCB
                 CMPB   #$53
                 BNE    L_3AEB
                 LDB    #$50
L_3AEB           STB    ,X
                 TFR    X,D
                 ADDB   #$04
                 TFR    D,X
                 LDB    ,X
                 DECB
                 CMPB   #$CF
                 BNE    L_3AFC
                 LDB    #$D2
L_3AFC           STB    ,X
                 RTS
L_3AFF           LDB    ,X
                 DECB
                 CMPB   #$4F
                 BNE    L_3B08
                 LDB    #$52
L_3B08           STB    ,X
                 TFR    X,D
                 ADDB   #$04
                 TFR    D,X
                 LDB    ,X
                 INCB
                 CMPB   #$D3
                 BNE    L_3B19
                 LDB    #$D0
L_3B19           STB    ,X
                 RTS

; =====================================================================
; SUB_3B1C (8 instructions)
; =====================================================================
SUB_3B1C         LDA    ,X
                 BPL    L_3B25
                 LDA    #$02
                 STA    ,X
                 RTS
L_3B25           LDA    #$FE
                 STA    ,X
                 RTS

; =====================================================================
; SUB_3B2A (9 instructions)
; Uses:  FrameCounter
; =====================================================================
SUB_3B2A         LDB    >FrameCounter ; decremented every frame
                 ANDB   #$01
                 BEQ    L_3B3B
                 LDB    #$FF
                 LDA    ,X
                 BMI    L_3B39
                 LDB    #$01
L_3B39           STB    ,X
L_3B3B           RTS

; =====================================================================
; SUB_3B3C (33 instructions)
; Uses:  MarioY FrameCounter Level $6958 $6600
; Calls: RST_RetIfNotScreen SUB_3B82 SUB_3BCE SUB_3C0A
; =====================================================================
SUB_3B3C         LDB    #$04
                 JSR    <RST_RetIfNotScreen
                 LDB    >MarioY
                 CMPB   #$F0
                 BCC    L_3BB7
                 LDB    >FrameCounter ; decremented every frame
                 LDA    >Level ; level number
                 DECA
                 BNE    L_3B59
                 ANDB   #$03
                 CMPB   #$01
                 BEQ    L_3B5C
                 BCS    L_3B5F
                 RTS
L_3B59           RORB
                 BCS    L_3B5F
L_3B5C           BSR    SUB_3B82
                 RTS
L_3B5F           JSR    >SUB_3BCE
                 JSR    >SUB_3C0A
                 LDA    #$06
                 LDY    #$0010
                 LDX    #$6958
                 LDU    #$6600
L_3B71           LDB    3,U
                 STB    ,X
                 LEAX   3,X
                 LDB    5,U
                 STB    ,X+
                 LEAU   <16,U
                 DECA
                 BNE    L_3B71
                 RTS

; =====================================================================
; SUB_3B82 (36 instructions)
; Uses:  $6398 $6216 MarioX $6221 MarioY $694F MarioAlive
; =====================================================================
SUB_3B82         LDB    >$6398
                 BEQ    L_3BB6
                 LDB    >$6216
                 BNE    L_3BB6
                 LDB    >MarioX
                 CMPB   #$2C
                 BCS    L_3B9F
                 CMPB   #$43
                 BCS    L_3BA8
                 CMPB   #$6C
                 BCS    L_3B9F
                 CMPB   #$83
                 BCS    L_3BBF
L_3B9F           CLRB
                 STB    >$6398
                 INCB
                 STB    >$6221
                 RTS
L_3BA8           LDB    >MarioY
                 CMPB   #$71
                 BCS    L_3BB7
                 DECB
                 STB    >MarioY
                 STB    >$694F
L_3BB6           RTS
L_3BB7           CLRB
                 STB    >MarioAlive ; bit0 = Mario alive
                 STB    >$6398
                 RTS
L_3BBF           LDB    >MarioY
                 CMPB   #$E8
                 BCC    L_3BB7
                 INCB
                 STB    >MarioY
                 STB    >$694F
                 RTS

; =====================================================================
; SUB_3BCE (29 instructions)
; Uses:  $6600 $7704
; =====================================================================
SUB_3BCE         LDA    #$06
                 STA    <$02
                 LDY    #$0010
                 LDU    #$6600
L_3BD9           LDA    ,U
                 ANDA   #$01
                 BEQ    L_3BF5
                 LDA    13,U
                 ANDA   #$08
                 BEQ    L_3BFD
                 LDB    5,U
                 DECB
                 STB    5,U
                 CMPB   #$60
                 BNE    L_3BF5
                 LDD    #$7704
                 STA    3,U
                 STB    13,U
L_3BF5           LEAU   <16,U
                 DEC    <$02
                 BNE    L_3BD9
                 RTS
L_3BFD           LDB    5,U
                 INCB
                 STB    5,U
                 CMPB   #$F8
                 BNE    L_3BF5
                 CLR    ,U
                 BRA    L_3BF5

; =====================================================================
; SUB_3C0A (23 instructions)
; Uses:  $62A7 $6600
; =====================================================================
SUB_3C0A         LDX    #$62A7
                 LDB    ,X
                 BNE    L_3C38
                 LDA    #$06
                 STA    <$02
                 LDU    #$6600
L_3C18           LDA    ,U
                 ANDA   #$01
                 BEQ    L_3C26
                 LEAU   <16,U
                 DEC    <$02
                 BNE    L_3C18
                 RTS
L_3C26           LDD    #$0137
                 STA    ,U
                 STB    3,U
                 LDD    #$F808
                 STA    5,U
                 STB    13,U
                 LDA    #$34
                 STA    ,X
L_3C38           DEC    ,X
                 RTS

; =====================================================================
; SUB_3C3B (11 instructions)
; Uses:  MarioAlive MarioY
; Calls: SUB_3CAE
; =====================================================================
SUB_3C3B         LDX    #MarioAlive
                 STX    <$0A
                 LDB    >MarioY
                 STB    <$03
                 LDX    #$0407
                 BSR    SUB_3CAE
                 TSTB
                 BEQ    L_3C51
                 DECB
                 STB    >MarioAlive ; bit0 = Mario alive
L_3C51           RTS

; =====================================================================
; SUB_3C52 (27 instructions)
; Uses:  $6680 $6350 $63B9 $6354 $6353 $6351
; Calls: SUB_3CAE
; =====================================================================
SUB_3C52         LDA    #$02
                 STA    <$02
                 LDY    #$6680
L_3C5A           LDA    1,Y
                 ANDA   #$01
                 BNE    L_3C6F
                 LEAY   <16,Y
                 DEC    <$02
                 BNE    L_3C5A
                 STY    <$0A
                 LDY    #$0010
                 RTS
L_3C6F           LDA    5,Y
                 STA    <$03
                 LDX    9,Y
                 STY    <$0A
                 BSR    SUB_3CAE
                 TSTB
                 BEQ    L_3C90
                 STB    >$6350
                 LDB    >$63B9
                 SUBB   <$02
                 STB    >$6354
                 LDB    <$05
                 STB    >$6353
                 STU    >$6351
L_3C90           RTS

; =====================================================================
; CheckJumpOver (12 instructions)
; Uses:  MarioAlive MarioY InputState
; Calls: JumpOverCheck
; =====================================================================
CheckJumpOver    LDX    #MarioAlive
                 STX    <$0A
                 LDB    >MarioY
                 ADDB   #$0C
                 STB    <$03
                 LDX    #$0508
                 LDB    >InputState ; joystick+jump, bit7 = jump edge
                 ANDB   #$03
                 BEQ    L_3CAA
                 LDX    #$1308
L_3CAA           JSR    >JumpOverCheck
                 RTS

; =====================================================================
; SUB_3CAE (65 instructions)
; Uses:  ScreenNum $63B9 Barrels Fireballs $66A0 $65A0 $6500
; Calls: RST_JumpTable SUB_3D56
; =====================================================================
SUB_3CAE         LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 PSHS   X
                 JSR    <RST_JumpTable
TBL_StageObjects FDB    ColdStart
                 FDB    L_3CC1
                 FDB    L_3CF3
                 FDB    L_3D23
                 FDB    L_3D44
                 FDB    ColdStart
L_3CC1           PULS   X
                 LDD    #$200A
                 STB    <$02
                 STB    >$63B9
                 STA    <$05
                 LDU    #Barrels
                 JSR    >SUB_3D56
                 LDD    #$2005
                 STB    <$02
                 STB    >$63B9
                 STA    <$05
                 LDU    #Fireballs
                 JSR    >SUB_3D56
                 LDD    #$0001
                 STB    <$02
                 STB    >$63B9
                 STA    <$05
                 LDU    #$66A0
                 BSR    SUB_3D56
                 RTS
L_3CF3           PULS   X
                 LDD    #$2005
                 STB    <$02
                 STB    >$63B9
                 STA    <$05
                 LDU    #Fireballs
                 BSR    SUB_3D56
                 LDD    #$1006
                 STB    <$02
                 STB    >$63B9
                 STA    <$05
                 LDU    #$65A0
                 BSR    SUB_3D56
                 LDD    #$0001
                 STB    <$02
                 STB    >$63B9
                 STA    <$05
                 LDU    #$66A0
                 BSR    SUB_3D56
                 RTS
L_3D23           PULS   X
                 LDD    #$2005
                 STB    <$02
                 STB    >$63B9
                 STA    <$05
                 LDU    #Fireballs
                 BSR    SUB_3D56
                 LDD    #$100A
                 STB    <$02
                 STB    >$63B9
                 STA    <$05
                 LDU    #$6500
                 BSR    SUB_3D56
                 RTS
L_3D44           PULS   X
                 LDD    #$2007
                 STB    <$02
                 STB    >$63B9
                 STA    <$05
                 LDU    #Fireballs
                 BSR    SUB_3D56
                 RTS

; =====================================================================
; SUB_3D56 (42 instructions)
; =====================================================================
SUB_3D56         PSHS   U
                 STX    <$06
                 LDX    <$0A
L_3D5C           LDA    ,U
                 ANDA   #$01
                 BEQ    L_3D8F
                 LDB    <$03
                 SUBB   5,U
                 BCC    L_3D69
                 NEGB
L_3D69           INCB
                 SUBB   <$07
                 BCS    L_3D72
                 SUBB   10,U
                 BCC    L_3D8F
L_3D72           LDB    3,X
                 SUBB   3,U
                 BCC    L_3D79
                 NEGB
L_3D79           SUBB   <$06
                 BCS    L_3D81
                 SUBB   9,U
                 BCC    L_3D8F
L_3D81           CLRA
                 LDB    <$05
                 TFR    D,Y
                 LDB    #$01
                 PULS   U
                 LEAS   2,S
                 LDX    <$06
                 RTS
L_3D8F           LDA    <$05
                 LEAU   A,U
                 DEC    <$02
                 BNE    L_3D5C
                 CLRA
                 LDB    <$05
                 TFR    D,Y
                 CLRB
                 PULS   U
                 LDX    <$06
                 RTS

; =====================================================================
; SUB_3DA2 (19 instructions)
; Uses:  $6218 SndFx5
; Calls: RST_RetIfNotScreen SUB_3DC5
; =====================================================================
SUB_3DA2         LDB    #$0B
                 JSR    <RST_RetIfNotScreen
                 BSR    SUB_3DC5
                 STB    >$6218
                 TFR    B,A
                 ASRA
                 RORB
                 ASRA
                 RORB
                 STB    >SndFx5
                 LDB    <$02
                 BEQ    L_3DC4
                 CMPB   #$01
                 BEQ    L_3DC1
                 LDA    #$01
                 STA    1,U
                 RTS
L_3DC1           STB    <17,U
L_3DC4           RTS

; =====================================================================
; SUB_3DC5 (11 instructions)
; Uses:  MarioAlive MarioY $6680
; Calls: SUB_3D56
; =====================================================================
SUB_3DC5         LDX    #MarioAlive
                 STX    <$0A
                 LDB    >MarioY
                 STB    <$03
                 LDX    #$0408
                 LDD    #$0210
                 STA    <$02
                 STB    <$05
                 LDU    #$6680
                 JSR    >SUB_3D56
                 RTS

; =====================================================================
; SUB_3DE0 (19 instructions)
; Uses:  $63C8
; Calls: SUB_443F
; =====================================================================
SUB_3DE0         LDX    >$63C8
                 TFR    X,D
                 ADDB   #$0E
                 TFR    D,X
                 LDA    ,X+
                 LDB    ,X
                 ADDB   #$0C
                 TFR    D,X
                 JSR    >SUB_443F
                 LDB    ,X
                 CMPB   #$B0
                 BCS    L_3E02
                 ANDB   #$0F
                 CMPB   #$08
                 BCC    L_3E02
                 CLRB
                 RTS
L_3E02           LDB    #$01
                 RTS

; =====================================================================
; SUB_3E05 (56 instructions)
; Uses:  MarioAlive MarioY $620C $6398 MarioX $6210 $694C
; Calls: RST_RetIfNotScreen SUB_3E7C
; =====================================================================
SUB_3E05         LDB    #$04
                 JSR    <RST_RetIfNotScreen
                 LDX    #MarioAlive
                 STX    <$0A
                 LDB    >MarioY
                 STB    <$03
                 LDX    #$0408
                 JSR    >SUB_3E7C
                 TSTB
                 BEQ    L_3E79
                 LDB    #$06
                 SUBB   <$02
L_3E20           BEQ    L_3E28
                 LEAU   <16,U
                 DECB
                 BRA    L_3E20
L_3E28           LDA    5,U
                 SUBA   #$04
                 TFR    D,Y
                 STA    <$04
                 LDB    >$620C
                 ADDB   #$05
                 CMPB   <$04
                 BCC    L_3E4A
                 LDB    <$04
                 SUBB   #$08
                 STB    >MarioY
                 LDB    #$01
                 STB    <$02
                 STB    >$6398
                 LEAS   2,S
                 RTS
L_3E4A           LDB    >$620C
                 SUBB   #$0E
                 CMPB   <$04
                 BCC    L_3E74
                 LDB    >MarioX
                 LDA    >$6210
                 BEQ    L_3E61
                 ORB    #$07
                 SUBB   #$04
                 BRA    L_3E67
L_3E61           SUBB   #$08
                 ORB    #$07
                 ADDB   #$04
L_3E67           STB    >MarioX
                 STB    >$694C
                 LDB    #$01
                 CLR    <$02
                 LEAS   2,S
                 RTS
L_3E74           CLRB
                 STB    >MarioAlive ; bit0 = Mario alive
                 RTS
L_3E79           STB    <$02
                 RTS

; =====================================================================
; SUB_3E7C (6 instructions)
; Uses:  $6600
; Calls: SUB_3D56
; =====================================================================
SUB_3E7C         LDD    #$0610
                 STA    <$02
                 STB    <$05
                 LDU    #$6600
                 JSR    >SUB_3D56
                 RTS

; =====================================================================
; SUB_3E8A (43 instructions)
; Calls: SUB_443F
; =====================================================================
SUB_3E8A         LDA    3,U
                 LDB    5,U
                 ADDB   #$04
                 TFR    D,X
                 PSHS   X
                 JSR    >SUB_443F
                 PULS   Y
                 LDB    ,X
                 CMPB   #$B0
                 BCS    L_3ED4
                 ANDB   #$0F
                 CMPB   #$08
                 BCC    L_3ED4
                 LDB    ,X
                 CMPB   #$C0
                 BEQ    L_3ED4
                 BCS    L_3EBE
                 CMPB   #$D0
                 BCS    L_3EC2
                 CMPB   #$E0
                 BCS    L_3EB9
                 CMPB   #$F0
                 BCS    L_3EC2
L_3EB9           ANDB   #$0F
                 DECB
                 BRA    L_3EC6
L_3EBE           LDB    #$FF
                 BRA    L_3EC6
L_3EC2           ANDB   #$0F
                 SUBB   #$09
L_3EC6           STB    <$03
                 TFR    Y,D
                 STB    <$05
                 ANDB   #$F8
                 ADDB   <$03
                 CMPB   <$05
                 BCS    L_3ED6
L_3ED4           CLRB
                 RTS
L_3ED6           SUBB   #$04
                 STB    5,U
                 LDB    #$01
                 RTS

; =====================================================================
; SUB_3EDD (36 instructions)
; Uses:  $6215 $6216 $6398 MarioX MarioY $6221
; Calls: SUB_443F
; =====================================================================
SUB_3EDD         LDB    >$6215
                 BNE    L_3F29
                 LDB    >$6216
                 BNE    L_3F29
                 LDB    >$6398
                 CMPB   #$01
                 BEQ    L_3F29
                 LDA    >MarioX
                 SUBA   #$03
                 LDB    >MarioY
                 ADDB   #$0C
                 TFR    D,X
                 PSHS   X
                 JSR    >SUB_443F
                 PULS   Y
                 LDB    ,X
                 CMPB   #$B0
                 BCS    L_3F0E
                 ANDB   #$0F
                 CMPB   #$08
                 BCC    L_3F0E
                 RTS
L_3F0E           TFR    Y,D
                 ANDA   #$07
                 BEQ    L_3F24
                 LEAX   <-32,X
                 LDB    ,X
                 CMPB   #$B0
                 BCS    L_3F24
                 ANDB   #$0F
                 CMPB   #$08
                 BCC    L_3F24
                 RTS
L_3F24           LDB    #$01
                 STB    >$6221
L_3F29           RTS

; =====================================================================
; SUB_3F2A (36 instructions)
; Uses:  MarioX MarioY $63A3 $63A6 $63A5 $63A4 $694C
; Calls: SUB_3864
; =====================================================================
SUB_3F2A         LDB    >MarioX
                 STB    <$02
                 LDB    >MarioY
                 CMPB   #$50
                 BEQ    L_3F3F
                 CMPB   #$78
                 BEQ    L_3F49
                 CMPB   #$C8
                 BEQ    L_3F44
                 RTS
L_3F3F           LDB    >$63A3
                 BRA    L_3F55
L_3F44           LDB    >$63A6
                 BRA    L_3F55
L_3F49           LDB    <$02
                 CMPB   #$80
                 LDB    >$63A5
                 BCC    L_3F55
                 LDB    >$63A4
L_3F55           ADDB   <$02
                 STB    >MarioX
                 STB    >$694C
                 JSR    >SUB_3864
                 LDX    #MarioX
                 DEC    <$05
                 BEQ    L_3F6F
                 DEC    <$04
                 BEQ    L_3F75
                 LDY    <$04
                 RTS
L_3F6F           DEC    ,X
                 LDY    <$04
                 RTS
L_3F75           INC    ,X
                 LDY    <$04
                 RTS

; =====================================================================
; SUB_3F7B (6 instructions)
; Uses:  MarioAlive
; Calls: SUB_3F87 SUB_3E05
; =====================================================================
SUB_3F7B         LDU    #MarioAlive
                 BSR    SUB_3F87
                 JSR    >SUB_3E05
                 CLRB
                 STB    <$02
                 RTS

; =====================================================================
; SUB_3F87 (52 instructions)
; Uses:  ScreenNum MarioX MarioY $6210 $694C
; Calls: SUB_3FF4
; =====================================================================
SUB_3F87         LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 DECB
                 BNE    L_3FB1
                 LDA    >MarioX
                 LDB    >MarioY
                 ADDB   #$07
                 TFR    D,X
                 BSR    SUB_3FF4
                 TSTB
                 BEQ    L_3FAF
                 TFR    Y,D
                 SUBB   <$03
                 CMPB   #$04
                 BCC    L_3FD0
                 LDB    <$03
                 SUBB   #$07
                 STB    >MarioY
                 LDB    #$01
                 STB    <$02
L_3FAF           PULS   X,PC
L_3FB1           LDA    >MarioX
                 SUBA   #$03
                 LDB    >MarioY
                 ADDB   #$07
                 TFR    D,X
                 BSR    SUB_3FF4
                 CMPB   #$02
                 BEQ    L_3FD5
                 TFR    Y,D
                 ADDA   #$07
                 TFR    D,X
                 BSR    SUB_3FF4
                 TSTB
                 BEQ    L_3FF3
                 BRA    L_3FD5
L_3FD0           CLRB
                 STB    <$02
                 PULS   X,PC
L_3FD5           LDB    >MarioX
                 LDA    >$6210
                 BEQ    L_3FE3
                 ORB    #$07
                 SUBB   #$04
                 BRA    L_3FE9
L_3FE3           SUBB   #$08
                 ORB    #$07
                 ADDB   #$04
L_3FE9           STB    >MarioX
                 STB    >$694C
                 LDB    #$01
                 PULS   X,PC
L_3FF3           RTS

; =====================================================================
; SUB_3FF4 (58 instructions)
; Uses:  $620C MarioY
; Calls: SUB_443F
; =====================================================================
SUB_3FF4         PSHS   X
                 JSR    >SUB_443F
                 PULS   Y
                 LDB    ,X
                 CMPB   #$B0
                 BCS    L_4034
                 ANDB   #$0F
                 CMPB   #$08
                 BCC    L_4034
                 LDB    ,X
                 CMPB   #$C0
                 BEQ    L_4034
                 BCS    L_4038
                 CMPB   #$D0
                 BCS    L_4020
                 CMPB   #$E0
                 BCS    L_401B
                 CMPB   #$F0
                 BCS    L_4020
L_401B           ANDB   #$0F
                 DECB
                 BRA    L_4024
L_4020           ANDB   #$0F
                 SUBB   #$09
L_4024           STB    <$03
                 TFR    Y,D
                 STB    <$05
                 ANDB   #$F8
                 ADDB   <$03
                 STB    <$03
                 CMPB   <$05
                 BCS    L_4041
L_4034           CLRB
                 STB    <$02
                 RTS
L_4038           TFR    Y,D
                 STB    <$05
                 ANDB   #$F8
                 DECB
                 STB    <$03
L_4041           LDB    >$620C
                 SUBB   5,U
                 ADDB   <$05
                 CMPB   <$03
                 BEQ    L_404E
                 BCC    L_4057
L_404E           LDB    <$03
                 SUBB   #$07
                 STB    >MarioY
                 BRA    L_405C
L_4057           LDB    #$02
                 CLR    <$02
                 RTS
L_405C           LDB    #$01
                 STB    <$02
                 LEAS   2,S
                 PULS   X
                 RTS

; =====================================================================
; SUB_4065 (68 instructions)
; Uses:  $6393 $62B1 $62B0 $6382 Difficulty FrameCounter RandTimer $638F $6392 $62B2 Fireballs
; Calls: RST_RetIfNotScreen RST_RetIfMarioDead UpdateRandom
; =====================================================================
SUB_4065         LDB    #$01
                 JSR    <RST_RetIfNotScreen
                 JSR    <RST_RetIfMarioDead
                 LDB    >$6393
                 RORB
                 BCS    L_409A
                 LDB    >$62B1
                 BEQ    L_409A
                 STB    <$03
                 LDB    >$62B0
                 SUBB   #$02
                 CMPB   <$03
                 BCS    L_40E5
                 LDB    >$6382
                 ANDB   #$02
                 BNE    L_40EF
                 LDB    >Difficulty
                 STB    <$02
                 LDB    >FrameCounter ; decremented every frame
                 ANDB   #$1F
L_4092           CMPB   <$02
                 BEQ    L_409B
                 DEC    <$02
                 BNE    L_4092
L_409A           RTS
L_409B           LDB    >$62B0
                 LSRB
                 CMPB   <$03
                 BCS    L_40A9
                 LDB    >RandTimer
                 RORB
                 BCC    L_409A
L_40A9           JSR    <UpdateRandom
                 ANDB   #$0F
                 BNE    L_40EF
L_40AF           LDB    #$01
L_40B1           STB    >$6382
                 INCB
L_40B5           STB    >$638F
                 LDB    #$01
                 STB    >$6392
                 LDB    >$62B2
                 CMPB   <$03
                 BNE    L_409A
                 SUBB   #$08
                 STB    >$62B2
                 LDX    #Fireballs
                 LDA    #$05
                 STA    <$02
L_40D0           LDB    ,X
                 BEQ    L_40DC
                 LEAX   <32,X
                 DEC    <$02
                 BNE    L_40D0
                 RTS
L_40DC           LDB    >$6382
                 ORB    #$80
                 STB    >$6382
                 RTS
L_40E5           ADDB   #$02
                 CMPB   <$03
                 BEQ    L_40AF
                 LDB    #$02
                 BRA    L_40B1
L_40EF           CLRB
                 STB    >$6382
                 LDB    #$03
                 BRA    L_40B5

; =====================================================================
; SUB_40F7 (150 instructions)
; Uses:  $6393 $6392 Barrels $62AA $6980 $62AC $62B1 $6386 $69A8 $6382 $62AF $638F $62A8 $690B
; Calls: RST_RetIfNotScreen RST_RetIfMarioDead AddTask RST_CopySprites RST_AddToObjects
; =====================================================================
SUB_40F7         LDB    #$01
                 JSR    <RST_RetIfNotScreen
                 JSR    <RST_RetIfMarioDead
                 LDB    >$6393
                 RORB
                 BCS    L_4179
                 LDB    >$6392
                 RORB
                 BCC    L_4123
                 LDU    #Barrels
                 LDY    #$0020
                 LDA    #$0A
                 STA    <$02
L_4114           LDB    ,U
                 RORB
                 BCS    L_411C
                 RORB
                 BCC    L_4124
L_411C           LEAU   <32,U
                 DEC    <$02
                 BNE    L_4114
L_4123           RTS
L_4124           STU    >$62AA
                 LDA    #$02
                 STA    ,U
                 LDB    #$0A
                 SUBB   <$02
                 ASLB
                 ASLB
                 LDX    #$6980
                 ABX
                 STX    >$62AC
                 LDB    #$01
                 STB    >$6393
                 LDY    #$0501 ; queue BonusTimer(1)
                 JSR    >AddTask
                 LDX    #$62B1
                 DEC    ,X
                 BNE    L_4150
                 LDB    #$01
                 STB    >$6386
L_4150           LDB    ,X
                 CMPB   #$04
                 BCC    L_415E
                 LDX    #$69A8
                 ASLB
                 ASLB
                 ABX
                 CLR    ,X
L_415E           LDD    #$150B
                 STD    7,U
                 CLR    <21,U
                 LDB    >$6382
                 ROLB
                 BCC    L_4179
                 LDA    #$19
                 STA    7,U
                 LDA    #$0C
                 STA    8,U
                 LDA    #$01
                 STA    <21,U
L_4179           LDX    #$62AF
                 DEC    ,X
                 BNE    L_4123
                 LDA    #$18
                 STA    ,X
                 LDB    >$638F
                 BEQ    L_41B6
                 STB    <$03
                 LDX    #D_4D1A
                 LDB    >$6382
                 RORB
                 BCS    L_4196
                 DEC    <$03
L_4196           LDB    <$03
                 ASLB
                 ASLB
                 ASLB
                 STB    <$03
                 ASLB
                 ASLB
                 ADDB   <$03
                 ABX
                 JSR    <RST_CopySprites
                 LDX    #$638F
                 DEC    ,X
                 BNE    L_41B6
                 LDB    #$01
                 STB    >$62AF
                 LDB    >$6382
                 RORB
                 BCS    L_41E6
L_41B6           LDX    >$62A8
L_41B9           LDB    ,X
                 LDU    >$62AA
                 LDY    >$62AC
                 CMPB   #$7F
                 BEQ    L_41EE
                 STB    <$03
                 ANDB   #$7F
                 STB    ,Y+
                 LDB    7,U
                 LDA    <$03
                 BPL    L_41D4
                 EORB   #$03
L_41D4           STB    ,Y+
                 STB    7,U
                 LDB    8,U
                 STB    ,Y+
                 LEAX   1,X
                 LDB    ,X+
                 STB    ,Y
                 STX    >$62A8
                 RTS
L_41E6           LDX    #D_4DB4
                 STX    >$62A8
                 BRA    L_41B9
L_41EE           LDX    #D_4DAB
                 STX    >$62A8
                 LDA    #$01
                 STA    1,U
                 LDB    >$6382
                 RORB
                 BCS    L_4204
                 CLR    1,U
                 LDA    #$02
                 STA    2,U
L_4204           LDA    #$01
                 STA    ,U
                 STA    15,U
                 CLRB
                 STB    <16,U
                 STB    <17,U
                 STB    <18,U
                 STB    <19,U
                 STB    <20,U
                 STB    >$6393
                 STB    >$6392
                 LDB    ,Y
                 STB    3,U
                 LEAY   3,Y
                 LDB    ,Y
                 STB    5,U
                 LDX    #D_4DB7
                 JSR    <RST_CopySprites
                 LDX    #$690B
                 LDA    #$FC
                 STA    <$03
                 JSR    <RST_AddToObjects
                 RTS

; =====================================================================
; SUB_4239 (25 instructions)
; Uses:  Difficulty ScreenNum FrameCounter $63A0 $639A
; Calls: RST_RetIfNotScreen RST_RetIfMarioDead
; =====================================================================
SUB_4239         LDB    #$0A
                 JSR    <RST_RetIfNotScreen
                 JSR    <RST_RetIfMarioDead
                 LDB    >Difficulty
                 INCB
                 LSRB
                 STB    <$02
                 LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 CMPB   #$02
                 BNE    L_424F
                 INC    <$02
L_424F           LDB    #$FE
                 ORCC   #$01
L_4253           RORB
                 CLRA
                 DEC    <$02
                 BNE    L_4253
                 STB    <$02
                 LDB    >FrameCounter ; decremented every frame
                 ANDB   <$02
                 BNE    L_426A
                 LDB    #$01
                 STB    >$63A0
                 STB    >$639A
L_426A           RTS

; =====================================================================
; SUB_426B (87 instructions)
; Uses:  $6980 $6500 FrameCounter SndCoin SndFx4 $6396
; Calls: RST_RetIfNotScreen RST_RetIfMarioDead UpdateRandom
; =====================================================================
SUB_426B         LDB    #$04
                 JSR    <RST_RetIfNotScreen
                 JSR    <RST_RetIfMarioDead
                 LDY    #$6980
                 LDU    #$6500
                 LDA    #$0A
                 STA    <$02
L_427C           LDB    ,U
                 RORB
                 BCC    L_42FD
                 LDB    >FrameCounter ; decremented every frame
                 ANDB   #$0F
                 BNE    L_428E
                 LDB    1,Y
                 EORB   #$07
                 STB    1,Y
L_428E           LDB    13,U
                 CMPB   #$04
                 BEQ    L_42E3
                 INC    3,U
                 INC    3,U
                 LDB    14,U
                 LDA    15,U
                 TFR    D,X
                 LDB    ,X
                 STB    <$03
                 CMPB   #$7F
                 BEQ    L_42F3
                 LEAX   1,X
                 ADDB   5,U
                 STB    5,U
L_42AC           TFR    X,D
                 STB    14,U
                 STA    15,U
                 LDB    3,U
                 CMPB   #$B7
                 BCS    L_42CA
                 LDB    <$03
                 CMPB   #$7F
                 BNE    L_42CA
                 LDA    #$04
                 STA    13,U
                 CLR    >SndCoin
                 LDB    #$03
                 STB    >SndFx4
L_42CA           LDB    3,U
                 STB    ,Y
                 LDB    5,U
                 STB    3,Y
L_42D2           LEAU   <16,U
                 LEAY   4,Y
                 DEC    <$02
                 BNE    L_427C
                 STY    <$0A
                 LDY    #$0004
                 RTS
L_42E3           LDB    #$03
                 ADDB   5,U
                 STB    5,U
                 CMPB   #$F8
                 BCS    L_42CA
                 CLR    3,U
                 CLR    ,U
                 BRA    L_42CA
L_42F3           LDX    #D_4D92
                 LDB    #$03
                 STB    >SndCoin
                 BRA    L_42AC
L_42FD           LDB    >$6396
                 RORB
                 BCC    L_42D2
                 CLRB
                 STB    >$6396
                 LDD    #$5001
                 STA    5,U
                 STB    13,U
                 JSR    <UpdateRandom
                 ANDB   #$0F
                 ADDB   #$F8
                 STB    3,U
                 LDA    #$01
                 STA    ,U
                 LDX    #D_4D92
                 TFR    X,D
                 STB    14,U
                 STA    15,U
                 BRA    L_42D2

; =====================================================================
; SUB_4325 (106 instructions)
; Uses:  $6A18 $6680 $6A1C $6690 $6217 $6218 MusicReq $6207 $6394 $694D $6395 MarioX $6389 MarioY ...
; Calls: RST_RetIfNotScreen RST_RetIfMarioDead
; =====================================================================
SUB_4325         LDB    #$0B
                 JSR    <RST_RetIfNotScreen
                 JSR    <RST_RetIfMarioDead
                 LDY    #$6A18
                 LDU    #$6680
                 LDB    1,U
                 RORB
                 BCS    L_433E
                 LDY    #$6A1C
                 LDU    #$6690
L_433E           LDD    #$00F0
                 STD    14,U
                 LDB    >$6217
                 RORB
                 LBCC   L_43E3
                 CLRB
                 STB    >$6218
                 LDX    #MusicReq
                 LDA    #$04
                 STA    ,X
                 LDD    #$0603
                 STD    9,U
                 LDA    #$1E
                 STA    <$02
                 LDB    >$6207
                 ASLB
                 BCC    L_436D
                 ORB    #$80
                 LDA    <$02
                 ORA    #$80
                 STA    <$02
L_436D           ORB    #$08
                 STB    <$03
                 LDB    >$6394
                 ANDB   #$08
                 BEQ    L_4392
                 LDD    <$02
                 ORA    #$01
                 ORB    #$01
                 STD    <$02
                 LDD    #$0506
                 STD    9,U
                 LDD    #$F000
                 STD    14,U
                 LDA    <$03
                 BPL    L_4392
                 LDA    #$10
                 STA    14,U
L_4392           LDB    <$03
                 STB    >$694D
                 CLR    <$03
                 LDX    #$6394
                 INC    ,X
                 BNE    L_4401
                 LDX    #$6395
                 INC    ,X
                 LDB    ,X
                 CMPB   #$02
                 BNE    L_4406
                 CLRB
                 STB    >$6395
                 STB    >$6217
                 STB    1,U
                 LDB    >MarioX
                 NEGB
                 STB    14,U
                 LDB    >$6207
                 STB    >$694D
                 CLR    ,U
                 LDB    >$6389
                 STB    >MusicReq ; music number request
L_43C8           EXG    Y,X
                 LDB    >MarioX
                 ADDB   14,U
                 STB    ,X+
                 STB    3,U
                 LDA    <$02
                 ADDA   <$03
                 STA    ,X++
                 LDB    >MarioY
                 ADDB   15,U
                 STB    ,X
                 STB    5,U
L_43E2           RTS
L_43E3           LDB    >$6218
                 RORB
                 BCC    L_43E2
                 LDD    #$0603
                 STD    9,U
                 LDB    >$6207
                 ROLB
                 LDB    #$3C
                 RORB
                 STB    <$02
                 CLR    <$03
                 LDB    >MusicReq ; music number request
                 STB    >$6389
                 BRA    L_43C8
L_4401           LDB    >$6395
                 BEQ    L_43C8
L_4406           LDB    >FrameCounter ; decremented every frame
                 ANDB   #$08
                 BEQ    L_43C8
                 LDA    #$FE
                 STA    <$03
                 BRA    L_43C8

; =====================================================================
; SUB_4413 (18 instructions)
; Uses:  $62B4 $62B9 $6396 $62B3 $62B1 $6386
; Calls: RST_RetIfNotScreen AddTask
; =====================================================================
SUB_4413         LDB    #$0E
                 JSR    <RST_RetIfNotScreen
                 LDX    #$62B4
                 DEC    ,X
                 BNE    L_443E
                 LDB    #$03
                 STB    >$62B9
                 STB    >$6396
                 LDY    #$0501 ; queue BonusTimer(1)
                 JSR    >AddTask
                 LDB    >$62B3
                 STB    ,X
                 LDX    #$62B1
                 DEC    ,X
                 BNE    L_443E
                 LDB    #$01
                 STB    >$6386
L_443E           RTS

; =====================================================================
; SUB_443F (18 instructions)
; =====================================================================
SUB_443F         TFR    X,D
                 LSRB
                 LSRB
                 LSRB
                 COMA
                 ANDA   #$F8
                 STA    <$05
                 CLRA
                 TFR    D,X
                 LDB    <$05
                 ROLB
                 ROLA
                 ROLB
                 ROLA
                 ADDA   #$74
                 TFR    D,Y
                 LEAX   D,X
                 RTS

; =====================================================================
; SUB_4459 (51 instructions)
; =====================================================================
SUB_4459         STB    <$04
                 RORB
                 BCS    L_4475
                 LDA    #$93
                 STA    <$03
                 RORB
                 RORB
                 BCC    L_446A
                 LDA    #$6C
                 STA    <$03
L_446A           ROLB
                 BCS    L_4489
                 LDB    <$03
                 ANDB   #$F0
                 STB    <$03
                 BRA    L_4489
L_4475           LDA    #$B4
                 STA    <$03
                 RORB
                 RORB
                 BCC    L_4481
                 LDA    #$1E
                 STA    <$03
L_4481           LDA    <$02
                 ANDA   #$04
                 BEQ    L_4489
                 DEC    <$02
L_4489           LDB    <$03
                 TFR    B,A
                 RORA
                 RORB
                 RORA
                 RORB
                 STB    <$03
                 ANDB   #$03
                 CMPB   <$02
                 BNE    L_4489
                 LDB    <$03
                 RORB
                 RORB
                 ANDB   #$03
                 CMPB   #$03
                 BNE    L_44AC
                 LDA    <$04
                 ANDA   #$FB
                 DECA
                 BNE    L_44AD
                 LDB    #$04
L_44AC           RTS
L_44AD           LDB    #$03
                 RTS

; =====================================================================
; SUB_44B0 (12 instructions)
; Uses:  $638E $7600 $75C0
; Calls: SUB_44CC
; =====================================================================
SUB_44B0         LDY    #$FFE0
                 LDB    >$638E
                 CLRA
                 STD    <$02
                 LDX    #$7600
                 BSR    SUB_44CC
                 LDB    <$03
                 LDX    #$75C0
                 BSR    SUB_44CC
                 LDX    #$638E
                 DEC    ,X
                 RTS

; =====================================================================
; SUB_44CC (8 instructions)
; Uses:  $63C0
; Calls: RST_WaitTimer
; =====================================================================
SUB_44CC         LEAX   D,X
                 LDB    ,X
                 STB    <-32,X
                 RTS
L_44D4           JSR    <RST_WaitTimer
                 LDX    >$63C0
                 INC    ,X
                 RTS

; =====================================================================
; SUB_44DC (21 instructions)
; Uses:  $62AF $690B $6909 $691D $692D
; Calls: RST_AddToObjects SUB_450A UpdateRandom
; =====================================================================
SUB_44DC         LDX    #$62AF
                 INC    ,X
                 LDB    ,X
                 ANDB   #$07
                 BNE    L_4509
                 LDX    #$690B
                 LDA    #$FC
                 STA    <$03
                 JSR    <RST_AddToObjects
                 LDA    #$81
                 STA    <$03
                 LDX    #$6909
                 BSR    SUB_450A
                 LDX    #$691D
                 BSR    SUB_450A
                 JSR    <UpdateRandom
                 ANDB   #$80
                 LDX    #$692D
                 EORB   ,X
                 STB    ,X
L_4509           RTS

; =====================================================================
; SUB_450A (12 instructions)
; =====================================================================
SUB_450A         LDA    #$02
                 STA    <$02
L_450E           LDB    <$03
                 EORB   ,X
                 STB    ,X
                 STB    <$01
                 TFR    Y,D
                 LEAX   D,X
                 LDB    <$01
                 DEC    <$02
                 BNE    L_450E
                 RTS

; =====================================================================
; AddTask: Y = task number : parameter.  Writes it into the task
; ring buffer $60C0-$60FF at $60B0 when the slot is free ($FF).
; =====================================================================
AddTask          PSHS   X
                 LDA    #$60
                 LDB    >TaskWrPtr ; task queue write ptr (low byte)
                 TFR    D,X
                 LDA    ,X
                 BPL    L_453C
                 STY    ,X++
                 TFR    X,D
                 CMPB   #$C0
                 BCC    L_4539
                 LDB    #$C0
L_4539           STB    >TaskWrPtr ; task queue write ptr (low byte)
L_453C           PULS   X,PC

; =====================================================================
; SUB_453E (12 instructions)
; Uses:  $6950 $6980 $69B8 $6A0C
; Calls: SUB_4564
; =====================================================================
SUB_453E         LDX    #$6950
                 LDA    #$02
                 BSR    SUB_4564
                 LDX    #$6980
                 LDA    #$0A
                 BSR    SUB_4564
                 LDX    #$69B8
                 LDA    #$0B
                 BSR    SUB_4564
                 LDX    #$6A0C
                 LDA    #$05
                 BRA    SUB_4564

; =====================================================================
; SUB_455A (4 instructions)
; Uses:  $694C $6958
; =====================================================================
SUB_455A         LDX    #$694C
                 CLR    ,X
                 LDX    #$6958
                 LDA    #$06

; =====================================================================
; SUB_4564 (5 instructions)
; =====================================================================
SUB_4564         CLR    ,X
                 LEAX   4,X
                 DECA
                 BNE    SUB_4564
                 RTS

; =====================================================================
; SUB_456C (5 instructions)
; Calls: SUB_4577 SUB_45BE SUB_4640 SUB_4921
; =====================================================================
SUB_456C         BSR    SUB_4577
                 BSR    SUB_45BE
                 JSR    >SUB_4640
                 JSR    >SUB_4921
                 RTS

; =====================================================================
; SUB_4577 (29 instructions)
; Uses:  Difficulty FrameCounter
; Calls: RST_JumpTable
; =====================================================================
SUB_4577         LDB    >Difficulty
                 CMPB   #$06
                 BCS    L_4580
                 LDB    #$05
L_4580           JSR    <RST_JumpTable
TBL_4582         FDB    L_458E
                 FDB    L_458E
                 FDB    L_459A
                 FDB    L_45A6
                 FDB    L_45A6
                 FDB    L_45B2
L_458E           LDB    >FrameCounter ; decremented every frame
                 ANDB   #$01
                 CMPB   #$01
                 BEQ    L_4599
                 LEAS   2,S
L_4599           RTS
L_459A           LDB    >FrameCounter ; decremented every frame
                 ANDB   #$07
                 CMPB   #$05
                 BMI    L_45A5
                 LEAS   2,S
L_45A5           RTS
L_45A6           LDB    >FrameCounter ; decremented every frame
                 ANDB   #$03
                 CMPB   #$03
                 BMI    L_45B1
                 LEAS   2,S
L_45B1           RTS
L_45B2           LDB    >FrameCounter ; decremented every frame
                 ANDB   #$07
                 CMPB   #$07
                 BMI    L_45BD
                 LEAS   2,S
L_45BD           RTS

; =====================================================================
; SUB_45BE (59 instructions)
; Uses:  Fireballs $63A1 $6217 $63A0 ScreenNum Difficulty
; =====================================================================
SUB_45BE         LDU    #Fireballs
                 CLRB
                 STB    >$63A1
                 LDA    #$05
                 STA    <$02
L_45C9           LDB    ,U
                 BEQ    L_460D
                 LDB    >$63A1
                 INCB
                 STB    >$63A1
                 LDB    >$6217
                 CMPB   #$01
                 BNE    L_45EB
                 LDB    7,U
                 ANDB   #$70
                 CMPB   #$40
                 BHI    L_45F9
                 LDB    7,U
                 ADDB   #$20
                 STB    7,U
                 BRA    L_45F9
L_45EB           LDB    7,U
                 ANDB   #$70
                 CMPB   #$50
                 BCS    L_45F9
                 LDB    7,U
                 SUBB   #$20
                 STB    7,U
L_45F9           LEAU   <32,U
                 DEC    <$02
                 BNE    L_45C9
                 LDX    #$63A0
                 CLR    ,X
                 LDB    >$63A1
                 BNE    L_460C
                 LEAS   2,S
L_460C           RTS
L_460D           LDB    >$63A1
                 CMPB   #$05
                 BEQ    L_45F9
                 LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 CMPB   #$02
                 BNE    L_4627
                 LDB    >$63A1
                 STB    <$03
                 LDB    >Difficulty
                 CMPB   <$03
                 BEQ    L_460C
L_4627           LDB    >$63A0
                 CMPB   #$01
                 BNE    L_45F9
                 STB    ,U
                 STB    <24,U
                 CLRB
                 STB    >$63A0
                 LDB    >$63A1
                 INCB
                 STB    >$63A1
                 BRA    L_45F9

; =====================================================================
; SUB_4640 (17 instructions)
; Uses:  $63A2 $63E0 $63C8
; Calls: SUB_4667 SUB_4690
; =====================================================================
SUB_4640         BSR    SUB_4667
                 CLRB
                 STB    >$63A2
                 LDX    #$63E0
                 STX    >$63C8
L_464C           LDX    >$63C8
                 LEAX   <32,X
                 STX    >$63C8
                 LDB    ,X
                 BEQ    L_465B
                 BSR    SUB_4690
L_465B           LDB    >$63A2
                 INCB
                 STB    >$63A2
                 CMPB   #$05
                 BNE    L_464C
                 RTS

; =====================================================================
; SUB_4667 (13 instructions)
; Uses:  Difficulty $6439 $6479
; Calls: SUB_4683
; =====================================================================
SUB_4667         LDB    >Difficulty
                 CMPB   #$03
                 BMI    L_4682
                 BSR    SUB_4683
                 CMPB   #$01
                 BNE    L_4682
                 LDX    #$6439
                 LDB    #$02
                 STB    ,X
                 LDX    #$6479
                 LDB    #$02
                 STB    ,X
L_4682           RTS

; =====================================================================
; SUB_4683 (6 instructions)
; Uses:  RandNum FrameCounter
; =====================================================================
SUB_4683         LDB    >RandNum ; random number
                 ANDB   #$03
                 CMPB   #$01
                 BNE    L_4682
                 LDB    >FrameCounter ; decremented every frame
                 RTS

; =====================================================================
; SUB_4690 (70 instructions)
; Uses:  $63C8 RandNum
; Calls: SUB_476E SUB_4794 SUB_480E SUB_3DE0 SUB_4727 SUB_473E SUB_483D SUB_481E
; =====================================================================
SUB_4690         LDU    >$63C8
                 LDB    <24,U
                 CMPB   #$01
                 BEQ    L_46F4
                 LDB    13,U
                 CMPB   #$04
                 BPL    L_46B5
                 LDB    <25,U
                 CMPB   #$02
                 BEQ    L_46F7
                 JSR    >SUB_476E
                 LDB    >RandNum ; random number
                 ANDB   #$03
                 BNE    L_46B8
L_46B1           LDB    13,U
                 BEQ    L_46D5
L_46B5           JSR    >SUB_4794
L_46B8           LDB    13,U
                 CMPB   #$04
                 BPL    L_4705
                 JSR    >SUB_480E
                 JSR    >SUB_3DE0
                 CMPB   #$01
                 BEQ    L_470A
                 LDU    >$63C8
                 LDB    14,U
                 CMPB   #$10
                 BCS    L_4701
                 CMPB   #$F0
                 BCC    L_46FB
L_46D5           LDB    <19,U
                 BNE    L_4724
                 LDB    #$11
L_46DC           STB    <19,U
                 LDX    #D_4EA7
                 ABX
                 LDB    ,X
                 LDA    14,U
                 STA    <$02
                 STA    3,U
                 LDA    15,U
                 STA    <$03
                 ADDB   <$03
                 STB    5,U
                 RTS
L_46F4           BSR    SUB_4727
                 RTS
L_46F7           BSR    SUB_473E
                 BRA    L_46B1
L_46FB           LDB    #$02
L_46FD           STB    13,U
                 BRA    L_46D5
L_4701           LDB    #$01
                 BRA    L_46FD
L_4705           JSR    >SUB_483D
                 BRA    L_46D5
L_470A           LDU    >$63C8
                 LDB    13,U
                 CMPB   #$01
                 BNE    L_471E
                 LDB    #$02
                 DEC    14,U
L_4717           STB    13,U
                 JSR    >SUB_481E
                 BRA    L_46D5
L_471E           LDB    #$01
                 INC    14,U
                 BRA    L_4717
L_4724           DECB
                 BRA    L_46DC

; =====================================================================
; SUB_4727 (11 instructions)
; Uses:  ScreenNum
; Calls: SUB_48EF SUB_4878 SUB_48BC
; =====================================================================
SUB_4727         LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 CMPB   #$01
                 BEQ    L_4736
                 CMPB   #$02
                 BEQ    L_473A
                 JSR    >SUB_48EF
                 RTS
L_4736           JSR    >SUB_4878
                 RTS
L_473A           JSR    >SUB_48BC
                 RTS

; =====================================================================
; SUB_473E (21 instructions)
; Uses:  MarioY
; Calls: SUB_476E
; =====================================================================
SUB_473E         LDB    <28,U
                 BNE    L_4760
                 LDB    <29,U
                 CMPB   #$01
                 BNE    L_476B
                 CLR    <29,U
                 LDB    >MarioY
                 LDA    15,U
                 STA    <$02
                 SUBB   <$02
                 BCS    L_4765
                 LDA    #$FF
                 STA    <28,U
L_475D           CLR    13,U
                 RTS
L_4760           DEC    <28,U
                 BNE    L_475D
L_4765           CLR    <25,U
                 CLR    <28,U
L_476B           BSR    SUB_476E
                 RTS

; =====================================================================
; SUB_476E (18 instructions)
; Uses:  RandNum
; =====================================================================
SUB_476E         LDB    <22,U
                 BNE    L_478A
                 LDA    #$2B
                 STA    <22,U
                 CLR    13,U
                 LDB    >RandNum ; random number
                 RORB
                 BCC    L_478A
                 LDB    13,U
                 CMPB   #$01
                 BEQ    L_478E
                 LDA    #$01
                 STA    13,U
L_478A           DEC    <22,U
                 RTS
L_478E           LDA    #$02
                 STA    13,U
                 BRA    L_478A

; =====================================================================
; SUB_4794 (52 instructions)
; Uses:  MarioY
; Calls: SUB_4801 SUB_37B6
; =====================================================================
SUB_4794         LDB    13,U
                 CMPB   #$08
                 BEQ    L_47CB
                 CMPB   #$04
                 BEQ    L_47E7
                 BSR    SUB_4801
                 LDB    15,U
                 ADDB   #$08
                 STY    <$04
                 STB    <$04
                 LDB    14,U
                 LDX    #$0015
                 STX    <$02
                 JSR    >SUB_37B6
                 TSTB
                 BEQ    L_47F7
                 LDA    <$02
                 STA    <31,U
                 LDB    >MarioY
                 STB    <$02
                 LDB    15,U
                 SUBB   <$02
                 BCC    L_4800
                 LDA    #$04
                 STA    13,U
                 RTS
L_47CB           LDB    15,U
                 ADDB   #$08
                 LDA    <31,U
                 STA    <$02
                 CMPB   <$02
                 BNE    L_4800
                 CLR    13,U
                 LDB    <25,U
                 CMPB   #$02
                 BNE    L_4800
                 LDA    #$01
                 STA    <29,U
                 RTS
L_47E7           LDB    15,U
                 ADDB   #$08
                 LDA    <31,U
                 STA    <$02
                 CMPB   <$02
                 BNE    L_4800
                 CLR    13,U
                 RTS
L_47F7           LDA    <$02
                 STA    <31,U
                 LDA    #$08
                 STA    13,U
L_4800           RTS

; =====================================================================
; SUB_4801 (7 instructions)
; Calls: RST_RetIfNotScreen
; =====================================================================
SUB_4801         LDB    #$07
                 JSR    <RST_RetIfNotScreen
                 LDB    15,U
                 CMPB   #$59
                 BCC    L_4800
                 LEAS   2,S
                 RTS

; =====================================================================
; SUB_480E (8 instructions)
; Calls: SUB_4859
; =====================================================================
SUB_480E         LDB    13,U
                 CMPB   #$01
                 BEQ    L_4833
                 LDB    7,U
                 ANDB   #$7F
                 STB    7,U
                 DEC    14,U
L_481C           BSR    SUB_4859

; =====================================================================
; SUB_481E (15 instructions)
; Uses:  ScreenNum
; Calls: SUB_376C
; =====================================================================
SUB_481E         LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 CMPB   #$01
                 BNE    L_4832
                 LDX    14,U
                 LDA    13,U
                 STA    <$02
                 JSR    >SUB_376C
                 LDA    <$07
                 STA    15,U
L_4832           RTS
L_4833           LDB    7,U
                 ORB    #$80
                 STB    7,U
                 INC    14,U
                 BRA    L_481C

; =====================================================================
; SUB_483D (14 instructions)
; Calls: SUB_4859
; =====================================================================
SUB_483D         BSR    SUB_4859
                 LDB    13,U
                 CMPB   #$08
                 BNE    L_4856
                 LDB    <20,U
                 BNE    L_4852
                 LDA    #$02
                 STA    <20,U
                 DEC    15,U
                 RTS
L_4852           DEC    <20,U
                 RTS
L_4856           INC    15,U
                 RTS

; =====================================================================
; SUB_4859 (15 instructions)
; =====================================================================
SUB_4859         LDB    <21,U
                 BNE    L_4874
                 LDA    #$02
                 STA    <21,U
                 INC    7,U
                 LDB    7,U
                 ANDB   #$0F
                 CMPB   #$0F
                 BNE    L_4877
                 LDB    7,U
                 EORB   #$02
                 STB    7,U
                 RTS
L_4874           DEC    <21,U
L_4877           RTS

; =====================================================================
; SUB_4878 (30 instructions)
; =====================================================================
SUB_4878         LDB    <26,U
                 LDA    <27,U
                 TFR    D,X
                 CMPX   #$0000
                 BNE    L_488C
                 LDX    #D_4EB9
                 LDA    #$26
                 STA    3,U
L_488C           INC    3,U
L_488E           LDB    ,X
                 CMPB   #$AA
                 BEQ    L_48A1
                 STB    5,U
                 LEAX   1,X
                 TFR    X,D
                 STB    <26,U
                 STA    <27,U
                 RTS
L_48A1           CLRB
                 STB    <19,U
                 STB    <24,U
                 STB    13,U
                 STB    <28,U
                 LDB    3,U
                 STB    14,U
                 LDB    5,U
                 STB    15,U
                 CLR    <26,U
                 CLR    <27,U
                 RTS

; =====================================================================
; SUB_48BC (22 instructions)
; Uses:  MarioX
; =====================================================================
SUB_48BC         LDB    <26,U
                 LDA    <27,U
                 TFR    D,X
                 CMPX   #$0000
                 BNE    L_48D8
                 LDX    #D_4ED9
                 LDB    >MarioX
                 BPL    L_48E2
                 LDD    #$017E
                 STA    13,U
                 STB    3,U
L_48D8           LDB    13,U
                 CMPB   #$01
                 BNE    L_48EB
                 INC    3,U
                 BRA    L_488E
L_48E2           LDD    #$0280
                 STA    13,U
                 STB    3,U
                 BRA    L_48D8
L_48EB           DEC    3,U
                 BRA    L_488E

; =====================================================================
; SUB_48EF (23 instructions)
; Uses:  ScreenNum MarioX RandTimer
; =====================================================================
SUB_48EF         LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 CMPB   #$03
                 BEQ    L_491B
                 LDB    >MarioX
                 BMI    L_491C
                 LDX    #D_4EF1
L_48FE           CLR    <$02
                 LDB    >RandTimer
                 ANDB   #$06
                 ABX
                 LDB    ,X+
                 STB    3,U
                 STB    14,U
                 LDB    ,X
                 STB    5,U
                 STB    15,U
                 CLRB
                 STB    13,U
                 STB    <24,U
                 STB    <28,U
L_491B           RTS
L_491C           LDX    #D_4F01
                 BRA    L_48FE

; =====================================================================
; SUB_4921 (17 instructions)
; Uses:  Fireballs $69D0
; =====================================================================
SUB_4921         LDX    #Fireballs
                 LDY    #$69D0
                 LDA    #$05
L_492A           LDB    ,X
                 BEQ    L_493C
                 LDB    3,X
                 ANDB   #$FE
                 STB    ,Y
                 LDB    7,X
                 STB    1,Y
                 LDB    5,X
                 STB    3,Y
L_493C           LEAY   4,Y
                 LEAX   <32,X
                 DECA
                 BNE    L_492A
                 RTS

; =====================================================================
; Arcade data tables (translated from the Z80 ROM): score values,
; default high scores, strings, stage layouts, animation tables.
; =====================================================================
TBL_ScoreValues  FCB    $00,$00,$00,$00,$01,$00,$00,$02
                 FCB    $00,$00,$03,$00,$00,$04,$00,$00
                 FCB    $05,$00,$00,$06,$00,$00,$07,$00
                 FCB    $00,$08,$00,$00,$09,$00,$00,$00
                 FCB    $00,$00,$10,$00,$00,$20,$00,$00
                 FCB    $30,$00,$00,$40,$00,$00,$50,$00
                 FCB    $00,$60,$00,$00,$70,$00,$00,$80
                 FCB    $00,$00,$90,$00
DefaultHiScores  FCB    $77,$94,$01,$23,$24,$10,$10,$00
                 FCB    $00,$07,$06,$05,$00
                 FILL   $10,14
                 FCB    $3F,$00,$50,$76,$00,$76,$F4,$77
                 FCB    $96,$02,$1E,$14,$10,$10,$00,$00
                 FCB    $06,$01,$00,$00
                 FILL   $10,14
                 FCB    $3F,$00,$00,$61,$00,$76,$F6,$77
                 FCB    $98,$03,$22,$14,$10,$10,$00,$00
                 FCB    $05,$09,$05,$00
                 FILL   $10,14
                 FCB    $3F,$00,$50,$59,$00,$76,$F8,$77
                 FCB    $9A,$04,$24,$18,$10,$10,$00,$00
                 FCB    $05,$00,$05,$00
                 FILL   $10,14
                 FCB    $3F,$00,$50,$50,$00,$76,$FA,$77
                 FCB    $9C,$05,$24,$18,$10,$10,$00,$00
                 FCB    $04,$03,$00,$00
                 FILL   $10,14
                 FCB    $3F,$00,$00,$43,$00,$76,$FC
D_4A2B           FCB    $3B,$5D,$4B,$5D,$5B,$5D,$6B,$5D
                 FCB    $7B,$5D,$8B,$5D,$9B,$5D,$AB,$5D
                 FCB    $BB,$5D,$CB,$5D,$3B,$6D,$4B,$6D
                 FCB    $5B,$6D,$6B,$6D,$7B,$6D,$8B,$6D
                 FCB    $9B,$6D,$AB,$6D,$BB,$6D,$CB,$6D
                 FCB    $3B,$7D,$4B,$7D,$5B,$7D,$6B,$7D
                 FCB    $7B,$7D,$8B,$7D,$9B,$7D,$AB,$7D
                 FCB    $BB,$7D,$CB,$7D

; =====================================================================
; String pointer table for Task3_ShowString.  Entries $14-$18 point
; to the high-score lines in RAM ($6100-$61A8).
; =====================================================================
TBL_Strings      FDB    D_4AA7 ; #00 "GAME  OVER"
                 FDB    $0001 ; #01 (unused)
                 FDB    D_4AB4 ; #02 "PLAYER ~~~"
                 FDB    D_4AC1 ; #03 "PLAYER ~~~"
                 FDB    D_4ACE ; #04 "HIGH SCORE"
                 FDB    D_4ADB ; #05 "CREDIT    "
                 FDB    $0006 ; #06 (unused)
                 FDB    D_4AE8 ; #07 "HOW HIGH CAN YOU GET ~ "
                 FDB    $0008 ; #08 (unused)
                 FDB    D_4B02 ; #09 "ONLY 1 PLAYER BUTTON"
                 FDB    D_4B19 ; #0A "1 OR 2 PLAYERS BUTTON"
                 FDB    $000B ; #0B (unused)
                 FDB    D_4B31 ; #0C "PUSH"
                 FDB    D_4B38 ; #0D "NAME REGISTRATION"
                 FDB    D_4B4C ; #0E "NAME:"
                 FDB    D_4B54 ; #0F """"         "
                 FDB    D_4B63 ; #10 "A B C D E F G H I J"
                 FDB    D_4B79 ; #11 "K L M N O P Q R S T"
                 FDB    D_4B8F ; #12 "U V W X Y Z . -~~~~~ "
                 FDB    D_4BA7 ; #13 "REGI TIME  ~30~ "
                 FDB    HiScoreTable ; #14 (RAM high-score line)
                 FDB    $6122 ; #15 (RAM high-score line)
                 FDB    $6144 ; #16 (RAM high-score line)
                 FDB    $6166 ; #17 (RAM high-score line)
                 FDB    $6188 ; #18 (RAM high-score line)
                 FDB    D_4BBA ; #19 "RANK  SCORE  NAME    "
                 FDB    D_4BD2 ; #1A "YOUR NAME WAS REGISTERED~"
                 FDB    D_4BEE ; #1B "INSERT COIN "
                 FDB    D_4BFD ; #1C "  PLAYER    COIN"
                 FDB    $001D ; #1D (unused)
                 FDB    D_4C10 ; #1E "~~ NINTENDO"
                 FDB    D_4C1E ; #1F "1981"
D_4AA7           FDB    $7696 ; string #00 at tile RAM $7696
                 FCB    $17,$11,$1D,$15,$10,$10,$1F,$26,$15,$22,$3F ; "GAME  OVER" +end
D_4AB4           FDB    $7694 ; string #02 at tile RAM $7694
                 FCB    $20,$1C,$11,$29,$15,$22,$10,$30,$32,$31,$3F ; "PLAYER ~~~" +end
D_4AC1           FDB    $7694 ; string #03 at tile RAM $7694
                 FCB    $20,$1C,$11,$29,$15,$22,$10,$30,$33,$31,$3F ; "PLAYER ~~~" +end
D_4ACE           FDB    $7680 ; string #04 at tile RAM $7680
                 FCB    $18,$19,$17,$18,$10,$23,$13,$1F,$22,$15,$3F ; "HIGH SCORE" +end
D_4ADB           FDB    $759F ; string #05 at tile RAM $759F
                 FCB    $13,$22,$15,$14,$19,$24,$10,$10,$10,$10,$3F ; "CREDIT    " +end
D_4AE8           FDB    $775E ; string #07 at tile RAM $775E
                 FCB    $18,$1F,$27,$10,$18,$19,$17,$18,$10,$13,$11,$1E ; "HOW HIGH CAN"
                 FCB    $10,$29,$1F,$25,$10,$17,$15,$24,$10,$FB,$10,$3F ; " YOU GET ~ " +end
D_4B02           FDB    $7729 ; string #09 at tile RAM $7729
                 FCB    $1F,$1E,$1C,$29,$10,$01,$10,$20,$1C,$11,$29,$15 ; "ONLY 1 PLAYE"
                 FCB    $22,$10,$12,$25,$24,$24,$1F,$1E,$3F ; "R BUTTON" +end
D_4B19           FDB    $7729 ; string #0A at tile RAM $7729
                 FCB    $01,$10,$1F,$22,$10,$02,$10,$20,$1C,$11,$29,$15 ; "1 OR 2 PLAYE"
                 FCB    $22,$23,$10,$12,$25,$24,$24,$1F,$1E,$3F ; "RS BUTTON" +end
D_4B31           FDB    $7627 ; string #0C at tile RAM $7627
                 FCB    $20,$25,$23,$18,$3F ; "PUSH" +end
D_4B38           FDB    $7706 ; string #0D at tile RAM $7706
                 FCB    $1E,$11,$1D,$15,$10,$22,$15,$17,$19,$23,$24,$22 ; "NAME REGISTR"
                 FCB    $11,$24,$19,$1F,$1E,$3F ; "ATION" +end
D_4B4C           FDB    $7688 ; string #0E at tile RAM $7688
                 FCB    $1E,$11,$1D,$15,$2E,$3F ; "NAME:" +end
D_4B54           FDB    $75E9 ; string #0F at tile RAM $75E9
                 FCB    $2D,$2D,$2D,$10,$10,$10,$10,$10,$10,$10,$10,$10 ; """"         "
                 FCB    $3F ; "" +end
D_4B63           FDB    $770B ; string #10 at tile RAM $770B
                 FCB    $11,$10,$12,$10,$13,$10,$14,$10,$15,$10,$16,$10 ; "A B C D E F "
                 FCB    $17,$10,$18,$10,$19,$10,$1A,$3F ; "G H I J" +end
D_4B79           FDB    $770D ; string #11 at tile RAM $770D
                 FCB    $1B,$10,$1C,$10,$1D,$10,$1E,$10,$1F,$10,$20,$10 ; "K L M N O P "
                 FCB    $21,$10,$22,$10,$23,$10,$24,$3F ; "Q R S T" +end
D_4B8F           FDB    $770F ; string #12 at tile RAM $770F
                 FCB    $25,$10,$26,$10,$27,$10,$28,$10,$29,$10,$2A,$10 ; "U V W X Y Z "
                 FCB    $2B,$10,$2C,$44,$45,$46,$47,$48,$10,$3F ; ". -~~~~~ " +end
D_4BA7           FDB    $76F2 ; string #13 at tile RAM $76F2
                 FCB    $22,$15,$17,$19,$10,$24,$19,$1D,$15,$10,$10,$30 ; "REGI TIME  ~"
                 FCB    $03,$00,$31,$10,$3F ; "30~ " +end
D_4BBA           FDB    $7792 ; string #19 at tile RAM $7792
                 FCB    $22,$11,$1E,$1B,$10,$10,$23,$13,$1F,$22,$15,$10 ; "RANK  SCORE "
                 FCB    $10,$1E,$11,$1D,$15,$10,$10,$10,$10,$3F ; " NAME    " +end
D_4BD2           FDB    $7772 ; string #1A at tile RAM $7772
                 FCB    $29,$1F,$25,$22,$10,$1E,$11,$1D,$15,$10,$27,$11 ; "YOUR NAME WA"
                 FCB    $23,$10,$22,$15,$17,$19,$23,$24,$15,$22,$15,$14 ; "S REGISTERED"
                 FCB    $42,$3F ; "~" +end
D_4BEE           FDB    $76A7 ; string #1B at tile RAM $76A7
                 FCB    $19,$1E,$23,$15,$22,$24,$10,$13,$1F,$19,$1E,$10 ; "INSERT COIN "
                 FCB    $3F ; "" +end
D_4BFD           FDB    $770A ; string #1C at tile RAM $770A
                 FCB    $10,$10,$20,$1C,$11,$29,$15,$22,$10,$10,$10,$10 ; "  PLAYER    "
                 FCB    $13,$1F,$19,$1E,$3F ; "COIN" +end
D_4C10           FDB    $76FC ; string #1E at tile RAM $76FC
                 FCB    $49,$4A,$10,$1E,$19,$1E,$24,$15,$1E,$14,$1F,$3F ; "~~ NINTENDO" +end
D_4C1E           FDB    $757C ; string #1F at tile RAM $757C
                 FCB    $01,$09,$08,$01,$3F ; "1981" +end
D_4C25           FCB    $02,$97,$38,$68,$38,$02,$DF,$54
                 FCB    $10,$54,$02,$EF,$6D,$20,$6D,$02
                 FCB    $DF,$8E,$10,$8E,$02,$EF,$AF,$20
                 FCB    $AF,$02,$DF,$D0,$10,$D0,$02,$EF
                 FCB    $F1,$10,$F1,$00,$53,$18,$53,$54
                 FCB    $00,$63,$18,$63,$54,$00,$93,$38
                 FCB    $93,$54,$00,$83,$54,$83,$F1,$00
                 FCB    $93,$54,$93,$F1,$AA
D_4C62           FCB    $8D,$7D,$8C,$6F,$00,$7C,$6E,$00
                 FCB    $7C,$6D,$00,$7C,$6C,$00,$7C,$8F
                 FCB    $7F,$8E
D_4C74           FCB    $50,$34,$08,$3C,$00,$35,$08,$3C
                 FCB    $53,$32,$08,$40,$63,$33,$08,$40
                 FCB    $00,$70,$08,$48,$53,$36,$08,$50
                 FCB    $63,$37,$08,$50,$6B,$31,$08,$41
                 FCB    $00,$70,$08,$48,$6A,$14,$0A,$48
D_4C9C           FCB    $FD,$FD,$FD,$FD,$FD,$FD,$FD,$FE
                 FCB    $FE,$FE,$FE,$FE,$FE,$FF,$FF,$FF
                 FCB    $FF,$00,$00,$01,$01,$01,$7F
D_4CB3           FCB    $FF,$FF,$FF,$FF,$FF,$00,$FF,$00
                 FCB    $00,$01,$00,$01,$01,$01,$01,$01
                 FCB    $7F
D_4CC4           FCB    $04,$7F,$F0,$10,$F0,$02,$DF,$F2
                 FCB    $70,$F8,$02,$6F,$F8,$10,$F8,$AA
                 FCB    $04,$DF,$D0,$90,$D0,$02,$DF,$DC
                 FCB    $20,$D1,$AA,$FF,$FF,$FF,$FF,$FF
                 FCB    $04,$DF,$A8,$20,$A8,$04,$5F,$B0
                 FCB    $20,$B0,$02,$DF,$B0,$20,$BB,$AA
                 FCB    $04,$DF,$88,$30,$88,$04,$DF,$90
                 FCB    $B0,$90,$02,$DF,$9A,$20,$8F,$AA
                 FCB    $04,$BF,$68,$20,$68,$04,$3F,$70
                 FCB    $20,$70,$02,$DF,$6E,$20,$79,$AA
D_4D14           FCB    $02,$DF,$58,$A0,$55,$AA
D_4D1A           FCB    $00,$70,$08,$44,$2B,$AC,$08,$4C
                 FCB    $3B,$AE,$08,$4C,$3B,$AF,$08,$3C
                 FCB    $4B,$B0,$07,$3C,$4B,$AD,$08,$4C
                 FCB    $00,$70,$08,$44,$00,$70,$08,$44
                 FCB    $00,$70,$08,$44,$00,$70,$0A,$44
                 FCB    $47,$27,$08,$4C,$2F,$A7,$08,$4C
                 FCB    $3B,$25,$08,$4C,$00,$70,$08,$44
                 FCB    $3B,$23,$07,$3C,$4B,$2A,$08,$3C
                 FCB    $4B,$2B,$08,$4C,$2B,$AA,$08,$3C
                 FCB    $2B,$AB,$08,$4C,$00,$70,$0A,$44
                 FCB    $00,$70,$08,$44,$4B,$2C,$08,$4C
                 FCB    $3B,$2E,$08,$4C,$3B,$2F,$08,$3C
                 FCB    $2B,$30,$07,$3C,$2B,$2D,$08,$4C
                 FCB    $00,$70,$08,$44,$00,$70,$08,$44
                 FCB    $00,$70,$08,$44,$00,$70,$0A,$44
D_4D92           FCB    $FD,$FD,$FD,$FE,$FE,$FE,$FE,$FF
                 FCB    $FF,$00,$FF,$00,$00,$01,$00,$01
                 FCB    $01,$02,$02,$02,$02,$03,$03,$03
                 FCB    $7F
D_4DAB           FCB    $1E,$4E,$BB,$4C,$D8,$4E,$59,$4E
                 FCB    $7F
D_4DB4           FCB    $BB,$4D,$7F
D_4DB7           FCB    $47,$27,$08,$50,$2F,$A7,$08,$50
                 FCB    $3B,$25,$08,$50,$00,$70,$08,$48
                 FCB    $3B,$23,$07,$40,$47,$A9,$08,$44
                 FCB    $00,$70,$08,$48,$2F,$29,$08,$44
                 FCB    $00,$70,$08,$48,$00,$70,$0A,$48
                 FCB    $6F,$10,$09,$23,$6F,$11,$0A,$33
D_4DE7           FCB    $47,$27,$08,$50,$2D,$26,$08,$50
                 FCB    $3B,$25,$08,$50,$00,$70,$08,$48
                 FCB    $3B,$24,$07,$40,$4B,$28,$08,$40
                 FCB    $00,$70,$08,$48,$2F,$29,$08,$44
                 FCB    $00,$70,$08,$48,$00,$70,$0A,$48
D_4E0F           FCB    $49,$A6,$08,$50,$2F,$A7,$08,$50
                 FCB    $3B,$25,$08,$50,$00,$70,$08,$48
                 FCB    $3B,$24,$07,$40,$47,$A9,$08,$44
                 FCB    $00,$70,$08,$48,$2B,$A8,$08,$40
                 FCB    $00,$70,$08,$48,$00,$70,$0A,$48
D_4E37           FCB    $73,$E7,$08,$60,$8B,$67,$08,$60
                 FCB    $7F,$65,$08,$60,$00,$70,$08,$68
                 FCB    $7F,$64,$07,$70,$75,$69,$08,$6C
                 FCB    $00,$70,$08,$68,$89,$E9,$08,$6C
                 FCB    $00,$70,$08,$68,$00,$70,$0A,$68
D_4E5F           FCB    $05,$AF,$F0,$50,$F0,$AA
D_4E65           FCB    $05,$AF,$E8,$50,$E8,$AA
D_4E6B           FCB    $05,$AF,$E0,$50,$E0,$AA
D_4E71           FCB    $05,$AF,$D8,$50,$D8,$AA
D_4E77           FCB    $05,$B7,$58,$48,$58,$AA

; =====================================================================
; TBL_StageOrder: screen sequence per level (1 girders, 2 conveyors,
; 3 elevators, 4 rivets); Setup copies the Japanese order over it.
; =====================================================================
TBL_StageOrder   FCB    $01,$04,$01,$03,$04,$01,$02,$03
                 FCB    $04,$01,$02,$01,$03,$04
D_4E8B           FCB    $01,$02,$01,$03,$01,$04,$7F,$01
                 FCB    $02,$03,$04,$01,$02,$03,$04,$01
                 FCB    $02,$03,$04,$7F,$7F,$01,$02,$03
                 FCB    $04,$7F,$7F,$7F
D_4EA7           FCB    $FF,$00,$FF,$FF
                 FILL   $FE,11
                 FCB    $FF,$FF,$00
D_4EB9           FCB    $E8,$E5,$E3,$E2,$E1,$E0,$DF,$DE
                 FCB    $DD,$DD,$DC,$DC,$DC,$DC,$DC,$DC
                 FCB    $DD,$DD,$DE,$DF,$E0,$E1,$E2,$E3
                 FCB    $E4,$E5,$E7,$E9,$EB,$ED,$F0,$AA
D_4ED9           FCB    $80,$7B,$78,$76,$74,$73,$72,$71
                 FCB    $70,$70,$6F,$6F,$6F,$70,$70,$71
                 FCB    $72,$73,$74,$75,$76,$77,$78,$AA
D_4EF1           FCB    $EE,$F0,$DB,$A0,$E6,$C8,$D6,$78
                 FCB    $EB,$F0,$DB,$A0,$E6,$C8,$E6,$C8
D_4F01           FCB    $1B,$C8,$23,$A0,$2B,$78,$12,$F0
                 FCB    $1B,$C8,$23,$A0,$12,$F0,$1B,$C8
D_4F11           FCB    $02,$97,$38,$68,$38,$02,$9F,$54
                 FCB    $10,$54,$02,$DF,$58,$A0,$55,$02
                 FCB    $EF,$6D,$20,$79,$02,$DF,$9A,$10
                 FCB    $8E,$02,$EF,$AF,$20,$BB,$02,$DF
                 FCB    $DC,$10,$D0,$02,$FF,$F0,$80,$F7
                 FCB    $02,$7F,$F8,$00,$F8,$00,$CB,$57
                 FCB    $CB,$6F,$00,$CB,$99,$CB,$B1,$00
                 FCB    $CB,$DB,$CB,$F3,$00,$63,$18,$63
                 FCB    $54,$01,$63,$D5,$63,$F8,$00,$33
                 FCB    $78,$33,$90,$00,$33,$BA,$33,$D2
                 FCB    $00,$53,$18,$53,$54,$01,$53,$92
                 FCB    $53,$B8,$00,$5B,$76,$5B,$92,$00
                 FCB    $73,$B6,$73,$D6,$00,$83,$95,$83
                 FCB    $B5,$00,$93,$38,$93,$54,$01,$BB
                 FCB    $70,$BB,$98,$01,$6B,$54,$6B,$75
                 FCB    $AA
D_4F8A           FCB    $06,$8F,$90,$70,$90,$06,$8F,$98
                 FCB    $70,$98,$06,$8F,$A0,$70,$A0,$00
                 FCB    $63,$18,$63,$58,$00,$63,$80,$63
                 FCB    $A8,$00,$63,$D0,$63,$F8,$00,$53
                 FCB    $18,$53,$58,$00,$53,$A8,$53,$D0
                 FCB    $00,$9B,$80,$9B,$A8,$00,$9B,$D0
                 FCB    $9B,$F8,$01,$23,$58,$23,$80,$01
                 FCB    $DB,$58,$DB,$80,$00,$2B,$80,$2B
                 FCB    $A8,$00,$D3,$80,$D3,$A8,$00,$A3
                 FCB    $A8,$A3,$D0,$00,$2B,$D0,$2B,$F8
                 FCB    $00,$D3,$D0,$D3,$F8,$00,$93,$38
                 FCB    $93,$58,$02,$97,$38,$68,$38,$03
                 FCB    $EF,$58,$10,$58,$03,$F7,$80,$88
                 FCB    $80,$03,$77,$80,$08,$80,$02,$A7
                 FCB    $A8,$50,$A8,$02,$E7,$A8,$B8,$A8
                 FCB    $02,$3F,$A8,$18,$A8,$03,$EF,$D0
                 FCB    $10,$D0,$02,$EF,$F8,$10,$F8,$AA
D_5012           FCB    $00,$63,$18,$63,$58,$00,$63,$88
                 FCB    $63,$D0,$00,$53,$18,$53,$58,$00
                 FCB    $53,$88,$53,$D0,$00,$E3,$68,$E3
                 FCB    $90,$00,$E3,$B8,$E3,$D0,$00,$CB
                 FCB    $90,$CB,$B0,$00,$B3,$58,$B3,$78
                 FCB    $00,$9B,$80,$9B,$A0,$00,$93,$38
                 FCB    $93,$58,$00,$23,$88,$23,$C0,$00
                 FCB    $1B,$C0,$1B,$E8,$02,$97,$38,$68
                 FCB    $38,$02,$B7,$58,$10,$58,$02,$EF
                 FCB    $68,$E0,$68,$02,$D7,$70,$C8,$70
                 FCB    $02,$BF,$78,$B0,$78,$02,$A7,$80
                 FCB    $90,$80,$02,$67,$88,$48,$88,$02
                 FCB    $27,$88,$10,$88,$02,$EF,$90,$C8
                 FCB    $90,$02,$A7,$A0,$98,$A0,$02,$BF
                 FCB    $A8,$B0,$A8,$02,$D7,$B0,$C8,$B0
                 FCB    $02,$EF,$B8,$E0,$B8,$02,$27,$C0
                 FCB    $10,$C0,$02,$EF,$D0,$D8,$D0,$02
                 FCB    $67,$D0,$50,$D0,$02,$CF,$D8,$C0
                 FCB    $D8,$02,$B7,$E0,$A8,$E0,$02,$9F
                 FCB    $E8,$88,$E8,$02,$27,$E8,$10,$E8
                 FCB    $02,$EF,$F8,$10,$F8,$AA
D_50B8           FCB    $00,$7B,$80,$7B,$A8,$00,$7B,$D0
                 FCB    $7B,$F8,$00,$33,$58,$33,$80,$00
                 FCB    $53,$58,$53,$80,$00,$AB,$58,$AB
                 FCB    $80,$00,$CB,$58,$CB,$80,$00,$2B
                 FCB    $80,$2B,$A8,$00,$D3,$80,$D3,$A8
                 FCB    $00,$23,$A8,$23,$D0,$00,$5B,$A8
                 FCB    $5B,$D0,$00,$A3,$A8,$A3,$D0,$00
                 FCB    $DB,$A8,$DB,$D0,$00,$1B,$D0,$1B
                 FCB    $F8,$00,$E3,$D0,$E3,$F8,$05,$B7
                 FCB    $30,$48,$30,$05,$CF,$58,$30,$58
                 FCB    $05,$D7,$80,$28,$80,$05,$DF,$A8
                 FCB    $20,$A8,$05,$E7,$D0,$18,$D0,$05
                 FCB    $EF,$F8,$10,$F8,$AA
D_511D           FCB    $10,$82,$85,$8B,$10,$85,$80,$8B
                 FCB    $10,$87,$85,$8B,$81,$80,$80,$8B
                 FCB    $81,$82,$85,$8B,$81,$85,$80,$8B
D_5135           FCB    $05,$77,$88,$01,$77,$68,$01,$77
                 FCB    $6C,$03,$77,$49,$05,$77,$08,$01
                 FCB    $76,$E8,$01,$76,$EC,$05,$76,$C8
                 FCB    $05,$76,$88,$02,$76,$69,$02,$76
                 FCB    $4A,$05,$76,$28,$05,$75,$E8,$01
                 FCB    $75,$CA,$03,$75,$A9,$01,$75,$88
                 FCB    $01,$75,$8C,$05,$75,$48,$01,$75
                 FCB    $28,$01,$75,$2A,$01,$75,$2C,$01
                 FCB    $75,$08,$01,$75,$0A,$01,$75,$0C
                 FCB    $03,$74,$C8,$03,$74,$AA,$03,$74
                 FCB    $88,$05,$77,$2F,$05,$77,$0F,$02
                 FCB    $76,$F0,$02,$76,$CF,$02,$76,$D2
                 FCB    $05,$76,$8F,$05,$76,$6F,$01,$76
                 FCB    $4F,$01,$76,$53,$05,$76,$2F,$05
                 FCB    $75,$EF,$02,$75,$D0,$02,$75,$B1
                 FCB    $05,$75,$8F,$03,$75,$50,$05,$75
                 FCB    $2F,$01,$75,$0F,$01,$75,$13,$01
                 FCB    $74,$EF,$01,$74,$F1,$01,$74,$F3
                 FCB    $02,$74,$D1,$00
D_51C9           FCB    $00,$00,$23,$68,$01,$11,$00,$00
                 FCB    $00,$10,$DB,$68,$01,$40,$00,$00
                 FCB    $08
                 FILL   $01,9
                 FCB    $00,$00,$00,$00,$00,$00,$80,$01
                 FCB    $C0,$FF,$01,$FF,$FF,$34,$4D,$AB
                 FCB    $67,$00,$69,$80,$1A,$01
                 FILL   $00,8
                 FCB    $04,$00,$10,$00,$00,$00,$00,$00
D_5209           FCB    $1E,$18,$0B,$4B,$14,$18,$0B,$4B
                 FCB    $1E,$18,$0B,$3B,$14,$18,$0B,$3B
D_5219           FCB    $3D,$01,$03,$02
D_521D           FCB    $4D,$01,$04,$01
D_5221           FCB    $27,$70,$01,$E0,$00,$00
D_5227           FCB    $7F,$40,$01,$78,$02,$00
D_522D           FCB    $27,$49,$0C,$F0
D_5231           FCB    $7F,$49,$0C,$88
D_5235           FCB    $1E,$07,$03,$09
D_5239           FCB    $24,$64,$BB,$C0
D_523D           FCB    $23,$8D,$7B,$B4
D_5241           FCB    $1B,$8C,$7C,$64
D_5245           FCB    $4B,$0E,$04,$02
D_5249           FCB    $23,$46,$03,$68,$DB,$46,$03,$68
D_5251           FCB    $17,$50,$00,$5C,$E7,$D0,$00,$5C
                 FCB    $8C,$50,$00,$84,$71,$D0,$00,$84
                 FCB    $17,$50,$00,$D4,$E7,$D0,$00,$D4
D_5269           FCB    $53,$73,$0A,$A0,$8B,$74,$0A,$F0
                 FCB    $DB,$75,$0A,$A0
D_5275           FCB    $5B,$73,$0A,$C8,$E3,$74,$0A,$60
                 FCB    $1B,$75,$0A,$80
D_5281           FCB    $DB,$73,$0A,$C8,$93,$74,$0A,$F0
                 FCB    $33,$75,$0A,$50
D_528D           FCB    $44,$03,$08,$04
D_5291           FCB    $37,$F4,$37,$C0,$37,$8C,$77,$70
                 FCB    $77,$A4,$77,$D8

; =====================================================================
; JumpOverCheck: while Mario jumps, count barrels ($6700) and
; fireballs ($6400) inside the box under him (HitboxScan) -> $6060.
; Returns B = score index (0 none, 3 one, 7 several) for Task0_AddScore.
; Per-screen variants through TBL_JumpOverStage.
; =====================================================================
JumpOverCheck    LDB    >ScreenNum ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
                 PSHS   X
                 JSR    <RST_JumpTable
TBL_JumpOverStage FDB    ColdStart
                 FDB    L_52B0
                 FDB    L_3CF3
                 FDB    L_3D23
                 FDB    L_3D44
                 FDB    ColdStart
L_52B0           PULS   X
                 CLRB
                 STB    >$6060
                 LDA    #$0A
                 STA    <$02
                 LDY    #$0020
                 LDU    #Barrels
                 BSR    HitboxScan
                 LDA    #$05
                 STA    <$02
                 LDU    #Fireballs
                 BSR    HitboxScan
                 LDB    >$6060
                 BEQ    L_52DD
                 CMPB   #$01
                 BEQ    L_52DD
                 CMPB   #$03
                 LDB    #$03
                 BCS    L_52DD
                 LDB    #$07
L_52DD           RTS

; =====================================================================
; HitboxScan: count objects (stride 32 at U) overlapping the box
; around (IX+3, <$03) into $6060.
; =====================================================================
HitboxScan       STX    <$06
                 LDX    <$0A
L_52E2           LDA    ,U
                 ANDA   #$01
                 BEQ    L_530A
                 LDB    <$03
                 SUBB   5,U
                 BCC    L_52EF
                 NEGB
L_52EF           INCB
                 SUBB   <$07
                 BCS    L_52F8
                 SUBB   10,U
                 BCC    L_530A
L_52F8           LDB    3,X
                 SUBB   3,U
                 BCC    L_52FF
                 NEGB
L_52FF           SUBB   <$06
                 BCS    L_5307
                 SUBB   9,U
                 BCC    L_530A
L_5307           INC    >$6060
L_530A           LEAU   <32,U
                 DEC    <$02
                 BNE    L_52E2
                 LDX    <$06
                 RTS
L_5314           BSR    SUB_5319
                 JMP    >L_1F7E

; =====================================================================
; SUB_5319 (13 instructions)
; Uses:  $776C $748C
; Calls: RST_RetIfNotScreen
; =====================================================================
SUB_5319         LDB    #$02
                 JSR    <RST_RetIfNotScreen
                 LDA    #$02
                 STA    <$02
                 LDX    #$776C
L_5324           LDA    #$10
                 STA    ,X++
                 LDA    #$C0
                 STA    ,X
                 LDX    #$748C
                 DEC    <$02
                 BNE    L_5324
                 RTS

; =====================================================================
; SUB_5334 (4 instructions)
; Uses:  $694D
; =====================================================================
SUB_5334         LDX    #$694D
                 LDA    #$03
                 STA    ,X++
                 RTS

; =====================================================================
; Z80_EXX: swap BC/HL/DE (<$02, X, Y) with the alternate set kept in
; the direct page; <$0C toggles which set is active.
; =====================================================================
Z80_EXX          COM    <$0C
                 BMI    L_5353
                 STX    <$17
                 LDX    <$02
                 STX    <$13
                 LDX    <$0D
                 STX    <$02
                 LDX    <$11
                 STY    <$15
                 LDY    <$0F
                 RTS
L_5353           STX    <$11
                 LDX    <$02
                 STX    <$0D
                 LDX    <$13
                 STX    <$02
                 LDX    <$17
                 STY    <$0F
                 LDY    <$15
                 RTS

; =====================================================================
; PaletteBankUpdate: arcade palette bank $7D86/$7D87 -> copy the
; matching colour tables from page $29 to $0F00 and select the tile
; colour table used by DrawDirtyTiles (patches LDY at L_54C6).
; =====================================================================
PaletteBankUpdate PSHS   A,B,X,Y
                 LDA    #$29
                 STA    >MMU_T0_P1 ; MMU_T0_P1 - Task0 page1 ($2000-$3FFF)
                 LDD    >PaletteBank0 ; palette bank bit 0
                 LSRB
                 ROLA
                 ANDA   #$03
                 STA    >L_538A+1
                 BEQ    L_538A
                 ADDA   #$27
                 CLRB
                 TFR    D,Y
                 LDX    #$0F00
L_5381           LDD    ,Y++
                 STD    ,X++
                 CMPX   #$1000
                 BCS    L_5381
L_538A           LDD    #$0000 ; SMC: operand patched by $5374
                 RORA
                 RORB
                 RORA
                 RORB
                 LDX    #TBL_TilePalette
                 ABX
                 STX    >L_54C6+2
                 LDA    #$39
                 STA    >MMU_T0_P1 ; MMU_T0_P1 - Task0 page1 ($2000-$3FFF)
                 PULS   A,B,X,Y,PC
TBL_TilePalette  FCB    $20,$50,$20,$10,$20,$00,$20,$00
                 FCB    $20,$40,$20,$20,$20,$20,$20,$10
                 FILL   $20,9
                 FCB    $50,$20,$20,$20,$50,$20,$10,$20
                 FCB    $50
                 FILL   $20,9
                 FCB    $10,$20,$50,$20,$10,$20,$30,$20
                 FCB    $10,$20,$20,$20,$30,$20,$50,$20
                 FCB    $30,$20,$50,$20,$20,$20,$20,$20
                 FCB    $10,$20,$00,$20,$00,$20,$40
                 FILL   $20,55
                 FCB    $00,$20,$10,$20,$00,$20,$00,$20
                 FCB    $40,$20,$00,$20,$00,$20,$00,$20
                 FCB    $00,$20,$00,$20,$00,$20,$00,$20
                 FCB    $00,$20,$00,$20,$00,$20,$00,$20
                 FCB    $00,$20,$00,$20,$00,$20,$00,$20
                 FCB    $00,$20,$00,$20,$00,$20,$00,$20
                 FCB    $00,$20,$00,$20,$00,$20,$00,$20
                 FCB    $00,$20,$00,$20,$00,$20,$00
D_545F           FCB    $20,$30,$20,$10,$20,$00,$20,$00
                 FCB    $20,$40,$20,$30,$20,$30,$20,$30
                 FCB    $20,$30,$20,$30,$20,$30,$20,$30
                 FCB    $20,$30,$20,$30,$20,$30,$20,$30
                 FCB    $20,$30,$20,$30,$20,$30,$20,$30
                 FCB    $20,$30,$20,$30,$20,$30,$20,$30
                 FCB    $20,$30,$20,$30,$20,$30,$20,$30
                 FCB    $20,$30,$20,$30,$20,$30,$20,$30

; =====================================================================
; DrawDirtyTiles - tile RAM emulation.  Compares arcade tile RAM
; $7400-$77FF with the copy kept in each video buffer ($F89C...).  For
; every changed tile: tile $10 = blank -> fast clear with STU; other tiles
; -> compiled tile routine (page:address from the table at $0C00 + 4*tile)
; called with JSR ,U while that page is mapped at $2000.
; =====================================================================
DrawDirtyTiles   LDY    #$7420
                 LDX    #$F89C
                 JMP    >L_5560
L_54A9           PSHS   X,Y
                 LDA    #$03
                 ASLB
                 ROLA
                 ASLB
                 ROLA
                 TFR    D,U
                 LDA    ,U
                 LDU    1,U
                 STA    >MMU_T0_P1 ; MMU_T0_P1 - Task0 page1 ($2000-$3FFF)
                 TFR    Y,D
                 ANDA   #$03
                 ASLB
                 ROLA
                 TFR    D,X
                 LDX    ,X
                 ANDB   #$3E
L_54C6           LDY    #TBL_TilePalette ; SMC: operand patched by $1740,$197B,$5395
                 LDY    B,Y
                 LDB    #$FF
                 JSR    ,U
                 PULS   X,Y
                 LDB    ,Y+
                 CMPB   ,X+
                 BNE    L_5519
L_54D9           LDD    ,Y++
                 CMPD   ,X++
                 BEQ    L_54D9
                 CMPA   -2,X
                 BEQ    L_5519
                 LEAY   -1,Y
                 LEAX   -1,X
                 LDB    -1,Y
                 BRA    L_5519
L_54EC           CMPB   #$4B
                 BCS    L_54A9
                 STX    >L_5510+1
                 LDA    #$03
                 ASLB
                 ROLA
                 ASLB
                 ROLA
                 TFR    D,U
                 LDA    ,U
                 LDU    1,U
                 STA    >MMU_T0_P1 ; MMU_T0_P1 - Task0 page1 ($2000-$3FFF)
                 TFR    Y,D
                 ANDA   #$03
                 ASLB
                 ROLA
                 TFR    D,X
                 LDX    ,X
                 LDB    #$FF
                 JSR    ,U
L_5510           LDX    #$0000 ; SMC: operand patched by $54F0
                 LDB    ,Y+
                 CMPB   ,X+
                 BEQ    L_5566
L_5519           CMPX   #$FC5C
                 BHI    L_5579
                 STB    -1,X
                 CMPB   #$10
                 BNE    L_54EC
                 STX    >L_555D+1
                 TFR    Y,D
                 ANDA   #$03
                 ASLB
                 ROLA
                 TFR    D,X
                 LDX    ,X
                 LDB    #$FF
                 LDU    #$0000
                 STU    <-128,X
                 STU    <-126,X
                 STU    ,X
                 STU    2,X
                 ABX
                 STU    <-127,X
                 STU    <-125,X
                 STU    1,X
                 STU    3,X
                 ABX
                 STU    <-126,X
                 STU    <-124,X
                 STU    2,X
                 STU    4,X
                 ABX
                 STU    <-125,X
                 STU    <-123,X
L_555D           LDX    #$0000 ; SMC: operand patched by $5524
L_5560           LDB    ,Y+
                 CMPB   ,X+
                 BNE    L_5519
L_5566           LDD    ,Y++
                 CMPD   ,X++
                 BEQ    L_5566
                 CMPA   -2,X
                 BEQ    L_5519
                 LEAY   -1,Y
                 LEAX   -1,X
                 LDB    -1,Y
                 BRA    L_5519
L_5579           LDA    #$39
                 STA    >MMU_T0_P1 ; MMU_T0_P1 - Task0 page1 ($2000-$3FFF)
                 RTS

; =====================================================================
; EraseMovedSprites: compare the arcade sprite list ($6900, 4 bytes:
; X, code, attr, Y) with the copy from the last frame; mark the tiles
; under moved sprites dirty ($4F) so DrawDirtyTiles repaints them.
; =====================================================================
EraseMovedSprites LDX    #$68FC
                 LDY    #$FC82
                 BRA    L_55B6
L_5588           LDA    ,Y
                 BEQ    L_55D5
                 ADDB   #$07
                 COMA
                 LSRA
                 LSRA
                 LSRA
                 LSRA
                 RORB
                 LSRA
                 RORB
                 LSRA
                 RORB
                 STU    ,Y
                 ADDD   #$F87A
                 TFR    D,U
                 LDA    3,X
                 STA    3,Y
                 LDD    #$4F4F
                 STD    ,U
                 STA    2,U
                 STD    <-32,U
                 STA    <-30,U
                 STD    <32,U
                 STA    <34,U
L_55B6           LEAY   4,Y
                 LEAX   4,X
                 LDU    ,X
                 CMPU   ,Y
                 BEQ    L_55C9
                 LDB    3,Y
                 CMPX   #$6A34
                 BCS    L_55CF
                 RTS
L_55C9           LDB    3,Y
                 CMPB   3,X
                 BEQ    L_55B6
L_55CF           LDA    1,Y
                 CMPA   #$70
                 BNE    L_5588
L_55D5           STU    ,Y
                 LDA    3,X
                 STA    3,Y
                 BRA    L_55B6

; =====================================================================
; DrawSprites: for each active sprite compute the screen address
; (Y*$70 + X, buffer at $8000) and call its compiled sprite routine
; (page:address from the table at $0800 + 4*code, mapped at $2000).
; =====================================================================
DrawSprites      LDY    #$68FC
                 LDD    #$FF00
                 STD    >$6A34
                 BRA    L_5614
L_55E9           LDB    3,Y
                 LDA    #$70
                 MUL
                 ADDD   #$7D30
                 ANDB   #$80
                 TFR    D,X
                 LDB    ,Y
                 ADDB   #$10
                 CMPB   #$1E
                 BCS    L_5614
                 SUBB   #$16
                 LSRB
                 ABX
                 LDB    1,Y
                 LDA    #$02
                 ASLB
                 ROLA
                 ASLB
                 ROLA
                 TFR    D,U
                 LDA    ,U
                 LDU    1,U
                 STA    >MMU_T0_P1 ; MMU_T0_P1 - Task0 page1 ($2000-$3FFF)
                 JSR    ,U
L_5614           LEAY   4,Y
                 LDA    ,Y
                 BEQ    L_5614
                 CMPA   #$FF
                 BNE    L_55E9
                 LDB    1,Y
                 BNE    L_55E9
                 LDA    #$39
                 STA    >MMU_T0_P1 ; MMU_T0_P1 - Task0 page1 ($2000-$3FFF)
                 RTS

; =====================================================================
; ReadJoystick: read the CoCo joystick through the PIA: the DAC
; ($FF20) is set to thresholds and the comparator ($FF00 bit7) is read
; with the analog mux (CA2/CB2) on each axis -> 4 direction bits + fire
; in JoyNow (previous value in JoyPrev).  Start / coin come from the
; button bits via CoinStartBits.  DAC value is restored afterwards.
; =====================================================================
ReadJoystick     ORCC   #$40
                 LDA    >PIA1_DA ; PIA1_DA
                 STA    >L_567D+1
                 LDA    #$36
                 STA    >PIA1_CB ; PIA1_CB
                 LDD    #$D8BC
                 STB    >PIA0_CA ; PIA0_CA
                 STA    >PIA1_DA ; PIA1_DA
                 LDB    #$35
                 STB    >PIA0_CB ; PIA0_CB
                 NOP
                 LDA    >PIA0_DA ; PIA0_DA
                 ANDA   #$01
                 LDB    >PIA0_DA ; PIA0_DA
                 ROLB
                 LDB    #$24
                 STB    >PIA1_DA ; PIA1_DA
                 ROLA
                 LEAX   ,X
                 LDB    >PIA0_DA ; PIA0_DA
                 ROLB
                 LDB    #$B4
                 STB    >PIA0_CA ; PIA0_CA
                 ROLA
                 LEAX   10,X
                 LEAX   -10,X
                 LEAX   ,X
                 CLR    <CoinStartBits
                 LDB    <JoyNow
                 STB    <JoyPrev
                 DEC    <VsyncCount
                 LDB    >PIA0_DA ; PIA0_DA
                 ROLB
                 LDB    #$D8
                 STB    >PIA1_DA ; PIA1_DA
                 ROLA
                 EORA   #$0B
                 LDB    >PIA0_DA ; PIA0_DA
                 ROLB
L_567D           LDB    #$00 ; SMC: operand patched by $562D
                 STB    >PIA1_DA ; PIA1_DA
                 ROLA
                 STA    <JoyNow
                 LDB    #$3E
                 STB    >PIA1_CB ; PIA1_CB
                 ANDCC  #$BF
                 LDB    >NumCredits ; credits (BCD)
                 BNE    L_56A9
                 LDB    >AttractFlag ; 1 = attract / no game
                 BEQ    L_56B7
                 LDA    <JoyPrev
                 ANDA   #$10
                 EORA   #$10
                 BEQ    L_56A2
                 LDA    <JoyNow
                 ANDA   #$10
L_56A2           ASLA
                 ASLA
                 ASLA
                 STA    <CoinStartBits
                 BRA    L_56B7
L_56A9           LDB    <JoyPrev
                 ANDB   #$10
                 BNE    L_56B7
                 LDA    <JoyNow
                 ANDA   #$10
                 LSRA
                 LSRA
                 STA    <CoinStartBits
L_56B7           RTS

; =====================================================================
; FlipDrawPage: show the buffer just drawn (GIME vertical offset)
; and map the next one of pages $30/$34/$3C at $8000-$FEFF.
; =====================================================================
FlipDrawPage     LDA    <DrawPage
                 ASLA
                 ASLA
                 STA    >GIME_VOFFLO ; GIME_VOFFLO - Video offset LSB
                 LDA    <DrawPage
                 ADDA   #$04
                 CMPA   #$38
                 BNE    L_56C9
                 ADDA   #$04
L_56C9           CMPA   #$40
                 BCS    L_56CF
                 LDA    #$30
L_56CF           STA    <DrawPage
                 STA    >MMU_T0_P4 ; MMU_T0_P4 - Task0 page4 ($8000-$9FFF)
                 INCA
                 STA    >MMU_T0_P5 ; MMU_T0_P5 - Task0 page5 ($A000-$BFFF)
                 INCA
                 STA    >MMU_T0_P6 ; MMU_T0_P6 - Task0 page6 ($C000-$DFFF)
                 INCA
                 STA    >MMU_T0_P7 ; MMU_T0_P7 - Task0 page7 ($E000-$FEFF)
                 RTS

; =====================================================================
; SoundDriver: arcade music latch $7C00 -> TBL_MusicSamples (16
; tunes x 8 bytes: page, start, loop); effect latches $7D80 (death),
; $7D04, $7D06, $7D05, $7D01 (jump), $7D02 (boom), $7D00 (walk, 4 random
; variants) -> TBL_SfxSamples (8 bytes: page, start, ..., priority).
; Patches FIRQ_SampleMixer's operands with interrupts masked.
; =====================================================================
SoundDriver      LDA    >SfxCoin
                 BEQ    L_56EA
                 LDB    #$1A
                 BRA    L_5707
L_56EA           LDB    >MusicLatch ; music latch (arcade sound CPU)
                 CMPB   #$06
                 BNE    L_56F6
                 STB    >Sfx6
                 BRA    L_5735
L_56F6           CMPB   #$0D
                 BNE    L_56FF
                 STB    >Sfx5
                 BRA    L_5735
L_56FF           CMPB   #$0A
                 BNE    L_5707
                 STB    <LastMusic
                 BRA    L_5735
L_5707           CMPB   <LastMusic
                 BEQ    L_5735
                 STB    <LastMusic
                 LDX    #TBL_MusicSamples
                 ORCC   #$40
                 ANDB   #$0F
                 BEQ    L_5729
                 ASLB
                 ASLB
                 ASLB
                 ABX
                 LDA    ,X
                 STA    <MusicPage
                 STA    >MMU_T1_P3 ; MMU_T1_P3 - Task1 page3 ($6000-$7FFF)
                 LDD    1,X
                 STD    <L_1093+1
                 LDA    6,X
                 STA    <L_10E1+1
L_5729           LDD    3,X
                 STA    <L_10ED+1
                 STB    <L_10E9+1
                 LDA    5,X
                 STA    <L_10E5+1
                 ANDCC  #$BF
L_5735           LDA    <SfxPriority
                 BEQ    L_573C
                 DECA
                 STA    <SfxPriority
L_573C           LDX    #TBL_SfxSamples
                 LDA    >SfxDeath ; death sound / sound IRQ latch
                 BEQ    L_5747
                 CLRB
                 BRA    L_5785
L_5747           LDA    >Sfx4
                 BEQ    L_5750
                 LDB    #$20
                 BRA    L_5785
L_5750           LDA    >Sfx6
                 BEQ    L_5759
                 LDB    #$30
                 BRA    L_5785
L_5759           LDA    >Sfx5
                 BEQ    L_5762
                 LDB    #$28
                 BRA    L_5785
L_5762           LDA    >SfxJump ; jump sound latch
                 BEQ    L_576B
                 LDB    #$08
                 BRA    L_5785
L_576B           LDA    >SfxBoom ; boom sound latch
                 BEQ    L_5774
                 LDB    #$10
                 BRA    L_5785
L_5774           LDA    >SfxWalk ; walk sound latch
                 BEQ    L_57BA
                 LDB    >RandNum ; random number
                 LDA    #$18
                 MUL
                 ANDA   #$18
                 LEAX   A,X
                 LDB    #$38
L_5785           CMPB   <LastSfx
                 BEQ    L_57B9
                 STB    <LastSfx
                 ABX
                 LDA    7,X
                 CMPA   <SfxPriority
                 BCS    L_57B9
                 STA    <SfxPriority
                 ORCC   #$40
                 LDA    ,X
                 STA    <SfxPage
                 STA    >MMU_T1_P4 ; MMU_T1_P4 - Task1 page4 ($8000-$9FFF)
                 LDD    1,X
                 STD    <L_1096+1
                 LDB    6,X
                 STB    <L_10AD+1
                 LDA    #$BB
                 STA    <L_1096
                 LDD    #$B7FF
                 STD    <L_1099
                 LDD    #$200A
                 STD    <L_1099+2
                 ANDCC  #$BF
                 LDA    7,X
                 STA    <SfxPriority
L_57B9           RTS
L_57BA           LDB    #$FF
                 STB    <LastSfx
                 RTS

; =====================================================================
; Effect sample table: page, start address, length/end, ..., priority.
; =====================================================================
TBL_SfxSamples   FCB    $08,$9D,$A1,$06,$80,$FF,$06,$AA
                 FCB    $18,$9B,$D2,$18,$85,$FF,$18,$1D
                 FCB    $1A,$91,$C5,$1A,$80,$FF,$1A,$0A
                 FCB    $26,$87,$B9,$26,$80,$FF,$26,$06
                 FCB    $02,$8F,$43,$01,$81,$FF,$01,$3C
                 FCB    $1B,$97,$D2,$1B,$83,$FF,$1B,$25
                 FCB    $23,$82,$9A,$22,$80,$FF,$22,$3C
                 FCB    $0F,$85,$26,$0F,$80,$FF,$0F,$01
                 FCB    $0E,$8F,$E3,$0E,$89,$FF,$0E,$01
                 FCB    $00,$8F,$FF,$00,$89,$FF,$00,$01

; =====================================================================
; Music sample table, 16 tunes x 8 bytes.
; =====================================================================
TBL_MusicSamples FCB    $2F,$7F,$00,$2F,$7F,$00,$37,$00
                 FCB    $08,$7D,$AE,$0D,$7F,$00,$0D,$00
                 FCB    $26,$68,$24,$28,$78,$00,$28,$00
                 FCB    $0E,$70,$E4,$0E,$70,$E4,$0E,$00
                 FCB    $0F,$65,$A7,$0F,$65,$A7,$11,$00
                 FCB    $12,$60,$00,$17,$7F,$00,$17,$00
                 FCB    $28,$78,$00,$28,$78,$00,$28,$00
                 FCB    $02,$6F,$74,$05,$7E,$00,$05,$00
                 FCB    $18,$7C,$D3,$18,$7C,$D3,$19,$00
                 FCB    $1A,$72,$2B,$1A,$72,$2B,$1A,$00
                 FCB    $2F,$78,$47,$2F,$7F,$00,$2F,$00
                 FCB    $00,$70,$E3,$00,$70,$E3,$00,$00
                 FCB    $1B,$78,$D3,$21,$7D,$00,$21,$00
                 FCB    $28,$78,$00,$28,$78,$00,$28,$00
                 FCB    $23,$62,$9B,$25,$7F,$00,$25,$00
                 FCB    $04,$65,$8B,$05,$7E,$00,$05,$00

; =====================================================================
; Setup: CPU to 1.79 MHz (SAM R1), HD6309 detect (CLRD leaves B=$FF on a
; 6809) -> native mode, palette (RGB or CMP per $80EB), disk motor off,
; PIA sound on, level order patch ($80EA), difficulty ($80E9), sound on/off ($80EC:
; unpack samples or silence the mixer), MMU tasks 0/1, GIME timer FIRQ
; (timer $01C8), video 256x225x16, clear the three video buffers,
; build the tile -> screen address table at $0000-$07FF, copy the
; compiled-routine pointer tables from page $29 to $0800-$0FFF.
; =====================================================================
Setup            STA    >SAM_R1SET ; SAM R1=1: 1.79 MHz CPU
                 LDB    #$FF ; 6309 test: CLRD clears B only on an HD6309
                 FCB    $10,$4F ; HD6309: CLRD
                 TSTB
                 BNE    L_589C
                 FCB    $11,$3D,$01 ; HD6309: LDMD   #$01 ; 6309 found -> native mode
L_589C           LDU    #PaletteRGB
                 TFR    U,Y
                 DEC    >CfgPalette ; CMP monitor? use the second palette set  [BASIC POKE 33003]
                 BNE    L_58A9
                 LEAU   <16,U
L_58A9           LDX    #$FFB0
                 CLRA
L_58AD           LDB    ,U+
                 STB    ,Y+
                 LEAX   1,X
                 CMPX   #$FFC0
                 BCS    L_58AD
                 STA    >GIME_BORDER ; border black  [GIME_BORDER - Border color (6-bit palette index)]
                 STA    >DSKREG ; drive motors off  [disk drive control latch]
                 LDD    #$3F7F ; PIA1 CB2 = sound enable, DAC mid-level
                 STB    >PIA1_DA ; PIA1_DA
                 STA    >PIA1_CB ; PIA1_CB
                 DEC    >CfgLevelOrder ; Japan order: copy alt. stage order over TBL_StageOrder  [BASIC POKE 33002]
                 BNE    L_58D9
                 LDX    #TBL_StageOrder
                 LDB    #$15
L_58D1           LDA    <21,X
                 STA    ,X+
                 DECB
                 BNE    L_58D1
L_58D9           DEC    >CfgDifficulty ; hard: patch RNG step and a game-speed operand  [BASIC POKE 33001]
                 BNE    L_58E7
                 LDD    #$0405 ; #4 -> $3581 operand, #5 -> RNG ADDB
                 STA    >L_3581+1
                 STB    >L_1105+1
L_58E7           LDA    >CfgLivesBonus ; BASIC POKE 33000
                 ANDA   #$F0
                 BNE    L_58F1
                 LDA    >CfgLivesBonus ; BASIC POKE 33000
L_58F1           ANDA   #$0F
                 STA    <DipConfig
                 DEC    >CfgSound ; sound off: timer reload 0 = no sample FIRQ  [BASIC POKE 33004]
                 BNE    L_5901
                 CLRA
                 CLRB
                 STD    >L_5920+1
                 BRA    L_5904
L_5901           JSR    >UnpackSamples
L_5904           LDX    #$FFB0 ; all 16 palettes black while setting up
                 LDD    #$0010
L_590A           STA    ,X+
                 DECB
                 BNE    L_590A
                 LDA    #$08 ; copy MMU task 0 map to task 1
                 LDX    #$FFA0
L_5914           LDB    ,X+
                 STB    7,X
                 DECA
                 BNE    L_5914
                 LDD    <MusicPage
                 STD    >MMU_T1_P3 ; MMU_T1_P3 - Task1 page3 ($6000-$7FFF)
L_5920           LDD    #$01C8 ; GIME timer reload (279 ns ticks: ~7.8 kHz)  [SMC: operand patched by $58FC]
                 STD    >GIME_TMRHI ; GIME_TMRHI - Timer MSB (12-bit countdown)
                 LDD    #$0E89 ; FIRQ vector $FEF4 = JMP <$89 (FIRQ_SampleMixer)
                 STD    >$FEF4
                 LDD    #$2020
                 STA    >GIME_INIT1 ; GIME_INIT1 - Init 1: timer input, task select
                 STB    >GIME_FIRQEN ; GIME_FIRQEN - FIRQ enable: TMR|HBORD|VBORD|EI2-0
                 LDA    #$5C ; MMU on, GIME FIRQ on, constant RAM at $FExx
                 STA    >GIME_INIT0 ; GIME_INIT0 - Init 0: COCO|MMUEN|IEN|FEN|MC3-0
                 LDD    #$807A ; graphics, 225 lines x 128 bytes = 256x225, 16 colours
                 STD    >GIME_VMODE ; GIME_VMODE - Video mode: BP|BPI|MOCH|H50|LPR
                 LDD    #$0000
                 STD    >GIME_HOFFHI ; GIME_HOFFHI - Horizontal offset MSB
                 LDD    #$C030
                 STA    >GIME_VOFFLO ; GIME_VOFFLO - Video offset LSB
                 STB    <DrawPage
L_594E           JSR    >FlipDrawPage
                 LDX    #$8000
                 LDU    #$0000
                 LDD    #$3940
L_595A           STU    ,X++
                 DECB
                 BNE    L_595A
                 DECA
                 BNE    L_595A
                 LDU    #$F87C
                 LDD    #$1010
L_5968           STD    ,U++
                 CMPU   #$FC7C
                 BCS    L_5968
                 LDD    #$9595
                 STD    ,U
                 LDU    #$FC86
                 LDD    #$0000
L_597B           STD    ,U++
                 CMPU   #$FDFE
                 BCS    L_597B
                 LDD    #$9595
                 STD    ,U
                 LDA    <DrawPage
                 CMPA   #$30
                 BNE    L_594E
                 LDU    #PaletteRGB
                 LDX    #$FFB0
L_5994           LDD    ,U++
                 STD    ,X++
                 CMPX   #$FFC0
                 BCS    L_5994
                 LDX    #TileRAM
                 LDY    #$0000
L_59A4           TFR    X,D
                 SUBD   #$0001
                 STB    >L_59B3+1
                 LSRA
                 RORB
                 LSRA
                 RORB
                 COMB
                 ANDB   #$F8
L_59B3           LDA    #$00 ; SMC: operand patched by $59A9
                 ANDA   #$1F
                 STA    >L_59BD+1
                 ASLA
                 ASLA
                 ASLA
L_59BD           SUBA   #$00 ; SMC: operand patched by $59B7
                 LSRA
                 RORB
                 ORA    #$80
                 ADDD   #$0080
                 STD    ,Y++
                 LEAX   1,X
                 CMPX   #$7800
                 BNE    L_59A4
                 LDA    #$29
                 STA    >MMU_T0_P1 ; MMU_T0_P1 - Task0 page1 ($2000-$3FFF)
                 LDX    #$0800
                 LDY    #$2000
L_59DB           LDD    ,Y++
                 STD    ,X++
                 CMPX   #$1000
                 BCS    L_59DB
                 LDA    #$39
                 STA    >MMU_T0_P1 ; MMU_T0_P1 - Task0 page1 ($2000-$3FFF)
                 RTS

; =====================================================================
; UnpackSamples: 1-bit delta-modulation decoder.  Each input bit
; moves the output up/down by a step that grows on repeats and shrinks on
; reversals (CVSD-like); 4 samples per byte, output clipped to 7 bits.
; Source $B800-$BFFF/$A000-$BFFF in pages $1E.., output 8K pages at
; $8000.  The border flashes while it runs ('DECOMPRESSING DATA').
; =====================================================================
UnpackSamples    LDU    #$B800
L_59ED           LDX    #$8000
                 LDD    <SndSrcPage
                 STD    >MMU_T0_P4 ; MMU_T0_P4 - Task0 page4 ($8000-$9FFF)
L_59F5           LDA    #$04
                 STA    <BitCount
                 LDA    ,U+
L_59FB           LDB    #$80 ; SMC: operand patched by L_5A46
                 ROLA
                 BCC    L_5A10
                 ADDB   <DeltaStep
                 CLR    <DeltaLo
                 TST    <DeltaHi
                 BNE    L_5A1E
                 STB    <DeltaHi
                 DEC    <DeltaStep
                 BNE    L_5A20
                 BRA    L_5A1E
L_5A10           SUBB   <DeltaStep
                 CLR    <DeltaHi
                 TST    <DeltaLo
                 BNE    L_5A1E
                 STB    <DeltaLo
                 DEC    <DeltaStep
                 BNE    L_5A20
L_5A1E           INC    <DeltaStep
L_5A20           STB    >L_5A4B+1
                 ROLA
                 BCC    L_5A36
                 ADDB   <DeltaStep
                 CLR    <DeltaLo
                 TST    <DeltaHi
                 BNE    L_5A44
                 STB    <DeltaHi
                 DEC    <DeltaStep
                 BNE    L_5A46
                 BRA    L_5A44
L_5A36           SUBB   <DeltaStep
                 CLR    <DeltaHi
                 TST    <DeltaLo
                 BNE    L_5A44
                 STB    <DeltaLo
                 DEC    <DeltaStep
                 BNE    L_5A46
L_5A44           INC    <DeltaStep
L_5A46           STB    >L_59FB+1
                 LSRB
                 LSRB
L_5A4B           ADDB   #$80 ; SMC: operand patched by L_5A20
                 RORB
                 SUBB   #$2E
                 BCC    L_5A53
                 CLRB
L_5A53           ASLB
                 BPL    L_5A58
                 LDB    #$7F
L_5A58           STB    ,X+
                 STB    >GIME_BORDER ; GIME_BORDER - Border color (6-bit palette index)
                 DEC    <BitCount
                 BNE    L_59FB
                 CMPX   #$A000
                 BCS    L_59F5
                 INC    <SndSrcPage
                 LDA    <SndSrcPage
                 CMPA   #$29
                 BEQ    L_5A7E
                 CMPU   #$C000
                 LBCS   L_59ED
                 LDU    #$A000
                 INC    <SndSrcPage2
                 JMP    >L_59ED
L_5A7E           CLR    >GIME_BORDER ; GIME_BORDER - Border color (6-bit palette index)
                 LDD    #$262F
                 STD    >MMU_T0_P4 ; MMU_T0_P4 - Task0 page4 ($8000-$9FFF)
                 LDX    #$8000
                 LDY    #$C000
L_5A8E           LDA    ,X+
                 STA    ,-Y
                 CMPX   #$87BA
                 BCS    L_5A8E
                 RTS

; =====================================================================
; Palettes: 16 GIME colours for RGB monitors, then 16 for composite.
; =====================================================================
PaletteRGB       FCB    $00,$00,$08
D_5A9B           FCB    $09,$12
D_5A9D           FCB    $1B
D_5A9E           FCB    $20,$22,$39,$24
D_5AA2           FCB    $25,$26,$2E,$34,$35,$3F,$00,$00
                 FCB    $10,$1B,$21,$3D,$16,$14,$3B,$17
                 FCB    $27,$26,$28,$34,$35,$3F

        END    ColdStart
