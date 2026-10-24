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
  1019  FC 86             FCB    $FC,$86
JoyPrev:
  101B  00                FCB    $00
JoyNow:
  101C  00                FCB    $00
JoyP2:
  101D  00                FCB    $00
CoinStartBits:
  101E  00                FCB    $00
DipConfig:
  101F  80                FCB    $80
VsyncCount:
  1020  00                FCB    $00
FrameSkip:
  1021  00                FCB    $00
LoopCount:
  1022  00                FCB    $00
DrawPage:
  1023  30                FCB    $30
DeltaHi:
  1024  00                FCB    $00
DeltaLo:
  1025  00                FCB    $00
DeltaStep:
  1026  01                FCB    $01
SndSrcPage:
  1027  00                FCB    $00
SndSrcPage2:
  1028  1E                FCB    $1E
BitCount:
  1029  04                FCB    $04
LastMusic:
  102A  00                FCB    $00
LastSfx:
  102B  FF                FCB    $FF
SfxPriority:
  102C  00                FCB    $00
MusicPage:
  102D  04                FCB    $04
SfxPage:
  102E  00                FCB    $00

; =====================================================================
; Z80 RST equivalents, called with 2-byte JSR <xx.
; RST_RetIfAttract: if $6007 bit0 (attract / no credit) => return from
; the CALLER as well (LEAS 2,S ; RTS) - the Z80 'pop hl ; ret' trick.
; =====================================================================
RST_RetIfAttract:
  102F  F6 60 07          LDB    >AttractFlag            ; 1 = attract / no game
  1032  54                LSRB
  1033  24 02             BCC    L_1037
L_1035:
  1035  32 62             LEAS   2,S
L_1037:
  1037  39                RTS

; =====================================================================
; RST_RetIfMarioDead: return from caller unless $6200 (Mario alive) bit0.
; =====================================================================
RST_RetIfMarioDead:
  1038  F6 62 00          LDB    >MarioAlive             ; bit0 = Mario alive
  103B  54                LSRB
  103C  24 F7             BCC    L_1035
  103E  39                RTS

; =====================================================================
; RST_WaitTimer: DEC $6009 ; return from caller until it reaches 0.
; =====================================================================
RST_WaitTimer:
  103F  8E 60 09          LDX    #WaitTimer
  1042  6A 84             DEC    ,X
  1044  26 EF             BNE    L_1035
  1046  39                RTS

; =====================================================================
; RST_JumpTable (Z80 RST 28h): B = index, the FDB table follows the
; calling JSR.  Pulls the return address as table base and jumps.
; =====================================================================
RST_JumpTable:
  1047  58                ASLB
  1048  35 10             PULS   X
  104A  3A                ABX
  104B  AE 80             LDX    ,X+
  104D  6E 84             JMP    ,X

; =====================================================================
; RST_AddToObjects: add C (<$03) to byte ,X of 10 objects, stride 4.
; =====================================================================
RST_AddToObjects:
  104F  10 8E 00 04       LDY    #$0004
  1053  86 0A             LDA    #$0A
  1055  97 02             STA    <$02

; =====================================================================
; RST_AddToObjectsB (7 instructions)
; =====================================================================
RST_AddToObjectsB:
  1057  D6 03             LDB    <$03
  1059  EB 84             ADDB   ,X
  105B  E7 84             STB    ,X
  105D  30 04             LEAX   4,X
  105F  0A 02             DEC    <$02
  1061  26 F4             BNE    RST_AddToObjectsB
L_1063:
  1063  39                RTS

; =====================================================================
; RST_RetIfNotScreen: B = bitmask of stages (bit0 = screen 1 ...).
; Rotates B by the current screen $6227; returns from the caller when the
; current screen is not in the mask.
; =====================================================================
RST_RetIfNotScreen:
  1064  8E 62 27          LDX    #ScreenNum
  1067  A6 84             LDA    ,X
L_1069:
  1069  54                LSRB
  106A  24 02             BCC    L_106E
  106C  CA 80             ORB    #$80
L_106E:
  106E  4A                DECA
  106F  26 F8             BNE    L_1069
  1071  97 02             STA    <$02
  1073  25 EE             BCS    L_1063
  1075  35 90             PULS   X,PC

; =====================================================================
; RST_CopySprites: copy 20 words from X to the sprite buffer $6908.
; =====================================================================
RST_CopySprites:
  1077  10 8E 69 08       LDY    #$6908
  107B  86 14             LDA    #$14
  107D  DF 08             STU    <$08
L_107F:
  107F  EE 81             LDU    ,X++
  1081  EF A1             STU    ,Y++
  1083  4A                DECA
  1084  26 F9             BNE    L_107F
  1086  DE 08             LDU    <$08
  1088  39                RTS

; =====================================================================
; FIRQ_SampleMixer - GIME timer FIRQ (~7.8 kHz, vector $FEF4 = JMP <$89).
; Switches to MMU task 1 so the music sample page appears at $6000 and the
; effect page at $8000, adds one music byte + one effect byte and writes
; the sum to the DAC ($FF20).  Both sample pointers live in the operands of
; the LDA/ADDA below and are advanced in place.  When the effect ends the
; ADDA is patched into a harmless instruction.  A is saved in the operand
; of the final LDA #.
; =====================================================================
FIRQ_SampleMixer:
  1089  97 FA             STA    <L_10F9+1
  108B  B6 FF 93          LDA    >GIME_FIRQEN            ; GIME_FIRQEN - FIRQ enable: TMR|HBORD|VBORD|EI2-0
  108E  86 21             LDA    #$21
  1090  B7 FF 91          STA    >GIME_INIT1             ; GIME_INIT1 - Init 1: timer input, task select
L_1093:
  1093  B6 65 8B          LDA    >$658B                  ; SMC: operand patched by L_10D2,$10D6,$10DC,$10E7,$10EB,$5723
L_1096:
  1096  BB 89 FF          ADDA   >$89FF                  ; SMC: operand patched by L_109C,$10A0,$10A2,$10A8,$10B7,$10BB,$579F
L_1099:
  1099  B7 FF 20          STA    >PIA1_DA                ; SMC: operand patched by $10C3,$10C7,$57B1; PIA1_DA
L_109C:
  109C  0A 98             DEC    <L_1096+2
  109E  22 32             BHI    L_10D2
  10A0  0A 98             DEC    <L_1096+2
  10A2  0A 97             DEC    <L_1096+1
  10A4  2B 2C             BMI    L_10D2
  10A6  86 9F             LDA    #$9F
  10A8  97 97             STA    <L_1096+1
  10AA  96 2E             LDA    <SfxPage
  10AC  4A                DECA
L_10AD:
  10AD  81 00             CMPA   #$00                    ; SMC: operand patched by $57A3
  10AF  2C 1C             BGE    L_10CD
  10B1  86 8B             LDA    #$8B
  10B3  97 96             STA    <L_1096
  10B5  86 44             LDA    #$44
  10B7  97 97             STA    <L_1096+1
  10B9  86 B7             LDA    #$B7
  10BB  97 98             STA    <L_1096+2
  10BD  86 FF             LDA    #$FF
  10BF  97 99             STA    <L_1099
  10C1  86 20             LDA    #$20
  10C3  97 9A             STA    <L_1099+1
  10C5  86 0E             LDA    #$0E
  10C7  97 9B             STA    <L_1099+2
  10C9  86 D2             LDA    #$D2
  10CB  97 9C             STA    <L_109C
L_10CD:
  10CD  B7 FF AC          STA    >MMU_T1_P4              ; MMU_T1_P4 - Task1 page4 ($8000-$9FFF)
  10D0  97 2E             STA    <SfxPage
L_10D2:
  10D2  0C 95             INC    <L_1093+2
  10D4  26 1E             BNE    L_10F4
  10D6  0C 94             INC    <L_1093+1
  10D8  2A 1A             BPL    L_10F4
  10DA  86 60             LDA    #$60
  10DC  97 94             STA    <L_1093+1
  10DE  96 2D             LDA    <MusicPage
  10E0  4C                INCA
L_10E1:
  10E1  81 05             CMPA   #$05                    ; SMC: operand patched by $5727
  10E3  23 0A             BLS    L_10EF
L_10E5:
  10E5  86 00             LDA    #$00                    ; SMC: operand patched by $5731
  10E7  97 95             STA    <L_1093+2
L_10E9:
  10E9  86 7E             LDA    #$7E                    ; SMC: operand patched by $572D
  10EB  97 94             STA    <L_1093+1
L_10ED:
  10ED  86 05             LDA    #$05                    ; SMC: operand patched by $572B
L_10EF:
  10EF  B7 FF AB          STA    >MMU_T1_P3              ; MMU_T1_P3 - Task1 page3 ($6000-$7FFF)
  10F2  97 2D             STA    <MusicPage
L_10F4:
  10F4  86 20             LDA    #$20
  10F6  B7 FF 91          STA    >GIME_INIT1             ; GIME_INIT1 - Init 1: timer input, task select
L_10F9:
  10F9  86 00             LDA    #$00                    ; SMC: operand patched by FIRQ_SampleMixer
  10FB  3B                RTI

; =====================================================================
; UpdateRandom: $6018 += $601A + $6019 (arcade RNG).
; =====================================================================
UpdateRandom:
  10FC  F6 60 18          LDB    >RandNum                ; random number
  10FF  FB 60 1A          ADDB   >FrameCounter           ; decremented every frame
  1102  FB 60 19          ADDB   >RandTimer
L_1105:
  1105  CB 00             ADDB   #$00                    ; difficulty: 0 easy / 5 hard (patched by Setup)  [SMC: operand patched by $58E4]
  1107  F7 60 18          STB    >RandNum                ; random number
  110A  39                RTS

; =====================================================================
; MinorTimerWait: DEC $6008; when 0 fall into RST_WaitTimer, else
; return from caller.
; =====================================================================
MinorTimerWait:
  110B  7A 60 08          DEC    >MinorTimer
  110E  26 02             BNE    L_1112
  1110  0E 3F             JMP    <RST_WaitTimer
L_1112:
  1112  35 90             PULS   X,PC

; =====================================================================
; ColdStart - EXEC entry.  Interrupts off, DP=$10.
; =====================================================================
ColdStart:
  1114  1A 50             ORCC   #$50                    ; mask IRQ+FIRQ
  1116  C6 10             LDB    #$10
  1118  1F 9B             TFR    B,DP                    ; DP = $10 (Z80 register file)
  111A  7E 12 ED          JMP    >Reset

; =====================================================================
; ArcadeVBlank - the translated arcade NMI (vertical blank) routine.
; Builds the input byte $6010/$6011 from the CoCo joystick (P1 or P2),
; updates RNG and sound latches, handles coins, then dispatches the game
; mode $6005 through RST_JumpTable:
;   0 Mode0_Init  1 Mode1_Attract  2 Mode2_Credited  3 Mode3_Game
; =====================================================================
ArcadeVBlank:
  111D  DC 02             LDD    <$02
  111F  9E 0A             LDX    <$0A
  1121  34 16             PSHS   A,B,X
  1123  F6 60 07          LDB    >AttractFlag            ; 1 = attract / no game
  1126  26 26             BNE    L_114E
  1128  F6 60 26          LDB    >DipCabinet
  112B  26 07             BNE    L_1134
  112D  96 1D             LDA    <JoyP2
  112F  F6 60 0E          LDB    >Player2Ctrl
  1132  26 02             BNE    L_1136
L_1134:
  1134  96 1C             LDA    <JoyNow
L_1136:
  1136  97 02             STA    <$02
  1138  84 0F             ANDA   #$0F
  113A  97 03             STA    <$03
  113C  B6 60 11          LDA    >InputPrev
  113F  43                COMA
  1140  94 02             ANDA   <$02
  1142  84 10             ANDA   #$10
  1144  48                ASLA
  1145  49                ROLA
  1146  49                ROLA
  1147  9A 03             ORA    <$03
  1149  D6 02             LDB    <$02
  114B  FD 60 10          STD    >InputState             ; joystick+jump, bit7 = jump edge
L_114E:
  114E  7A 60 1A          DEC    >FrameCounter           ; decremented every frame
  1151  8D A9             BSR    UpdateRandom
  1153  BD 11 D2          JSR    >CoinHandler
  1156  8D 19             BSR    SoundLatchUpdate
  1158  8E 11 6A          LDX    #L_116A
  115B  34 10             PSHS   X
  115D  F6 60 05          LDB    >GameMode               ; 0 init, 1 attract, 2 credited, 3 game
  1160  9D 47             JSR    <RST_JumpTable          ; game mode
TBL_GameMode:
  1162  12 32             FDB    Mode0_Init              ; 0
  1164  18 8A             FDB    Mode1_Attract           ; 1
  1166  1A 3B             FDB    Mode2_Credited          ; 2
  1168  18 55             FDB    Mode3_Game              ; 3
L_116A:
  116A  35 16             PULS   A,B,X
  116C  9F 0A             STX    <$0A
  116E  DD 02             STD    <$02
  1170  39                RTS

; =====================================================================
; SoundLatchUpdate: arcade sound buffer $6080-$6087 => latches
; $7D00-$7D07 (1 while the duration counter is non-zero), $608A/$608B
; => music latch $7C00, $6088 => death sound $7D80.
; =====================================================================
SoundLatchUpdate:
  1171  8E 60 80          LDX    #SndWalk
  1174  10 8E 7D 00       LDY    #SfxWalk
  1178  F6 60 07          LDB    >AttractFlag            ; 1 = attract / no game
  117B  26 33             BNE    L_11B0
  117D  86 08             LDA    #$08
L_117F:
  117F  E6 84             LDB    ,X
  1181  27 04             BEQ    L_1187
  1183  6A 84             DEC    ,X
  1185  C6 01             LDB    #$01
L_1187:
  1187  E7 A0             STB    ,Y+
  1189  30 01             LEAX   1,X
  118B  4A                DECA
  118C  26 F1             BNE    L_117F
  118E  97 02             STA    <$02
  1190  8E 60 8B          LDX    #MusicCur
  1193  E6 84             LDB    ,X
  1195  26 04             BNE    L_119B
  1197  E6 83             LDB    ,--X
  1199  20 04             BRA    L_119F
L_119B:
  119B  6A 84             DEC    ,X
  119D  E6 82             LDB    ,-X
L_119F:
  119F  F7 7C 00          STB    >MusicLatch             ; music latch (arcade sound CPU)
  11A2  8E 60 88          LDX    #SndDeath
  11A5  5F                CLRB
  11A6  E1 84             CMPB   ,X
  11A8  27 03             BEQ    L_11AD
  11AA  6A 84             DEC    ,X
  11AC  5C                INCB
L_11AD:
  11AD  F7 7D 80          STB    >SfxDeath               ; death sound / sound IRQ latch
L_11B0:
  11B0  39                RTS

; =====================================================================
; SoundReset: clear all sound latches and the sound buffer.
; =====================================================================
SoundReset:
  11B1  86 08             LDA    #$08
  11B3  5F                CLRB
  11B4  8E 7D 00          LDX    #SfxWalk
  11B7  10 8E 60 80       LDY    #SndWalk
L_11BB:
  11BB  E7 80             STB    ,X+
  11BD  E7 A0             STB    ,Y+
  11BF  4A                DECA
  11C0  26 F9             BNE    L_11BB
  11C2  86 04             LDA    #$04
L_11C4:
  11C4  E7 A0             STB    ,Y+
  11C6  4A                DECA
  11C7  26 FB             BNE    L_11C4
  11C9  97 02             STA    <$02
  11CB  F7 7D 80          STB    >SfxDeath               ; death sound / sound IRQ latch
  11CE  F7 7C 00          STB    >MusicLatch             ; music latch (arcade sound CPU)
  11D1  39                RTS

; =====================================================================
; CoinHandler: CoinStartBits bit7 = coin.  Flashes palette 3/5, plays
; the coin sound, counts coins against $6024 (coins per credit) and adds
; one BCD credit to $6001 (max 90), then queues Task4 (show credits).
; =====================================================================
CoinHandler:
  11D2  D6 1E             LDB    <CoinStartBits
  11D4  8E 60 03          LDX    #CoinSwitch
  11D7  5D                TSTB
  11D8  2B 05             BMI    L_11DF
  11DA  86 01             LDA    #$01
  11DC  A7 84             STA    ,X
  11DE  39                RTS
L_11DF:
  11DF  B6 5A 9B          LDA    >D_5A9B
  11E2  F6 5A 9D          LDB    >D_5A9D
  11E5  B7 FF B3          STA    >PAL_3                  ; PAL_3 - Palette 3 (6-bit RGB)
  11E8  F7 FF B5          STB    >PAL_5                  ; PAL_5 - Palette 5 (6-bit RGB)
  11EB  E6 84             LDB    ,X
  11ED  27 39             BEQ    L_1228
  11EF  34 10             PSHS   X
  11F1  F6 60 05          LDB    >GameMode               ; 0 init, 1 attract, 2 credited, 3 game
  11F4  C1 03             CMPB   #$03
  11F6  27 08             BEQ    L_1200
  11F8  BD 11 B1          JSR    >SoundReset
  11FB  C6 03             LDB    #$03
  11FD  F7 60 83          STB    >SndCoin
L_1200:
  1200  35 10             PULS   X
  1202  6F 84             CLR    ,X
  1204  6C 82             INC    ,-X
  1206  10 8E 60 24       LDY    #DipCoinsPerCredit
  120A  E6 A4             LDB    ,Y
  120C  E0 84             SUBB   ,X
  120E  26 18             BNE    L_1228
  1210  E7 84             STB    ,X
  1212  31 21             LEAY   1,Y
  1214  1E 21             EXG    Y,X
  1216  A6 A2             LDA    ,-Y
  1218  81 90             CMPA   #$90
  121A  24 0C             BCC    L_1228
  121C  AB 84             ADDA   ,X
  121E  19                DAA
  121F  A7 A4             STA    ,Y
  1221  10 8E 04 00       LDY    #$0400                  ; queue ShowCredits(0)
  1225  BD 45 21          JSR    >AddTask
L_1228:
  1228  39                RTS
D_1229:
  1229  00 37 00 AA AA    FCB    $00,$37,$00,$AA,$AA
D_122E:
  122E  AA 50 76 00       FCB    $AA,$50,$76,$00

; =====================================================================
; Mode0_Init: clear scores, set attract flag, read DIP settings,
; queue HIGH SCORE strings and score displays, go to mode 1.
; =====================================================================
Mode0_Init:
  1232  BD 19 F9          JSR    >ClearPlayfield
  1235  8E 12 29          LDX    #D_1229
  1238  10 8E 60 B2       LDY    #ScoreP1
  123C  C6 09             LDB    #$09
L_123E:
  123E  A6 80             LDA    ,X+
  1240  A7 A0             STA    ,Y+
  1242  5A                DECB
  1243  26 F9             BNE    L_123E
  1245  C6 01             LDB    #$01
  1247  F7 60 07          STB    >AttractFlag            ; 1 = attract / no game
  124A  F7 62 29          STB    >Level                  ; level number
  124D  F7 62 28          STB    >Lives                  ; lives left
  1250  BD 18 01          JSR    >Task6_ShowLivesLevel
  1253  8D 28             BSR    ReadDipSettings
  1255  C6 01             LDB    #$01
  1257  F7 7D 82          STB    >FlipScreen             ; flip screen
  125A  F7 60 05          STB    >GameMode               ; 0 init, 1 attract, 2 credited, 3 game
  125D  F7 62 27          STB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  1260  5F                CLRB
  1261  F7 60 0A          STB    >GameState              ; sub-state of GameMode
  1264  BD 1C 1F          JSR    >Draw1UP
  1267  10 8E 03 04       LDY    #$0304                  ; show "HIGH SCORE"
  126B  BD 45 21          JSR    >AddTask
  126E  10 8E 02 02       LDY    #$0202                  ; queue ShowScore(2)
  1272  BD 45 21          JSR    >AddTask
  1275  10 8E 02 00       LDY    #$0200                  ; queue ShowScore(0)
  1279  BD 45 21          JSR    >AddTask
  127C  39                RTS

; =====================================================================
; ReadDipSettings: build the arcade DIP switch values from DipConfig
; (set from the BASIC menu): $6020 lives (3-6), $6021 bonus life
; (BCD 07/10/15/20 thousand), $6022-$6025 coin/credit ratios,
; $6026 cabinet; copy the default high-score table to $6100.
; =====================================================================
ReadDipSettings:
  127D  D6 1F             LDB    <DipConfig
  127F  D7 03             STB    <$03
  1281  8E 60 20          LDX    #DipLives
  1284  C4 03             ANDB   #$03
  1286  CB 03             ADDB   #$03
  1288  E7 80             STB    ,X+
  128A  D6 03             LDB    <$03
  128C  56                RORB
  128D  56                RORB
  128E  86 07             LDA    #$07
  1290  C4 03             ANDB   #$03
  1292  27 08             BEQ    L_129C
  1294  86 05             LDA    #$05
L_1296:
  1296  8B 05             ADDA   #$05
  1298  19                DAA
  1299  5A                DECB
  129A  26 FA             BNE    L_1296
L_129C:
  129C  A7 80             STA    ,X+
  129E  D6 03             LDB    <$03
  12A0  DF 08             STU    <$08
  12A2  CE 01 01          LDU    #$0101
  12A5  DF 02             STU    <$02
  12A7  CE 01 02          LDU    #$0102
  12AA  DF 04             STU    <$04
  12AC  C4 70             ANDB   #$70
  12AE  58                ASLB
  12AF  59                ROLB
  12B0  59                ROLB
  12B1  59                ROLB
  12B2  27 14             BEQ    L_12C8
  12B4  25 09             BCS    L_12BF
  12B6  5C                INCB
  12B7  D7 03             STB    <$03
  12B9  96 04             LDA    <$04
  12BB  97 05             STA    <$05
  12BD  20 09             BRA    L_12C8
L_12BF:
  12BF  CB 02             ADDB   #$02
  12C1  D7 02             STB    <$02
  12C3  D7 04             STB    <$04
  12C5  58                ASLB
  12C6  D7 05             STB    <$05
L_12C8:
  12C8  DE 04             LDU    <$04
  12CA  EF 81             STU    ,X++
  12CC  DE 02             LDU    <$02
  12CE  EF 81             STU    ,X++
  12D0  D6 1F             LDB    <DipConfig
  12D2  59                ROLB
  12D3  C6 01             LDB    #$01
  12D5  25 01             BCS    L_12D8
  12D7  5A                DECB
L_12D8:
  12D8  E7 84             STB    ,X
  12DA  8E 49 81          LDX    #DefaultHiScores
  12DD  10 8E 61 00       LDY    #HiScoreTable
  12E1  86 55             LDA    #$55
L_12E3:
  12E3  EE 81             LDU    ,X++
  12E5  EF A1             STU    ,Y++
  12E7  4A                DECA
  12E8  26 F9             BNE    L_12E3
  12EA  DE 08             LDU    <$08
  12EC  39                RTS

; =====================================================================
; Reset: stack at $6C00, Setup (GIME / MMU / sound / video), clear
; arcade RAM $6000-$6FFF, sprite RAM $7000, tile RAM $7400 (tile $10 =
; blank), task queue $60C0 = $FF, install IRQ code at $FEF7:
;    LDA $FF02 / INC <$20 / RTI    (60 Hz VSYNC counter)
; =====================================================================
Reset:
  12ED  10 CE 6C 00       LDS    #$6C00                  ; arcade stack top
  12F1  BD 58 8F          JSR    >Setup
  12F4  86 10             LDA    #$10
  12F6  97 02             STA    <$02
  12F8  8E 60 00          LDX    #$6000
  12FB  5F                CLRB
L_12FC:
  12FC  4F                CLRA
L_12FD:
  12FD  E7 80             STB    ,X+
  12FF  4A                DECA
  1300  26 FB             BNE    L_12FD
  1302  0A 02             DEC    <$02
  1304  26 F6             BNE    L_12FC
  1306  86 04             LDA    #$04
  1308  97 02             STA    <$02
  130A  8E 70 00          LDX    #SpriteRAM
L_130D:
  130D  4F                CLRA
L_130E:
  130E  E7 80             STB    ,X+
  1310  4A                DECA
  1311  26 FB             BNE    L_130E
  1313  0A 02             DEC    <$02
  1315  26 F6             BNE    L_130D
  1317  86 04             LDA    #$04
  1319  97 02             STA    <$02
  131B  C6 10             LDB    #$10
  131D  8E 74 00          LDX    #TileRAM
L_1320:
  1320  4F                CLRA
L_1321:
  1321  E7 80             STB    ,X+
  1323  4A                DECA
  1324  26 FB             BNE    L_1321
  1326  0A 02             DEC    <$02
  1328  26 F6             BNE    L_1320
  132A  8E 60 C0          LDX    #TaskQueue
  132D  86 40             LDA    #$40
  132F  C6 FF             LDB    #$FF
L_1331:
  1331  E7 80             STB    ,X+
  1333  4A                DECA
  1334  26 FB             BNE    L_1331
  1336  C6 C0             LDB    #$C0
  1338  F7 60 B0          STB    >TaskWrPtr              ; task queue write ptr (low byte)
  133B  F7 60 B1          STB    >TaskRdPtr              ; task queue read ptr (low byte)
  133E  5F                CLRB
  133F  F7 7D 83          STB    >SpriteBank
  1342  F7 7D 86          STB    >PaletteBank0           ; palette bank bit 0
  1345  F7 7D 87          STB    >PaletteBank1           ; palette bank bit 1
  1348  BD 53 66          JSR    >PaletteBankUpdate
  134B  5C                INCB
  134C  F7 7D 82          STB    >FlipScreen             ; flip screen
  134F  BD 11 B1          JSR    >SoundReset
  1352  8E FE F7          LDX    #$FEF7                  ; IRQ vector $FEF7:
  1355  CC B6 FF          LDD    #$B6FF
  1358  ED 81             STD    ,X++
  135A  CC 02 0C          LDD    #$020C
  135D  ED 81             STD    ,X++
  135F  CC 20 3B          LDD    #$203B
  1362  ED 84             STD    ,X
  1364  C6 35             LDB    #$35                    ; PIA0 CB1 VSYNC IRQ on
  1366  F7 FF 03          STB    >PIA0_CB                ; PIA0_CB
  1369  1C AF             ANDCC  #$AF                    ; interrupts on
  136B  86 01             LDA    #$01
  136D  97 20             STA    <VsyncCount

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
MainLoop:
  136F  0C 22             INC    <LoopCount
  1371  96 22             LDA    <LoopCount
  1373  84 07             ANDA   #$07
  1375  27 25             BEQ    L_139C
  1377  96 20             LDA    <VsyncCount
  1379  27 21             BEQ    L_139C
  137B  0A 21             DEC    <FrameSkip
  137D  27 04             BEQ    L_1383
  137F  81 02             CMPA   #$02
  1381  22 10             BHI    L_1393
L_1383:
  1383  BD 55 7F          JSR    >EraseMovedSprites
  1386  BD 54 9F          JSR    >DrawDirtyTiles
  1389  BD 55 DD          JSR    >DrawSprites
  138C  BD 56 B8          JSR    >FlipDrawPage
  138F  86 07             LDA    #$07
  1391  97 21             STA    <FrameSkip
L_1393:
  1393  BD 56 28          JSR    >ReadJoystick
  1396  BD 56 E1          JSR    >SoundDriver
  1399  BD 11 1D          JSR    >ArcadeVBlank
L_139C:
  139C  86 60             LDA    #$60
  139E  F6 60 B1          LDB    >TaskRdPtr              ; task queue read ptr (low byte)
  13A1  1F 01             TFR    D,X
  13A3  E6 84             LDB    ,X
  13A5  58                ASLB
  13A6  24 1C             BCC    TaskDispatch
  13A8  8D 51             BSR    Blink1UP
  13AA  BD 14 47          JSR    >CheckExtraLife
  13AD  7C 60 19          INC    >RandTimer
  13B0  8E 63 83          LDX    #$6383
  13B3  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  13B6  E1 84             CMPB   ,X
  13B8  27 B5             BEQ    MainLoop
  13BA  E7 84             STB    ,X
  13BC  BD 14 77          JSR    >UpdateDifficulty
  13BF  BD 14 A9          JSR    >SUB_14A9
  13C2  20 AB             BRA    MainLoop

; =====================================================================
; TaskDispatch: queue entry = task number (low 5 bits), parameter.
; Return address is MainLoop.
; =====================================================================
TaskDispatch:
  13C4  C4 1F             ANDB   #$1F
  13C6  4F                CLRA
  13C7  1F 02             TFR    D,Y
  13C9  86 FF             LDA    #$FF
  13CB  A7 80             STA    ,X+
  13CD  E6 84             LDB    ,X
  13CF  D7 03             STB    <$03
  13D1  A7 80             STA    ,X+
  13D3  1F 10             TFR    X,D
  13D5  C1 C0             CMPB   #$C0
  13D7  24 02             BCC    L_13DB
  13D9  C6 C0             LDB    #$C0
L_13DB:
  13DB  F7 60 B1          STB    >TaskRdPtr              ; task queue read ptr (low byte)
  13DE  D6 03             LDB    <$03
  13E0  8E 13 6F          LDX    #MainLoop
  13E3  34 10             PSHS   X
  13E5  31 A9 13 ED       LEAY   >TBL_Tasks,Y
  13E9  AE A4             LDX    ,Y
  13EB  6E 84             JMP    ,X

; =====================================================================
; Task table (queued with AddTask, Y = task:param).
; =====================================================================
TBL_Tasks:
  13ED  16 30             FDB    Task0_AddScore
  13EF  16 BC             FDB    Task1_ClearScore
  13F1  16 E7             FDB    Task2_ShowScore
  13F3  17 0B             FDB    Task3_ShowString
  13F5  17 36             FDB    Task4_ShowCredits
  13F7  17 54             FDB    Task5_BonusTimer
  13F9  18 01             FDB    Task6_ShowLivesLevel

; =====================================================================
; Blink1UP: every 16 frames toggles the '1UP' / '2UP' indicator.
; =====================================================================
Blink1UP:
  13FB  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  13FE  D7 02             STB    <$02
  1400  C4 0F             ANDB   #$0F
  1402  26 38             BNE    L_143C
  1404  9D 2F             JSR    <RST_RetIfAttract
  1406  F6 60 0D          LDB    >PlayerUp               ; 0 = player 1, 1 = player 2
  1409  8D 32             BSR    PlayerUpVramAddr
  140B  96 02             LDA    <$02
  140D  84 10             ANDA   #$10
  140F  27 1A             BEQ    L_142B
  1411  C6 10             LDB    #$10
  1413  E7 84             STB    ,X
  1415  30 88 E0          LEAX   <-32,X
  1418  E7 84             STB    ,X
  141A  30 88 E0          LEAX   <-32,X
  141D  E7 84             STB    ,X
  141F  F6 60 0F          LDB    >TwoPlayers
  1422  27 18             BEQ    L_143C
  1424  F6 60 0D          LDB    >PlayerUp               ; 0 = player 1, 1 = player 2
  1427  C8 01             EORB   #$01
  1429  8D 12             BSR    PlayerUpVramAddr
L_142B:
  142B  5C                INCB
  142C  E7 84             STB    ,X
  142E  30 88 E0          LEAX   <-32,X
  1431  86 25             LDA    #$25
  1433  A7 84             STA    ,X
  1435  30 88 E0          LEAX   <-32,X
  1438  86 20             LDA    #$20
  143A  A7 84             STA    ,X
L_143C:
  143C  39                RTS

; =====================================================================
; PlayerUpVramAddr (5 instructions)
; Uses:  $7740 $74E0
; =====================================================================
PlayerUpVramAddr:
  143D  8E 77 40          LDX    #$7740
  1440  5D                TSTB
  1441  27 F9             BEQ    L_143C
  1443  8E 74 E0          LDX    #$74E0
  1446  39                RTS

; =====================================================================
; CheckExtraLife: compare the current player's score with the bonus
; threshold $6021 and award one life ($6228) once ($622D).
; =====================================================================
CheckExtraLife:
  1447  F6 62 2D          LDB    >$622D
  144A  26 F0             BNE    L_143C
  144C  8E 60 B3          LDX    #$60B3
  144F  F6 60 0D          LDB    >PlayerUp               ; 0 = player 1, 1 = player 2
  1452  27 03             BEQ    L_1457
  1454  8E 60 B6          LDX    #$60B6
L_1457:
  1457  E6 80             LDB    ,X+
  1459  A6 84             LDA    ,X
  145B  44                LSRA
  145C  56                RORB
  145D  44                LSRA
  145E  56                RORB
  145F  44                LSRA
  1460  56                RORB
  1461  44                LSRA
  1462  56                RORB
  1463  8E 60 21          LDX    #DipBonusLife
  1466  E1 84             CMPB   ,X
  1468  25 D2             BCS    L_143C
  146A  C6 01             LDB    #$01
  146C  F7 62 2D          STB    >$622D
  146F  8E 62 28          LDX    #Lives
  1472  6C 84             INC    ,X
  1474  7E 18 01          JMP    >Task6_ShowLivesLevel

; =====================================================================
; UpdateDifficulty: internal difficulty $6380 from level $6229 and time.
; =====================================================================
UpdateDifficulty:
  1477  8E 63 84          LDX    #$6384
  147A  E6 84             LDB    ,X
  147C  6C 84             INC    ,X
  147E  5D                TSTB
  147F  26 27             BNE    L_14A8
  1481  8E 63 81          LDX    #$6381
  1484  A6 84             LDA    ,X
  1486  97 02             STA    <$02
  1488  6C 84             INC    ,X
  148A  84 07             ANDA   #$07
  148C  26 1A             BNE    L_14A8
  148E  D6 02             LDB    <$02
  1490  96 02             LDA    <$02
  1492  54                LSRB
  1493  46                RORA
  1494  54                LSRB
  1495  46                RORA
  1496  54                LSRB
  1497  46                RORA
  1498  97 02             STA    <$02
  149A  F6 62 29          LDB    >Level                  ; level number
  149D  DB 02             ADDB   <$02
  149F  C1 05             CMPB   #$05
  14A1  25 02             BCS    L_14A5
  14A3  C6 05             LDB    #$05
L_14A5:
  14A5  F7 63 80          STB    >Difficulty
L_14A8:
  14A8  39                RTS

; =====================================================================
; SUB_14A9 (38 instructions)
; Uses:  $6350 $62B8 $62B9 $6A29 $66A0 $62BA $63A0
; Calls: RST_RetIfNotScreen RST_RetIfMarioDead SUB_14FA
; =====================================================================
SUB_14A9:
  14A9  C6 03             LDB    #$03
  14AB  9D 64             JSR    <RST_RetIfNotScreen
  14AD  9D 38             JSR    <RST_RetIfMarioDead
  14AF  F6 63 50          LDB    >$6350
  14B2  56                RORB
  14B3  25 F3             BCS    L_14A8
  14B5  8E 62 B8          LDX    #$62B8
  14B8  6A 84             DEC    ,X
  14BA  26 EC             BNE    L_14A8
  14BC  86 04             LDA    #$04
  14BE  A7 84             STA    ,X
  14C0  F6 62 B9          LDB    >$62B9
  14C3  56                RORB
  14C4  24 E2             BCC    L_14A8
  14C6  8E 6A 29          LDX    #$6A29
  14C9  86 40             LDA    #$40
  14CB  CE 66 A0          LDU    #$66A0
  14CE  56                RORB
  14CF  24 1F             BCC    L_14F0
  14D1  C6 02             LDB    #$02
  14D3  E7 49             STB    9,U
  14D5  E7 4A             STB    10,U
  14D7  8B 02             ADDA   #$02
  14D9  8D 1F             BSR    SUB_14FA
  14DB  8E 62 BA          LDX    #$62BA
  14DE  6A 84             DEC    ,X
  14E0  26 C6             BNE    L_14A8
  14E2  C6 01             LDB    #$01
  14E4  F7 62 B9          STB    >$62B9
  14E7  F7 63 A0          STB    >$63A0
L_14EA:
  14EA  C6 10             LDB    #$10
  14EC  F7 62 BA          STB    >$62BA
  14EF  39                RTS
L_14F0:
  14F0  C6 02             LDB    #$02
  14F2  E7 49             STB    9,U
  14F4  6F 4A             CLR    10,U
  14F6  8D 02             BSR    SUB_14FA
  14F8  20 F0             BRA    L_14EA

; =====================================================================
; SUB_14FA (7 instructions)
; Uses:  RandTimer
; =====================================================================
SUB_14FA:
  14FA  A7 84             STA    ,X
  14FC  F6 60 19          LDB    >RandTimer
  14FF  56                RORB
  1500  25 03             BCS    L_1505
  1502  4C                INCA
  1503  A7 84             STA    ,X
L_1505:
  1505  39                RTS

; =====================================================================
; SUB_1506 (122 instructions)
; Uses:  ScreenNum $6908 $63A3 $6910 $63B7 $6391 FrameCounter $6390 $6393 SndBoom $690B $75C4 $6905 $7623 ...
; Calls: RST_AddToObjects RST_CopySprites SUB_161C
; =====================================================================
SUB_1506:
  1506  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  1509  C1 02             CMPB   #$02
  150B  26 12             BNE    L_151F
  150D  8E 69 08          LDX    #$6908
  1510  F6 63 A3          LDB    >$63A3
  1513  D7 03             STB    <$03
  1515  9D 4F             JSR    <RST_AddToObjects
  1517  F6 69 10          LDB    >$6910
  151A  C0 3B             SUBB   #$3B
  151C  F7 63 B7          STB    >$63B7
L_151F:
  151F  F6 63 91          LDB    >$6391
  1522  26 0A             BNE    L_152E
  1524  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  1527  26 66             BNE    L_158F
  1529  C6 01             LDB    #$01
  152B  F7 63 91          STB    >$6391
L_152E:
  152E  8E 63 90          LDX    #$6390
  1531  6C 84             INC    ,X
  1533  E6 84             LDB    ,X
  1535  C1 80             CMPB   #$80
  1537  27 34             BEQ    L_156D
  1539  F6 63 93          LDB    >$6393
  153C  26 51             BNE    L_158F
  153E  E6 84             LDB    ,X
  1540  D7 02             STB    <$02
  1542  C4 1F             ANDB   #$1F
  1544  26 49             BNE    L_158F
  1546  8E 4D E7          LDX    #D_4DE7
  1549  96 02             LDA    <$02
  154B  84 20             ANDA   #$20
  154D  26 03             BNE    L_1552
  154F  8E 4E 0F          LDX    #D_4E0F
L_1552:
  1552  9D 77             JSR    <RST_CopySprites
  1554  C6 03             LDB    #$03
  1556  F7 60 82          STB    >SndBoom
L_1559:
  1559  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  155C  56                RORB
  155D  24 1F             BCC    L_157E
  155F  56                RORB
  1560  25 2D             BCS    L_158F
  1562  8E 69 0B          LDX    #$690B
  1565  86 FC             LDA    #$FC
  1567  97 03             STA    <$03
  1569  9D 4F             JSR    <RST_AddToObjects
  156B  20 22             BRA    L_158F
L_156D:
  156D  5F                CLRB
  156E  E7 80             STB    ,X+
  1570  E7 84             STB    ,X
  1572  F6 63 93          LDB    >$6393
  1575  26 18             BNE    L_158F
  1577  8E 4D B7          LDX    #D_4DB7
  157A  9D 77             JSR    <RST_CopySprites
  157C  20 DB             BRA    L_1559
L_157E:
  157E  8E 69 08          LDX    #$6908
  1581  86 44             LDA    #$44
  1583  97 03             STA    <$03
  1585  56                RORB
  1586  24 05             BCC    L_158D
  1588  F6 63 B7          LDB    >$63B7
  158B  D7 03             STB    <$03
L_158D:
  158D  9D 4F             JSR    <RST_AddToObjects
L_158F:
  158F  F6 63 90          LDB    >$6390
  1592  D7 03             STB    <$03
  1594  10 8E 00 20       LDY    #$0020
  1598  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  159B  C1 04             CMPB   #$04
  159D  27 2F             BEQ    L_15CE
  159F  D6 03             LDB    <$03
  15A1  27 08             BEQ    L_15AB
  15A3  C6 EF             LDB    #$EF
  15A5  96 03             LDA    <$03
  15A7  84 40             ANDA   #$40
  15A9  26 02             BNE    L_15AD
L_15AB:
  15AB  C6 10             LDB    #$10
L_15AD:
  15AD  8E 75 C4          LDX    #$75C4
  15B0  8D 6A             BSR    SUB_161C
  15B2  F6 69 05          LDB    >$6905
L_15B5:
  15B5  F7 69 05          STB    >$6905
  15B8  96 03             LDA    <$03
  15BA  84 40             ANDA   #$40
  15BC  27 0F             BEQ    L_15CD
  15BE  D7 02             STB    <$02
  15C0  D6 03             LDB    <$03
  15C2  C4 07             ANDB   #$07
  15C4  26 07             BNE    L_15CD
  15C6  D6 02             LDB    <$02
  15C8  C8 03             EORB   #$03
  15CA  F7 69 05          STB    >$6905
L_15CD:
  15CD  39                RTS
L_15CE:
  15CE  C6 10             LDB    #$10
  15D0  8E 76 23          LDX    #$7623
  15D3  8D 47             BSR    SUB_161C
  15D5  8E 75 83          LDX    #$7583
  15D8  8D 42             BSR    SUB_161C
  15DA  96 03             LDA    <$03
  15DC  84 40             ANDA   #$40
  15DE  27 33             BEQ    L_1613
  15E0  F6 62 03          LDB    >MarioX
  15E3  C1 80             CMPB   #$80
  15E5  24 16             BCC    L_15FD
  15E7  C6 DF             LDB    #$DF
  15E9  8E 76 23          LDX    #$7623
  15EC  8D 2E             BSR    SUB_161C
L_15EE:
  15EE  F6 69 01          LDB    >$6901
  15F1  CA 80             ORB    #$80
  15F3  F7 69 01          STB    >$6901
  15F6  F6 69 05          LDB    >$6905
  15F9  CA 80             ORB    #$80
  15FB  20 B8             BRA    L_15B5
L_15FD:
  15FD  C6 EF             LDB    #$EF
  15FF  8E 75 83          LDX    #$7583
  1602  8D 18             BSR    SUB_161C
L_1604:
  1604  F6 69 01          LDB    >$6901
  1607  C4 7F             ANDB   #$7F
  1609  F7 69 01          STB    >$6901
  160C  F6 69 05          LDB    >$6905
  160F  C4 7F             ANDB   #$7F
  1611  20 A2             BRA    L_15B5
L_1613:
  1613  F6 62 03          LDB    >MarioX
  1616  C1 80             CMPB   #$80
  1618  24 EA             BCC    L_1604
  161A  20 D2             BRA    L_15EE

; =====================================================================
; SUB_161C (11 instructions)
; =====================================================================
SUB_161C:
  161C  86 03             LDA    #$03
  161E  97 02             STA    <$02
L_1620:
  1620  E7 84             STB    ,X
  1622  D7 01             STB    <$01
  1624  1F 20             TFR    Y,D
  1626  30 8B             LEAX   D,X
  1628  D6 01             LDB    <$01
  162A  5A                DECB
  162B  0A 02             DEC    <$02
  162D  26 F1             BNE    L_1620
  162F  39                RTS

; =====================================================================
; Task 0 - AddScore: B = index into TBL_ScoreValues (3-byte BCD),
; adds to the current player's score ($60B2 / $60B5), redraws it and
; updates the high score $60B8 when beaten.
; =====================================================================
Task0_AddScore:
  1630  D7 03             STB    <$03
  1632  9D 2F             JSR    <RST_RetIfAttract
  1634  8D 48             BSR    GetScorePtr
  1636  D6 03             LDB    <$03
  1638  DB 03             ADDB   <$03
  163A  DB 03             ADDB   <$03
  163C  8E 49 45          LDX    #TBL_ScoreValues
  163F  3A                ABX
  1640  4F                CLRA
  1641  C6 03             LDB    #$03
L_1643:
  1643  A6 A4             LDA    ,Y
  1645  A9 80             ADCA   ,X+
  1647  19                DAA
  1648  A7 A0             STA    ,Y+
  164A  5A                DECB
  164B  26 F6             BNE    L_1643
  164D  34 20             PSHS   Y
  164F  31 3F             LEAY   -1,Y
  1651  F6 60 0D          LDB    >PlayerUp               ; 0 = player 1, 1 = player 2
  1654  8D 36             BSR    DrawScore
  1656  35 20             PULS   Y
  1658  31 3F             LEAY   -1,Y
  165A  8E 60 BA          LDX    #$60BA
  165D  86 03             LDA    #$03
L_165F:
  165F  E6 A4             LDB    ,Y
  1661  E1 84             CMPB   ,X
  1663  25 09             BCS    L_166E
  1665  26 08             BNE    L_166F
  1667  31 3F             LEAY   -1,Y
  1669  30 1F             LEAX   -1,X
  166B  4A                DECA
  166C  26 F1             BNE    L_165F
L_166E:
  166E  39                RTS
L_166F:
  166F  8D 0D             BSR    GetScorePtr
  1671  8E 60 B8          LDX    #HiScore
L_1674:
  1674  E6 A0             LDB    ,Y+
  1676  E7 80             STB    ,X+
  1678  4A                DECA
  1679  26 F9             BNE    L_1674
  167B  7E 16 FA          JMP    >L_16FA

; =====================================================================
; GetScorePtr: Y = $60B2 (player 1) or $60B5 (player 2).
; =====================================================================
GetScorePtr:
  167E  10 8E 60 B2       LDY    #ScoreP1
  1682  F6 60 0D          LDB    >PlayerUp               ; 0 = player 1, 1 = player 2
  1685  27 04             BEQ    L_168B
  1687  10 8E 60 B5       LDY    #ScoreP2
L_168B:
  168B  39                RTS

; =====================================================================
; DrawScore: draw the 6 BCD digits at Y to tile RAM (U).
; =====================================================================
DrawScore:
  168C  CE 77 81          LDU    #$7781
  168F  5D                TSTB
  1690  27 08             BEQ    DrawBCD
  1692  CE 75 21          LDU    #$7521
  1695  20 03             BRA    DrawBCD
L_1697:
  1697  CE 76 41          LDU    #$7641

; =====================================================================
; DrawBCD (15 instructions)
; Calls: DrawDigit
; =====================================================================
DrawBCD:
  169A  1F 21             TFR    Y,X
  169C  CC 03 04          LDD    #$0304
  169F  DD 02             STD    <$02
L_16A1:
  16A1  E6 84             LDB    ,X
  16A3  56                RORB
  16A4  56                RORB
  16A5  56                RORB
  16A6  56                RORB
  16A7  8D 0B             BSR    DrawDigit
  16A9  E6 84             LDB    ,X
  16AB  8D 07             BSR    DrawDigit
  16AD  30 1F             LEAX   -1,X
  16AF  0A 02             DEC    <$02
  16B1  26 EE             BNE    L_16A1
  16B3  39                RTS

; =====================================================================
; DrawDigit (4 instructions)
; =====================================================================
DrawDigit:
  16B4  C4 0F             ANDB   #$0F
  16B6  E7 C4             STB    ,U
  16B8  33 C8 E0          LEAU   <-32,U
  16BB  39                RTS

; =====================================================================
; Task 1 - ClearScore: B = 0 P1, 1 P2, 2 high score, 3 all.
; =====================================================================
Task1_ClearScore:
  16BC  C1 03             CMPB   #$03
  16BE  24 1D             BCC    L_16DD
  16C0  34 04             PSHS   B
  16C2  8E 60 B2          LDX    #ScoreP1
  16C5  5D                TSTB
  16C6  27 03             BEQ    L_16CB
  16C8  8E 60 B5          LDX    #ScoreP2
L_16CB:
  16CB  C1 02             CMPB   #$02
  16CD  26 03             BNE    L_16D2
  16CF  8E 60 B8          LDX    #HiScore
L_16D2:
  16D2  5F                CLRB
  16D3  E7 80             STB    ,X+
  16D5  E7 80             STB    ,X+
  16D7  E7 84             STB    ,X
  16D9  35 04             PULS   B
  16DB  20 0A             BRA    Task2_ShowScore
L_16DD:
  16DD  5A                DECB
  16DE  34 05             PSHS   CC,B
  16E0  8D DA             BSR    Task1_ClearScore
  16E2  35 05             PULS   CC,B
  16E4  26 F7             BNE    L_16DD
  16E6  39                RTS

; =====================================================================
; Task 2 - ShowScore: B = 0 P1, 1 P2, 2 high score, 3 all.
; =====================================================================
Task2_ShowScore:
  16E7  C1 03             CMPB   #$03
  16E9  27 16             BEQ    L_1701
  16EB  10 8E 60 B4       LDY    #$60B4
  16EF  5D                TSTB
  16F0  27 04             BEQ    L_16F6
  16F2  10 8E 60 B7       LDY    #$60B7
L_16F6:
  16F6  C1 02             CMPB   #$02
  16F8  26 92             BNE    DrawScore
L_16FA:
  16FA  10 8E 60 BA       LDY    #$60BA
  16FE  7E 16 97          JMP    >L_1697
L_1701:
  1701  5A                DECB
  1702  34 05             PSHS   CC,B
  1704  8D E1             BSR    Task2_ShowScore
  1706  35 05             PULS   CC,B
  1708  26 F7             BNE    L_1701
  170A  39                RTS

; =====================================================================
; Task 3 - ShowString: B = string number (bit7 set = erase).
; TBL_Strings -> FDB vram address, tile codes..., $3F end.  Text runs
; in the rotated arcade screen: next column = -32 bytes.
; =====================================================================
Task3_ShowString:
  170B  8E 4A 67          LDX    #TBL_Strings
  170E  58                ASLB
  170F  34 05             PSHS   CC,B
  1711  C4 7F             ANDB   #$7F
  1713  3A                ABX
  1714  10 AE 84          LDY    ,X
  1717  AE A1             LDX    ,Y++
  1719  DD 02             STD    <$02
L_171B:
  171B  E6 A4             LDB    ,Y
  171D  C1 3F             CMPB   #$3F
  171F  26 02             BNE    L_1723
  1721  35 90             PULS   X,PC
L_1723:
  1723  E7 84             STB    ,X
  1725  35 05             PULS   CC,B
  1727  24 04             BCC    L_172D
  1729  86 10             LDA    #$10
  172B  A7 84             STA    ,X
L_172D:
  172D  34 05             PSHS   CC,B
  172F  31 21             LEAY   1,Y
  1731  30 88 E0          LEAX   <-32,X
  1734  20 E5             BRA    L_171B

; =====================================================================
; Task 4 - ShowCredits (only in attract mode).
; =====================================================================
Task4_ShowCredits:
  1736  F6 60 07          LDB    >AttractFlag            ; 1 = attract / no game
  1739  56                RORB
  173A  25 01             BCS    ShowCredits
L_173C:
  173C  39                RTS

; =====================================================================
; ShowCredits (94 instructions)
; Uses:  NumCredits $74BF BonusTimer $63B8 $62B0 $7465 MusicReq $7486 $74A6 $74E6 $74C6
; Calls: Task3_ShowString Task0_AddScore
; =====================================================================
ShowCredits:
  173D  8E 53 9F          LDX    #TBL_TilePalette
  1740  BF 54 C8          STX    >L_54C6+2
  1743  C6 05             LDB    #$05
  1745  8D C4             BSR    Task3_ShowString
  1747  8E 60 01          LDX    #NumCredits
  174A  CE 74 BF          LDU    #$74BF
  174D  86 01             LDA    #$01
  174F  97 02             STA    <$02
  1751  7E 16 A1          JMP    >L_16A1

; =====================================================================
; Task 5 - BonusTimer: B=0 add the remaining bonus to the score;
; else count the bonus timer $638C down and draw the bonus box.
; =====================================================================
Task5_BonusTimer:
  1754  5D                TSTB
  1755  27 77             BEQ    L_17CE
  1757  B6 63 8C          LDA    >BonusTimer             ; bonus timer (BCD)
  175A  10 26 00 89       LBNE   L_17E7
  175E  F6 63 B8          LDB    >$63B8
  1761  26 D9             BNE    L_173C
  1763  CC 00 0A          LDD    #$000A
  1766  DD 02             STD    <$02
  1768  F6 62 B0          LDB    >$62B0
L_176B:
  176B  0C 02             INC    <$02
  176D  D0 03             SUBB   <$03
  176F  26 FA             BNE    L_176B
  1771  D6 02             LDB    <$02
  1773  96 02             LDA    <$02
  1775  48                ASLA
  1776  59                ROLB
  1777  48                ASLA
  1778  59                ROLB
  1779  48                ASLA
  177A  59                ROLB
  177B  48                ASLA
  177C  59                ROLB
  177D  F7 63 8C          STB    >BonusTimer             ; bonus timer (BCD)
  1780  8E 4C 62          LDX    #D_4C62
  1783  10 8E 74 65       LDY    #$7465
  1787  C6 06             LDB    #$06
  1789  D7 01             STB    <$01
L_178B:
  178B  CE 00 1D          LDU    #$001D
  178E  C6 03             LDB    #$03
L_1790:
  1790  A6 80             LDA    ,X+
  1792  A7 A0             STA    ,Y+
  1794  5A                DECB
  1795  26 F9             BNE    L_1790
  1797  1F 20             TFR    Y,D
  1799  33 CB             LEAU   D,U
  179B  1F 32             TFR    U,Y
  179D  0A 01             DEC    <$01
  179F  26 EA             BNE    L_178B
  17A1  B6 63 8C          LDA    >BonusTimer             ; bonus timer (BCD)
L_17A4:
  17A4  97 03             STA    <$03
  17A6  84 0F             ANDA   #$0F
  17A8  97 02             STA    <$02
  17AA  D6 03             LDB    <$03
  17AC  54                LSRB
  17AD  54                LSRB
  17AE  54                LSRB
  17AF  54                LSRB
  17B0  26 13             BNE    L_17C5
  17B2  C6 03             LDB    #$03
  17B4  F7 60 89          STB    >MusicReq               ; music number request
  17B7  C6 70             LDB    #$70
  17B9  F7 74 86          STB    >$7486
  17BC  F7 74 A6          STB    >$74A6
  17BF  DB 02             ADDB   <$02
  17C1  D7 02             STB    <$02
  17C3  C6 10             LDB    #$10
L_17C5:
  17C5  F7 74 E6          STB    >$74E6
  17C8  D6 02             LDB    <$02
  17CA  F7 74 C6          STB    >$74C6
  17CD  39                RTS
L_17CE:
  17CE  F6 63 8C          LDB    >BonusTimer             ; bonus timer (BCD)
  17D1  D7 02             STB    <$02
  17D3  34 04             PSHS   B
  17D5  C4 0F             ANDB   #$0F
  17D7  BD 16 30          JSR    >Task0_AddScore
  17DA  35 04             PULS   B
  17DC  D7 02             STB    <$02
  17DE  54                LSRB
  17DF  54                LSRB
  17E0  54                LSRB
  17E1  54                LSRB
  17E2  CB 0A             ADDB   #$0A
  17E4  7E 16 30          JMP    >Task0_AddScore
L_17E7:
  17E7  80 01             SUBA   #$01
  17E9  26 07             BNE    L_17F2
  17EB  8E 63 B8          LDX    #$63B8
  17EE  C6 01             LDB    #$01
  17F0  E7 84             STB    ,X
L_17F2:
  17F2  1F 89             TFR    A,B
  17F4  C4 0F             ANDB   #$0F
  17F6  C1 0F             CMPB   #$0F
  17F8  26 02             BNE    L_17FC
  17FA  80 06             SUBA   #$06
L_17FC:
  17FC  B7 63 8C          STA    >BonusTimer             ; bonus timer (BCD)
  17FF  20 A3             BRA    L_17A4

; =====================================================================
; Task 6 - ShowLivesLevel: Mario icons for the spare lives and
; 'L=nn' for the level $6229 (max 99).
; =====================================================================
Task6_ShowLivesLevel:
  1801  D7 03             STB    <$03
  1803  9D 2F             JSR    <RST_RetIfAttract
  1805  86 06             LDA    #$06
  1807  8E 77 83          LDX    #$7783
  180A  C6 10             LDB    #$10
L_180C:
  180C  E7 84             STB    ,X
  180E  30 88 E0          LEAX   <-32,X
  1811  4A                DECA
  1812  26 F8             BNE    L_180C
  1814  F6 62 28          LDB    >Lives                  ; lives left
  1817  D0 03             SUBB   <$03
  1819  27 10             BEQ    L_182B
  181B  D7 02             STB    <$02
  181D  8E 77 83          LDX    #$7783
L_1820:
  1820  86 FF             LDA    #$FF
  1822  A7 84             STA    ,X
  1824  30 88 E0          LEAX   <-32,X
  1827  0A 02             DEC    <$02
  1829  26 F5             BNE    L_1820
L_182B:
  182B  8E 75 03          LDX    #$7503
  182E  86 1C             LDA    #$1C
  1830  A7 84             STA    ,X
  1832  8E 74 E3          LDX    #$74E3
  1835  86 34             LDA    #$34
  1837  A7 84             STA    ,X
  1839  B6 62 29          LDA    >Level                  ; level number
  183C  81 64             CMPA   #$64
  183E  25 05             BCS    L_1845
  1840  86 63             LDA    #$63
  1842  B7 62 29          STA    >Level                  ; level number
L_1845:
  1845  C6 FF             LDB    #$FF
L_1847:
  1847  5C                INCB
  1848  80 0A             SUBA   #$0A
  184A  24 FB             BCC    L_1847
  184C  8B 0A             ADDA   #$0A
  184E  B7 74 A3          STA    >$74A3
  1851  F7 74 C3          STB    >$74C3
  1854  39                RTS

; =====================================================================
; Mode3_Game: game state machine on $600A.
; =====================================================================
Mode3_Game:
  1855  F6 60 0A          LDB    >GameState              ; sub-state of GameMode
  1858  9D 47             JSR    <RST_JumpTable
TBL_GameState:
  185A  1B 2B             FDB    L_1B2B
  185C  1B 54             FDB    L_1B54
  185E  1B 8E             FDB    L_1B8E
  1860  1B BB             FDB    L_1BBB
  1862  1B DE             FDB    L_1BDE
  1864  1B FE             FDB    L_1BFE
  1866  1C 2F             FDB    L_1C2F
  1868  1C 48             FDB    L_1C48
  186A  1D DD             FDB    L_1DDD
  186C  11 14             FDB    ColdStart
  186E  1E 9B             FDB    L_1E9B
  1870  24 E0             FDB    L_24E0
  1872  2C EB             FDB    L_2CEB
  1874  25 24             FDB    L_2524
  1876  25 B7             FDB    L_25B7
  1878  26 17             FDB    L_2617
  187A  26 6F             FDB    L_266F
  187C  26 83             FDB    L_2683
  187E  26 8C             FDB    L_268C
  1880  26 9D             FDB    L_269D
  1882  27 18             FDB    L_2718
  1884  27 88             FDB    L_2788
  1886  29 14             FDB    L_2914
  1888  2C DC             FDB    L_2CDC

; =====================================================================
; Mode1_Attract: attract mode state machine on $600A; a credit
; ($6001) switches to mode 2.
; =====================================================================
Mode1_Attract:
  188A  8E 60 0A          LDX    #GameState
  188D  F6 60 01          LDB    >NumCredits             ; credits (BCD)
  1890  26 14             BNE    L_18A6
  1892  E6 84             LDB    ,X
  1894  9D 47             JSR    <RST_JumpTable
TBL_AttractState:
  1896  18 C6             FDB    L_18C6
  1898  18 AE             FDB    L_18AE
  189A  24 E0             FDB    L_24E0
  189C  2C E8             FDB    L_2CE8
  189E  25 24             FDB    L_2524
  18A0  19 19             FDB    L_1919
  18A2  19 31             FDB    L_1931
  18A4  19 C9             FDB    L_19C9
L_18A6:
  18A6  6F 84             CLR    ,X
  18A8  8E 60 05          LDX    #GameMode
  18AB  6C 84             INC    ,X
  18AD  39                RTS
L_18AE:
  18AE  BD 11 0B          JSR    >MinorTimerWait
  18B1  5F                CLRB
  18B2  F7 63 92          STB    >$6392
  18B5  F7 63 A0          STB    >$63A0
  18B8  C6 01             LDB    #$01
  18BA  F7 62 27          STB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  18BD  F7 62 29          STB    >Level                  ; level number
  18C0  F7 62 28          STB    >Lives                  ; lives left
  18C3  7E 1E 9D          JMP    >L_1E9D
L_18C6:
  18C6  8E 7D 86          LDX    #PaletteBank0
  18C9  6F 80             CLR    ,X+
  18CB  6F 84             CLR    ,X
  18CD  BD 53 66          JSR    >PaletteBankUpdate
  18D0  10 8E 03 1B       LDY    #$031B                  ; show "INSERT COIN "
  18D4  BD 45 21          JSR    >AddTask
  18D7  31 21             LEAY   1,Y
  18D9  BD 45 21          JSR    >AddTask
  18DC  BD 1B 00          JSR    >ShowHighScoreTable
  18DF  8E 60 09          LDX    #WaitTimer
  18E2  86 02             LDA    #$02
  18E4  A7 80             STA    ,X+
  18E6  6C 84             INC    ,X
  18E8  BD 19 F9          JSR    >ClearPlayfield
  18EB  BD 1C 1F          JSR    >Draw1UP
  18EE  F6 60 0F          LDB    >TwoPlayers
  18F1  C1 01             CMPB   #$01
  18F3  26 03             BNE    L_18F8
  18F5  BD 1B AB          JSR    >SUB_1BAB
L_18F8:
  18F8  10 BE 60 22       LDY    >DipCoinsLo
  18FC  8E 75 6C          LDX    #$756C
  18FF  8D 00             BSR    SUB_1901

; =====================================================================
; SUB_1901 (93 instructions)
; Uses:  $758E $768C GameState $638B $638A PAL_3 PAL_5 $6908 $690B WaitTimer
; Calls: ClearPlayfield AddTask RST_CopySprites RST_AddToObjects MinorTimerWait
; =====================================================================
SUB_1901:
  1901  1F 20             TFR    Y,D
  1903  E7 81             STB    ,X++
  1905  A7 84             STA    ,X
  1907  80 0A             SUBA   #$0A
  1909  26 06             BNE    L_1911
  190B  A7 84             STA    ,X
  190D  4C                INCA
  190E  B7 75 8E          STA    >$758E
L_1911:
  1911  10 8E 02 01       LDY    #$0201
  1915  8E 76 8C          LDX    #$768C
  1918  39                RTS
L_1919:
  1919  BD 19 F9          JSR    >ClearPlayfield
  191C  8E 60 0A          LDX    #GameState
  191F  6C 84             INC    ,X
  1921  39                RTS
L_1922:
  1922  F6 63 8B          LDB    >$638B
  1925  D7 03             STB    <$03
  1927  F6 63 8A          LDB    >$638A
  192A  5A                DECB
  192B  F7 63 8A          STB    >$638A
  192E  7E 19 3F          JMP    >L_193F
L_1931:
  1931  F6 63 8A          LDB    >$638A
  1934  26 EC             BNE    L_1922
  1936  C6 60             LDB    #$60
  1938  F7 63 8A          STB    >$638A
  193B  86 5F             LDA    #$5F
  193D  97 03             STA    <$03
L_193F:
  193F  C1 00             CMPB   #$00
  1941  27 75             BEQ    L_19B8
  1943  D6 03             LDB    <$03
  1945  96 03             LDA    <$03
  1947  48                ASLA
  1948  59                ROLB
  1949  1F 98             TFR    B,A
  194B  48                ASLA
  194C  59                ROLB
  194D  F7 63 8B          STB    >$638B
  1950  C1 D7             CMPB   #$D7
  1952  26 0E             BNE    L_1962
  1954  96 20             LDA    <VsyncCount
L_1956:
  1956  91 20             CMPA   <VsyncCount
  1958  27 FC             BEQ    L_1956
  195A  B6 5A 9B          LDA    >D_5A9B
  195D  F6 5A 9D          LDB    >D_5A9D
  1960  20 10             BRA    L_1972
L_1962:
  1962  C1 7D             CMPB   #$7D
  1964  26 18             BNE    L_197E
  1966  96 20             LDA    <VsyncCount
L_1968:
  1968  91 20             CMPA   <VsyncCount
  196A  27 FC             BEQ    L_1968
  196C  B6 5A 9E          LDA    >D_5A9E
  196F  F6 5A A2          LDB    >D_5AA2
L_1972:
  1972  B7 FF B3          STA    >PAL_3                  ; PAL_3 - Palette 3 (6-bit RGB)
  1975  F7 FF B5          STB    >PAL_5                  ; PAL_5 - Palette 5 (6-bit RGB)
  1978  8E 54 5F          LDX    #D_545F
  197B  BF 54 C8          STX    >L_54C6+2
L_197E:
  197E  8E 51 35          LDX    #D_5135
L_1981:
  1981  C6 B0             LDB    #$B0
  1983  A6 80             LDA    ,X+
  1985  97 02             STA    <$02
  1987  10 AE 81          LDY    ,X++
L_198A:
  198A  E7 A0             STB    ,Y+
  198C  0A 02             DEC    <$02
  198E  26 FA             BNE    L_198A
  1990  E6 84             LDB    ,X
  1992  26 ED             BNE    L_1981
  1994  10 8E 03 1E       LDY    #$031E                  ; show "~~ NINTENDO"
  1998  BD 45 21          JSR    >AddTask
  199B  31 21             LEAY   1,Y
  199D  BD 45 21          JSR    >AddTask
  19A0  8E 4D E7          LDX    #D_4DE7
  19A3  9D 77             JSR    <RST_CopySprites
  19A5  8E 69 08          LDX    #$6908
  19A8  86 44             LDA    #$44
  19AA  97 03             STA    <$03
  19AC  9D 4F             JSR    <RST_AddToObjects
  19AE  8E 69 0B          LDX    #$690B
  19B1  86 78             LDA    #$78
  19B3  97 03             STA    <$03
  19B5  9D 4F             JSR    <RST_AddToObjects
  19B7  39                RTS
L_19B8:
  19B8  8E 60 09          LDX    #WaitTimer
  19BB  86 02             LDA    #$02
  19BD  A7 80             STA    ,X+
  19BF  6C 84             INC    ,X
  19C1  8E 63 8A          LDX    #$638A
  19C4  6F 80             CLR    ,X+
  19C6  6F 84             CLR    ,X
  19C8  39                RTS
L_19C9:
  19C9  BD 11 0B          JSR    >MinorTimerWait
  19CC  8E 60 0A          LDX    #GameState
  19CF  6F 84             CLR    ,X
  19D1  39                RTS

; =====================================================================
; ClearScreenAll: tile RAM <- $10 (blank), sprite buffer <- 0.
; =====================================================================
ClearScreenAll:
  19D2  8E 74 00          LDX    #TileRAM
  19D5  86 04             LDA    #$04
  19D7  97 03             STA    <$03
L_19D9:
  19D9  4F                CLRA
  19DA  C6 10             LDB    #$10
L_19DC:
  19DC  E7 80             STB    ,X+
  19DE  4A                DECA
  19DF  26 FB             BNE    L_19DC
  19E1  0A 03             DEC    <$03
  19E3  26 F4             BNE    L_19D9
  19E5  8E 69 00          LDX    #SpriteBuf
  19E8  86 02             LDA    #$02
  19EA  97 03             STA    <$03
L_19EC:
  19EC  86 C0             LDA    #$C0
  19EE  5F                CLRB
L_19EF:
  19EF  E7 80             STB    ,X+
  19F1  4A                DECA
  19F2  26 FB             BNE    L_19EF
  19F4  0A 03             DEC    <$03
  19F6  26 F4             BNE    L_19EC
  19F8  39                RTS

; =====================================================================
; ClearPlayfield: blank the playfield columns, keep score area.
; =====================================================================
ClearPlayfield:
  19F9  8E 74 04          LDX    #$7404
  19FC  86 20             LDA    #$20
  19FE  97 03             STA    <$03
L_1A00:
  1A00  86 1C             LDA    #$1C
  1A02  C6 10             LDB    #$10
L_1A04:
  1A04  E7 80             STB    ,X+
  1A06  4A                DECA
  1A07  26 FB             BNE    L_1A04
  1A09  30 04             LEAX   4,X
  1A0B  0A 03             DEC    <$03
  1A0D  26 F1             BNE    L_1A00
  1A0F  8E 75 22          LDX    #$7522
  1A12  86 02             LDA    #$02
  1A14  97 03             STA    <$03
  1A16  C6 10             LDB    #$10
L_1A18:
  1A18  86 0E             LDA    #$0E
L_1A1A:
  1A1A  E7 84             STB    ,X
  1A1C  30 88 20          LEAX   <32,X
  1A1F  4A                DECA
  1A20  26 F8             BNE    L_1A1A
  1A22  8E 75 23          LDX    #$7523
  1A25  0A 03             DEC    <$03
  1A27  26 EF             BNE    L_1A18
  1A29  8E 69 00          LDX    #SpriteBuf
  1A2C  4F                CLRA
  1A2D  5F                CLRB
L_1A2E:
  1A2E  E7 80             STB    ,X+
  1A30  4A                DECA
  1A31  26 FB             BNE    L_1A2E
  1A33  86 80             LDA    #$80
L_1A35:
  1A35  E7 80             STB    ,X+
  1A37  4A                DECA
  1A38  26 FB             BNE    L_1A35
  1A3A  39                RTS

; =====================================================================
; Mode2_Credited: 'PUSH ... BUTTON' screen, wait for 1P/2P start.
; =====================================================================
Mode2_Credited:
  1A3B  F6 60 0A          LDB    >GameState              ; sub-state of GameMode
  1A3E  9D 47             JSR    <RST_JumpTable
TBL_CreditState:
  1A40  1A 44             FDB    L_1A44
  1A42  1A 8C             FDB    L_1A8C
L_1A44:
  1A44  8D B3             BSR    ClearPlayfield
  1A46  5F                CLRB
  1A47  F7 60 07          STB    >AttractFlag            ; 1 = attract / no game
  1A4A  10 8E 03 0C       LDY    #$030C                  ; show "PUSH"
  1A4E  BD 45 21          JSR    >AddTask
  1A51  8E 60 0A          LDX    #GameState
  1A54  6C 84             INC    ,X
  1A56  BD 1B 00          JSR    >ShowHighScoreTable
  1A59  5F                CLRB
  1A5A  8E 7D 86          LDX    #PaletteBank0
  1A5D  E7 80             STB    ,X+
  1A5F  E7 84             STB    ,X
  1A61  BD 53 66          JSR    >PaletteBankUpdate

; =====================================================================
; WaitStartButton (65 instructions)
; Uses:  NumCredits FrameCounter $6048 DipLives Player2Ctrl $6040 GameState GameMode
; Calls: Task3_ShowString ShowCredits WaitStartButton SUB_1B19 AddTask ClearPlayfield
; =====================================================================
WaitStartButton:
  1A64  CC 04 09          LDD    #$0409
  1A67  97 02             STA    <$02
  1A69  D7 05             STB    <$05
  1A6B  F6 60 01          LDB    >NumCredits             ; credits (BCD)
  1A6E  C1 01             CMPB   #$01
  1A70  27 06             BEQ    L_1A78
  1A72  86 0C             LDA    #$0C
  1A74  97 02             STA    <$02
  1A76  0C 05             INC    <$05
L_1A78:
  1A78  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  1A7B  C4 07             ANDB   #$07
  1A7D  26 08             BNE    L_1A87
  1A7F  D6 05             LDB    <$05
  1A81  BD 17 0B          JSR    >Task3_ShowString
  1A84  BD 17 3D          JSR    >ShowCredits
L_1A87:
  1A87  D6 1E             LDB    <CoinStartBits
  1A89  D4 02             ANDB   <$02
  1A8B  39                RTS
L_1A8C:
  1A8C  8D D6             BSR    WaitStartButton
  1A8E  C1 04             CMPB   #$04
  1A90  27 05             BEQ    L_1A97
  1A92  C1 08             CMPB   #$08
  1A94  27 14             BEQ    L_1AAA
  1A96  39                RTS
L_1A97:
  1A97  BD 1B 19          JSR    >SUB_1B19
  1A9A  8E 60 48          LDX    #$6048
  1A9D  86 08             LDA    #$08
  1A9F  5F                CLRB
L_1AA0:
  1AA0  E7 80             STB    ,X+
  1AA2  4A                DECA
  1AA3  26 FB             BNE    L_1AA0
  1AA5  8E 00 00          LDX    #$0000
  1AA8  20 23             BRA    L_1ACD
L_1AAA:
  1AAA  8D 6D             BSR    SUB_1B19
  1AAC  8D 6B             BSR    SUB_1B19
  1AAE  10 8E 60 48       LDY    #$6048
  1AB2  F6 60 20          LDB    >DipLives               ; lives per game (DIP)
  1AB5  E7 A0             STB    ,Y+
  1AB7  8E 1A F9          LDX    #D_1AF9
  1ABA  C6 07             LDB    #$07
L_1ABC:
  1ABC  A6 80             LDA    ,X+
  1ABE  A7 A0             STA    ,Y+
  1AC0  5A                DECB
  1AC1  26 F9             BNE    L_1ABC
  1AC3  10 8E 01 01       LDY    #$0101                  ; queue ClearScore(1)
  1AC7  BD 45 21          JSR    >AddTask
  1ACA  8E 00 01          LDX    #$0001
L_1ACD:
  1ACD  BF 60 0E          STX    >Player2Ctrl
  1AD0  BD 19 F9          JSR    >ClearPlayfield
  1AD3  10 8E 60 40       LDY    #$6040
  1AD7  F6 60 20          LDB    >DipLives               ; lives per game (DIP)
  1ADA  E7 A0             STB    ,Y+
  1ADC  8E 1A F9          LDX    #D_1AF9
  1ADF  C6 07             LDB    #$07
L_1AE1:
  1AE1  A6 80             LDA    ,X+
  1AE3  A7 A0             STA    ,Y+
  1AE5  5A                DECB
  1AE6  26 F9             BNE    L_1AE1
  1AE8  10 8E 01 00       LDY    #$0100                  ; queue ClearScore(0)
  1AEC  BD 45 21          JSR    >AddTask
  1AEF  5F                CLRB
  1AF0  F7 60 0A          STB    >GameState              ; sub-state of GameMode
  1AF3  C6 03             LDB    #$03
  1AF5  F7 60 05          STB    >GameMode               ; 0 init, 1 attract, 2 credited, 3 game
  1AF8  39                RTS
D_1AF9:
  1AF9  01 4E 7D 01 00    FCB    $01,$4E,$7D,$01,$00,$00,$00

; =====================================================================
; ShowHighScoreTable: queue credits + strings $14-$19.
; =====================================================================
ShowHighScoreTable:
  1B00  10 8E 04 00       LDY    #$0400                  ; queue ShowCredits(0)
  1B04  BD 45 21          JSR    >AddTask
  1B07  10 8E 03 14       LDY    #$0314
  1B0B  86 06             LDA    #$06
  1B0D  97 02             STA    <$02
L_1B0F:
  1B0F  BD 45 21          JSR    >AddTask
  1B12  31 21             LEAY   1,Y
  1B14  0A 02             DEC    <$02
  1B16  26 F7             BNE    L_1B0F
  1B18  39                RTS

; =====================================================================
; SUB_1B19 (63 instructions)
; Uses:  NumCredits FlipScreen GameState Player2Ctrl DipCabinet $6040 Lives $622A ScreenNum WaitTimer TwoPlayers PaletteBank0 PaletteBank1
; Calls: AddTask ClearScreenAll SoundReset PaletteBankUpdate
; =====================================================================
SUB_1B19:
  1B19  8E 60 01          LDX    #NumCredits
  1B1C  86 99             LDA    #$99
  1B1E  AB 84             ADDA   ,X
  1B20  19                DAA
  1B21  A7 84             STA    ,X
  1B23  10 8E 04 00       LDY    #$0400                  ; queue ShowCredits(0)
  1B27  BD 45 21          JSR    >AddTask
  1B2A  39                RTS
L_1B2B:
  1B2B  BD 19 D2          JSR    >ClearScreenAll
  1B2E  BD 11 B1          JSR    >SoundReset
  1B31  10 8E 7D 82       LDY    #FlipScreen
  1B35  C6 01             LDB    #$01
  1B37  E7 A4             STB    ,Y
  1B39  8E 60 0A          LDX    #GameState
  1B3C  F6 60 0E          LDB    >Player2Ctrl
  1B3F  26 05             BNE    L_1B46
  1B41  86 01             LDA    #$01
  1B43  A7 84             STA    ,X
  1B45  39                RTS
L_1B46:
  1B46  F6 60 26          LDB    >DipCabinet
  1B49  5A                DECB
  1B4A  27 03             BEQ    L_1B4F
  1B4C  5F                CLRB
  1B4D  E7 A4             STB    ,Y
L_1B4F:
  1B4F  86 03             LDA    #$03
  1B51  A7 84             STA    ,X
  1B53  39                RTS
L_1B54:
  1B54  8E 60 40          LDX    #$6040
  1B57  10 8E 62 28       LDY    #Lives
  1B5B  C6 08             LDB    #$08
L_1B5D:
  1B5D  A6 80             LDA    ,X+
  1B5F  A7 A0             STA    ,Y+
  1B61  5A                DECB
  1B62  26 F9             BNE    L_1B5D
  1B64  BE 62 2A          LDX    >$622A
  1B67  E6 84             LDB    ,X
  1B69  F7 62 27          STB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  1B6C  8E 60 09          LDX    #WaitTimer
  1B6F  10 8E 60 0A       LDY    #GameState
  1B73  F6 60 0F          LDB    >TwoPlayers
  1B76  27 0B             BEQ    L_1B83
  1B78  86 78             LDA    #$78
  1B7A  A7 84             STA    ,X
  1B7C  1E 21             EXG    Y,X
  1B7E  86 02             LDA    #$02
  1B80  A7 84             STA    ,X
  1B82  39                RTS
L_1B83:
  1B83  86 01             LDA    #$01
  1B85  A7 84             STA    ,X
  1B87  1E 21             EXG    Y,X
  1B89  86 05             LDA    #$05
  1B8B  A7 84             STA    ,X
  1B8D  39                RTS
L_1B8E:
  1B8E  5F                CLRB
  1B8F  F7 7D 86          STB    >PaletteBank0           ; palette bank bit 0
  1B92  F7 7D 87          STB    >PaletteBank1           ; palette bank bit 1
  1B95  BD 53 66          JSR    >PaletteBankUpdate
  1B98  10 8E 03 02       LDY    #$0302                  ; show "PLAYER ~~~"
  1B9C  BD 45 21          JSR    >AddTask
  1B9F  10 8E 02 01       LDY    #$0201                  ; queue ShowScore(1)
  1BA3  BD 45 21          JSR    >AddTask
  1BA6  C6 05             LDB    #$05
  1BA8  F7 60 0A          STB    >GameState              ; sub-state of GameMode

; =====================================================================
; SUB_1BAB (44 instructions)
; Uses:  $74E0 $74C0 $74A0 $6048 Lives $622A ScreenNum WaitTimer GameState PaletteBank0 PaletteBank1
; Calls: PaletteBankUpdate AddTask SUB_1BAB
; =====================================================================
SUB_1BAB:
  1BAB  C6 02             LDB    #$02
  1BAD  F7 74 E0          STB    >$74E0
  1BB0  C6 25             LDB    #$25
  1BB2  F7 74 C0          STB    >$74C0
  1BB5  C6 20             LDB    #$20
  1BB7  F7 74 A0          STB    >$74A0
  1BBA  39                RTS
L_1BBB:
  1BBB  8E 60 48          LDX    #$6048
  1BBE  10 8E 62 28       LDY    #Lives
  1BC2  C6 08             LDB    #$08
L_1BC4:
  1BC4  A6 80             LDA    ,X+
  1BC6  A7 A0             STA    ,Y+
  1BC8  5A                DECB
  1BC9  26 F9             BNE    L_1BC4
  1BCB  BE 62 2A          LDX    >$622A
  1BCE  E6 84             LDB    ,X
  1BD0  F7 62 27          STB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  1BD3  C6 78             LDB    #$78
  1BD5  F7 60 09          STB    >WaitTimer              ; frame countdown (RST_WaitTimer)
  1BD8  C6 04             LDB    #$04
  1BDA  F7 60 0A          STB    >GameState              ; sub-state of GameMode
  1BDD  39                RTS
L_1BDE:
  1BDE  5F                CLRB
  1BDF  F7 7D 86          STB    >PaletteBank0           ; palette bank bit 0
  1BE2  F7 7D 87          STB    >PaletteBank1           ; palette bank bit 1
  1BE5  BD 53 66          JSR    >PaletteBankUpdate
  1BE8  10 8E 03 03       LDY    #$0303                  ; show "PLAYER ~~~"
  1BEC  BD 45 21          JSR    >AddTask
  1BEF  10 8E 02 01       LDY    #$0201                  ; queue ShowScore(1)
  1BF3  BD 45 21          JSR    >AddTask
  1BF6  8D B3             BSR    SUB_1BAB
  1BF8  C6 05             LDB    #$05
  1BFA  F7 60 0A          STB    >GameState              ; sub-state of GameMode
  1BFD  39                RTS
L_1BFE:
  1BFE  10 8E 03 04       LDY    #$0304                  ; show "HIGH SCORE"
  1C02  BD 45 21          JSR    >AddTask
  1C05  10 8E 02 02       LDY    #$0202                  ; queue ShowScore(2)
  1C09  BD 45 21          JSR    >AddTask
  1C0C  10 8E 02 00       LDY    #$0200                  ; queue ShowScore(0)
  1C10  BD 45 21          JSR    >AddTask
  1C13  10 8E 06 00       LDY    #$0600                  ; queue ShowLivesLevel(0)
  1C17  BD 45 21          JSR    >AddTask
  1C1A  8E 60 0A          LDX    #GameState
  1C1D  6C 84             INC    ,X

; =====================================================================
; Draw1UP: tiles 1,U,P at the top of the screen.
; =====================================================================
Draw1UP:
  1C1F  C6 01             LDB    #$01
  1C21  F7 77 40          STB    >$7740
  1C24  C6 25             LDB    #$25
  1C26  F7 77 20          STB    >$7720
  1C29  C6 20             LDB    #$20
  1C2B  F7 77 00          STB    >$7700
  1C2E  39                RTS
L_1C2F:
  1C2F  9D 3F             JSR    <RST_WaitTimer
  1C31  BD 19 F9          JSR    >ClearPlayfield
  1C34  8E 60 09          LDX    #WaitTimer
  1C37  86 01             LDA    #$01
  1C39  A7 80             STA    ,X+
  1C3B  6C 84             INC    ,X
  1C3D  10 8E 62 2C       LDY    #$622C
  1C41  E6 A4             LDB    ,Y
  1C43  26 02             BNE    L_1C47
  1C45  6C 84             INC    ,X
L_1C47:
  1C47  39                RTS

; =====================================================================
; Game state 7: sub-steps on $6385 (TBL_Step6385).
; =====================================================================
L_1C48:
  1C48  F6 63 85          LDB    >$6385
  1C4B  9D 47             JSR    <RST_JumpTable
TBL_Step6385:
  1C4D  1C 5D             FDB    L_1C5D
  1C4F  1C 97             FDB    L_1C97
  1C51  1C CA             FDB    L_1CCA
  1C53  44 D4             FDB    L_44D4
  1C55  1C EC             FDB    L_1CEC
  1C57  44 D4             FDB    L_44D4
  1C59  1D 5D             FDB    L_1D5D
  1C5B  1D B0             FDB    L_1DB0
L_1C5D:
  1C5D  5F                CLRB
  1C5E  F7 7D 86          STB    >PaletteBank0           ; palette bank bit 0
  1C61  5C                INCB
  1C62  F7 7D 87          STB    >PaletteBank1           ; palette bank bit 1
  1C65  BD 53 66          JSR    >PaletteBankUpdate
  1C68  10 8E 4C 25       LDY    #D_4C25
  1C6C  BD 1F D6          JSR    >SUB_1FD6
  1C6F  C6 10             LDB    #$10
  1C71  F7 76 A3          STB    >$76A3
  1C74  F7 76 63          STB    >$7663
  1C77  C6 D4             LDB    #$D4
  1C79  F7 75 AA          STB    >$75AA
  1C7C  5F                CLRB
  1C7D  F7 62 AF          STB    >$62AF
  1C80  8E 4C 9C          LDX    #D_4C9C
  1C83  BF 63 C2          STX    >$63C2
  1C86  8E 4C B3          LDX    #D_4CB3
  1C89  BF 63 C4          STX    >$63C4
  1C8C  C6 40             LDB    #$40
  1C8E  F7 60 09          STB    >WaitTimer              ; frame countdown (RST_WaitTimer)
  1C91  8E 63 85          LDX    #$6385
  1C94  6C 84             INC    ,X
  1C96  39                RTS
L_1C97:
  1C97  9D 3F             JSR    <RST_WaitTimer
  1C99  8E 4C 74          LDX    #D_4C74
  1C9C  9D 77             JSR    <RST_CopySprites
  1C9E  8E 69 08          LDX    #$6908
  1CA1  86 30             LDA    #$30
  1CA3  97 03             STA    <$03
  1CA5  9D 4F             JSR    <RST_AddToObjects
  1CA7  8E 69 0B          LDX    #$690B
  1CAA  86 99             LDA    #$99
  1CAC  97 03             STA    <$03
  1CAE  9D 4F             JSR    <RST_AddToObjects
  1CB0  C6 1F             LDB    #$1F
  1CB2  F7 63 8E          STB    >$638E
  1CB5  5F                CLRB
  1CB6  F7 69 0C          STB    >$690C
  1CB9  8E 60 8A          LDX    #MusicReq2
  1CBC  86 01             LDA    #$01
  1CBE  A7 80             STA    ,X+
  1CC0  86 03             LDA    #$03
  1CC2  A7 84             STA    ,X
  1CC4  8E 63 85          LDX    #$6385
  1CC7  6C 84             INC    ,X
  1CC9  39                RTS
L_1CCA:
  1CCA  BD 44 DC          JSR    >SUB_44DC
  1CCD  F6 62 AF          LDB    >$62AF
  1CD0  C4 0F             ANDB   #$0F
  1CD2  26 03             BNE    L_1CD7
  1CD4  BD 44 B0          JSR    >SUB_44B0
L_1CD7:
  1CD7  F6 69 0B          LDB    >$690B
  1CDA  C1 5D             CMPB   #$5D
  1CDC  24 0D             BCC    L_1CEB
  1CDE  C6 20             LDB    #$20
  1CE0  F7 60 09          STB    >WaitTimer              ; frame countdown (RST_WaitTimer)
  1CE3  8E 63 85          LDX    #$6385
  1CE6  6C 84             INC    ,X
  1CE8  BF 63 C0          STX    >$63C0
L_1CEB:
  1CEB  39                RTS
L_1CEC:
  1CEC  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  1CEF  56                RORB
  1CF0  25 F9             BCS    L_1CEB
  1CF2  BE 63 C2          LDX    >$63C2
  1CF5  E6 84             LDB    ,X
  1CF7  C1 7F             CMPB   #$7F
  1CF9  27 0D             BEQ    L_1D08
  1CFB  30 01             LEAX   1,X
  1CFD  BF 63 C2          STX    >$63C2
  1D00  D7 03             STB    <$03
  1D02  8E 69 0B          LDX    #$690B
  1D05  9D 4F             JSR    <RST_AddToObjects
  1D07  39                RTS
L_1D08:
  1D08  8E 4D B7          LDX    #D_4DB7
  1D0B  9D 77             JSR    <RST_CopySprites
  1D0D  10 8E 69 00       LDY    #SpriteBuf
  1D11  C6 08             LDB    #$08
L_1D13:
  1D13  A6 80             LDA    ,X+
  1D15  A7 A0             STA    ,Y+
  1D17  5A                DECB
  1D18  26 F9             BNE    L_1D13
  1D1A  8E 69 08          LDX    #$6908
  1D1D  86 50             LDA    #$50
  1D1F  97 03             STA    <$03
  1D21  9D 4F             JSR    <RST_AddToObjects
  1D23  8E 69 0B          LDX    #$690B
  1D26  86 FC             LDA    #$FC
  1D28  97 03             STA    <$03
  1D2A  9D 4F             JSR    <RST_AddToObjects
L_1D2C:
  1D2C  BD 44 B0          JSR    >SUB_44B0
  1D2F  F6 63 8E          LDB    >$638E
  1D32  C1 0A             CMPB   #$0A
  1D34  26 F6             BNE    L_1D2C
  1D36  C6 03             LDB    #$03
  1D38  F7 60 82          STB    >SndBoom
  1D3B  10 8E 4D 14       LDY    #D_4D14
  1D3F  BD 1F D6          JSR    >SUB_1FD6
  1D42  C6 10             LDB    #$10
  1D44  F7 74 AA          STB    >$74AA
  1D47  F7 74 8A          STB    >$748A
  1D4A  C6 05             LDB    #$05
  1D4C  F7 63 8D          STB    >$638D
  1D4F  C6 20             LDB    #$20
  1D51  F7 60 09          STB    >WaitTimer              ; frame countdown (RST_WaitTimer)
  1D54  8E 63 85          LDX    #$6385
  1D57  6C 84             INC    ,X
  1D59  BF 63 C0          STX    >$63C0
  1D5C  39                RTS
L_1D5D:
  1D5D  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  1D60  56                RORB
  1D61  25 1E             BCS    L_1D81
  1D63  BE 63 C4          LDX    >$63C4
  1D66  E6 84             LDB    ,X
  1D68  C1 7F             CMPB   #$7F
  1D6A  27 16             BEQ    L_1D82
  1D6C  30 01             LEAX   1,X
  1D6E  BF 63 C4          STX    >$63C4
  1D71  8E 69 0B          LDX    #$690B
  1D74  D7 03             STB    <$03
  1D76  9D 4F             JSR    <RST_AddToObjects
  1D78  8E 69 08          LDX    #$6908
  1D7B  86 FF             LDA    #$FF
  1D7D  97 03             STA    <$03
  1D7F  9D 4F             JSR    <RST_AddToObjects
L_1D81:
  1D81  39                RTS
L_1D82:
  1D82  8E 4C B3          LDX    #D_4CB3
  1D85  BF 63 C4          STX    >$63C4
  1D88  C6 03             LDB    #$03
  1D8A  F7 60 82          STB    >SndBoom
  1D8D  8E 4C C4          LDX    #D_4CC4
  1D90  F6 63 8D          LDB    >$638D
  1D93  5A                DECB
  1D94  58                ASLB
  1D95  58                ASLB
  1D96  58                ASLB
  1D97  58                ASLB
  1D98  3A                ABX
  1D99  1F 12             TFR    X,Y
  1D9B  BD 1F D6          JSR    >SUB_1FD6
  1D9E  8E 63 8D          LDX    #$638D
  1DA1  6A 84             DEC    ,X
  1DA3  26 0A             BNE    L_1DAF
  1DA5  C6 B0             LDB    #$B0
  1DA7  F7 60 09          STB    >WaitTimer              ; frame countdown (RST_WaitTimer)
  1DAA  8E 63 85          LDX    #$6385
  1DAD  6C 84             INC    ,X
L_1DAF:
  1DAF  39                RTS
L_1DB0:
  1DB0  8E 60 8A          LDX    #MusicReq2
  1DB3  F6 60 09          LDB    >WaitTimer              ; frame countdown (RST_WaitTimer)
  1DB6  C1 90             CMPB   #$90
  1DB8  26 0F             BNE    L_1DC9
  1DBA  86 0F             LDA    #$0F
  1DBC  A7 80             STA    ,X+
  1DBE  86 03             LDA    #$03
  1DC0  A7 84             STA    ,X
  1DC2  8E 69 19          LDX    #$6919
  1DC5  6C 84             INC    ,X
  1DC7  20 09             BRA    L_1DD2
L_1DC9:
  1DC9  C1 18             CMPB   #$18
  1DCB  26 05             BNE    L_1DD2
  1DCD  8E 69 19          LDX    #$6919
  1DD0  6A 84             DEC    ,X
L_1DD2:
  1DD2  9D 3F             JSR    <RST_WaitTimer
  1DD4  5F                CLRB
  1DD5  F7 63 85          STB    >$6385
  1DD8  6C 80             INC    ,X+
  1DDA  6C 84             INC    ,X
  1DDC  39                RTS
L_1DDD:
  1DDD  BD 11 B1          JSR    >SoundReset
  1DE0  9D 3F             JSR    <RST_WaitTimer
  1DE2  BD 19 F9          JSR    >ClearPlayfield
  1DE5  86 06             LDA    #$06
  1DE7  F6 62 00          LDB    >MarioAlive             ; bit0 = Mario alive
  1DEA  1F 02             TFR    D,Y
  1DEC  BD 45 21          JSR    >AddTask
  1DEF  8E 7D 86          LDX    #PaletteBank0
  1DF2  86 01             LDA    #$01
  1DF4  A7 80             STA    ,X+
  1DF6  6F 84             CLR    ,X
  1DF8  BD 53 66          JSR    >PaletteBankUpdate
  1DFB  8E 60 8A          LDX    #MusicReq2
  1DFE  86 02             LDA    #$02
  1E00  A7 80             STA    ,X+
  1E02  86 03             LDA    #$03
  1E04  A7 84             STA    ,X
  1E06  8E 63 A7          LDX    #$63A7
  1E09  6F 84             CLR    ,X
  1E0B  8E 76 DC          LDX    #$76DC
  1E0E  BF 63 A8          STX    >$63A8
  1E11  F6 62 2E          LDB    >$622E
  1E14  C1 06             CMPB   #$06
  1E16  25 05             BCS    L_1E1D
  1E18  C6 05             LDB    #$05
  1E1A  F7 62 2E          STB    >$622E
L_1E1D:
  1E1D  F6 62 2F          LDB    >$622F
  1E20  D7 02             STB    <$02
  1E22  F6 62 2B          LDB    >$622B
  1E25  D1 02             CMPB   <$02
  1E27  27 05             BEQ    L_1E2E
  1E29  8E 62 2E          LDX    #$622E
  1E2C  6C 84             INC    ,X
L_1E2E:
  1E2E  F7 62 2F          STB    >$622F
  1E31  F6 62 2E          LDB    >$622E
  1E34  D7 02             STB    <$02
  1E36  8E 75 BC          LDX    #$75BC
L_1E39:
  1E39  86 50             LDA    #$50
L_1E3B:
  1E3B  A7 84             STA    ,X
  1E3D  4C                INCA
  1E3E  A7 82             STA    ,-X
  1E40  4C                INCA
  1E41  A7 82             STA    ,-X
  1E43  4C                INCA
  1E44  A7 82             STA    ,-X
  1E46  81 67             CMPA   #$67
  1E48  27 06             BEQ    L_1E50
  1E4A  4C                INCA
  1E4B  30 88 23          LEAX   <35,X
  1E4E  20 EB             BRA    L_1E3B
L_1E50:
  1E50  F6 63 A7          LDB    >$63A7
  1E53  5C                INCB
  1E54  F7 63 A7          STB    >$63A7
  1E57  5A                DECB
  1E58  58                ASLB
  1E59  58                ASLB
  1E5A  34 10             PSHS   X
  1E5C  8E 51 1D          LDX    #D_511D
  1E5F  FE 63 A8          LDU    >$63A8
  1E62  3A                ABX
  1E63  E6 80             LDB    ,X+
  1E65  E7 C8 60          STB    <96,U
  1E68  E6 80             LDB    ,X+
  1E6A  E7 C8 40          STB    <64,U
  1E6D  E6 84             LDB    ,X
  1E6F  E7 C8 20          STB    <32,U
  1E72  86 8B             LDA    #$8B
  1E74  A7 C8 E0          STA    <-32,U
  1E77  1F 31             TFR    U,X
  1E79  30 1C             LEAX   -4,X
  1E7B  BF 63 A8          STX    >$63A8
  1E7E  35 10             PULS   X
  1E80  30 89 FF 5F       LEAX   >-161,X
  1E84  0A 02             DEC    <$02
  1E86  26 B1             BNE    L_1E39
  1E88  10 8E 03 07       LDY    #$0307                  ; show "HOW HIGH CAN YOU GET ~ "
  1E8C  BD 45 21          JSR    >AddTask
  1E8F  8E 60 09          LDX    #WaitTimer
  1E92  86 A0             LDA    #$A0
  1E94  A7 80             STA    ,X+
  1E96  6C 84             INC    ,X
  1E98  6C 84             INC    ,X
  1E9A  39                RTS
L_1E9B:
  1E9B  9D 3F             JSR    <RST_WaitTimer
L_1E9D:
  1E9D  BD 19 F9          JSR    >ClearPlayfield
  1EA0  5F                CLRB
  1EA1  F7 63 8C          STB    >BonusTimer             ; bonus timer (BCD)
  1EA4  10 8E 05 01       LDY    #$0501                  ; queue BonusTimer(1)
  1EA8  BD 45 21          JSR    >AddTask
  1EAB  8E 7D 86          LDX    #PaletteBank0
  1EAE  6F 80             CLR    ,X+
  1EB0  86 01             LDA    #$01
  1EB2  A7 84             STA    ,X
  1EB4  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  1EB7  5A                DECB
  1EB8  27 2B             BEQ    L_1EE5
  1EBA  5A                DECB
  1EBB  27 36             BEQ    L_1EF3
  1EBD  5A                DECB
  1EBE  27 4A             BEQ    L_1F0A
  1EC0  BD 1F 60          JSR    >SUB_1F60
  1EC3  8E 7D 86          LDX    #PaletteBank0
  1EC6  86 01             LDA    #$01
  1EC8  A7 84             STA    ,X
  1ECA  BD 53 66          JSR    >PaletteBankUpdate
  1ECD  C6 0B             LDB    #$0B
  1ECF  F7 60 89          STB    >MusicReq               ; music number request
  1ED2  10 8E 50 B8       LDY    #D_50B8
L_1ED6:
  1ED6  BD 1F D6          JSR    >SUB_1FD6
  1ED9  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  1EDC  C1 04             CMPB   #$04
  1EDE  26 02             BNE    L_1EE2
  1EE0  8D 38             BSR    SUB_1F1A
L_1EE2:
  1EE2  7E 53 14          JMP    >L_5314
L_1EE5:
  1EE5  BD 53 66          JSR    >PaletteBankUpdate
  1EE8  10 8E 4F 11       LDY    #D_4F11
  1EEC  C6 08             LDB    #$08
  1EEE  F7 60 89          STB    >MusicReq               ; music number request
  1EF1  20 E3             BRA    L_1ED6
L_1EF3:
  1EF3  10 8E 4F 8A       LDY    #D_4F8A
  1EF7  8E 7D 86          LDX    #PaletteBank0
  1EFA  86 01             LDA    #$01
  1EFC  A7 80             STA    ,X+
  1EFE  6F 84             CLR    ,X
  1F00  BD 53 66          JSR    >PaletteBankUpdate
  1F03  C6 09             LDB    #$09
  1F05  F7 60 89          STB    >MusicReq               ; music number request
  1F08  20 CC             BRA    L_1ED6
L_1F0A:
  1F0A  BD 53 66          JSR    >PaletteBankUpdate
  1F0D  8D 34             BSR    SUB_1F43
  1F0F  C6 0A             LDB    #$0A
  1F11  F7 60 89          STB    >MusicReq               ; music number request
  1F14  10 8E 50 12       LDY    #D_5012
  1F18  20 BC             BRA    L_1ED6

; =====================================================================
; SUB_1F1A (13 instructions)
; =====================================================================
SUB_1F1A:
  1F1A  86 08             LDA    #$08
  1F1C  97 02             STA    <$02
  1F1E  8E 1F 33          LDX    #D_1F33
L_1F21:
  1F21  C6 B8             LDB    #$B8
  1F23  86 02             LDA    #$02
  1F25  10 AE 81          LDY    ,X++
L_1F28:
  1F28  E7 A0             STB    ,Y+
  1F2A  5A                DECB
  1F2B  4A                DECA
  1F2C  26 FA             BNE    L_1F28
  1F2E  0A 02             DEC    <$02
  1F30  26 EF             BNE    L_1F21
  1F32  39                RTS
D_1F33:
  1F33  76 CA 76 CF 76    FDB    $76CA,$76CF,$76D4,$76D9
  1F3B  75 2A 75 2F 75    FDB    $752A,$752F,$7534,$7539

; =====================================================================
; SUB_1F43 (3 instructions)
; Uses:  $770D $760D
; Calls: SUB_1F4B
; =====================================================================
SUB_1F43:
  1F43  8E 77 0D          LDX    #$770D
  1F46  8D 03             BSR    SUB_1F4B
  1F48  8E 76 0D          LDX    #$760D

; =====================================================================
; SUB_1F4B (12 instructions)
; =====================================================================
SUB_1F4B:
  1F4B  86 11             LDA    #$11
  1F4D  C6 FD             LDB    #$FD
L_1F4F:
  1F4F  E7 80             STB    ,X+
  1F51  4A                DECA
  1F52  26 FB             BNE    L_1F4F
  1F54  30 0F             LEAX   15,X
  1F56  86 11             LDA    #$11
  1F58  C6 FC             LDB    #$FC
L_1F5A:
  1F5A  E7 80             STB    ,X+
  1F5C  4A                DECA
  1F5D  26 FB             BNE    L_1F5A
  1F5F  39                RTS

; =====================================================================
; SUB_1F60 (3 instructions)
; Uses:  $7687 $7547
; Calls: SUB_1F68
; =====================================================================
SUB_1F60:
  1F60  8E 76 87          LDX    #$7687
  1F63  8D 03             BSR    SUB_1F68
  1F65  8E 75 47          LDX    #$7547

; =====================================================================
; SUB_1F68 (51 instructions)
; Uses:  WaitTimer SpriteBuf ScreenNum $690B $6908 $6903
; Calls: InitStage SUB_3891 RST_CopySprites RST_AddToObjects RST_AddToObjectsB
; =====================================================================
SUB_1F68:
  1F68  86 04             LDA    #$04
  1F6A  C6 FD             LDB    #$FD
L_1F6C:
  1F6C  E7 80             STB    ,X+
  1F6E  4A                DECA
  1F6F  26 FB             BNE    L_1F6C
  1F71  30 88 1C          LEAX   <28,X
  1F74  86 04             LDA    #$04
  1F76  C6 FC             LDB    #$FC
L_1F78:
  1F78  E7 80             STB    ,X+
  1F7A  4A                DECA
  1F7B  26 FB             BNE    L_1F78
  1F7D  39                RTS
L_1F7E:
  1F7E  BD 21 87          JSR    >InitStage
  1F81  BD 38 91          JSR    >SUB_3891
  1F84  8E 60 09          LDX    #WaitTimer
  1F87  86 40             LDA    #$40
  1F89  A7 80             STA    ,X+
  1F8B  6C 84             INC    ,X
  1F8D  8E 4D B7          LDX    #D_4DB7
  1F90  9D 77             JSR    <RST_CopySprites
  1F92  10 8E 69 00       LDY    #SpriteBuf
  1F96  C6 08             LDB    #$08
L_1F98:
  1F98  A6 80             LDA    ,X+
  1F9A  A7 A0             STA    ,Y+
  1F9C  5A                DECB
  1F9D  26 F9             BNE    L_1F98
  1F9F  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  1FA2  C1 04             CMPB   #$04
  1FA4  27 0E             BEQ    L_1FB4
  1FA6  54                LSRB
  1FA7  54                LSRB
  1FA8  25 2B             BCS    L_1FD5
  1FAA  8E 69 0B          LDX    #$690B
  1FAD  86 FC             LDA    #$FC
  1FAF  97 03             STA    <$03
  1FB1  9D 4F             JSR    <RST_AddToObjects
  1FB3  39                RTS
L_1FB4:
  1FB4  8E 69 08          LDX    #$6908
  1FB7  86 44             LDA    #$44
  1FB9  97 03             STA    <$03
  1FBB  9D 4F             JSR    <RST_AddToObjects
  1FBD  10 8E 00 04       LDY    #$0004
  1FC1  8E 02 10          LDX    #$0210
  1FC4  9F 02             STX    <$02
  1FC6  8E 69 00          LDX    #SpriteBuf
  1FC9  9D 57             JSR    <RST_AddToObjectsB
  1FCB  8E 02 F8          LDX    #$02F8
  1FCE  9F 02             STX    <$02
  1FD0  8E 69 03          LDX    #$6903
  1FD3  9D 57             JSR    <RST_AddToObjectsB
L_1FD5:
  1FD5  39                RTS

; =====================================================================
; SUB_1FD6 (185 instructions)
; Uses:  $63B3 $63AB $63B4 $63AF $63B1 $63B2 $63B0 $63AD $63B5
; Calls: SUB_443F
; =====================================================================
SUB_1FD6:
  1FD6  E6 A4             LDB    ,Y
  1FD8  F7 63 B3          STB    >$63B3
  1FDB  C1 AA             CMPB   #$AA
  1FDD  27 F6             BEQ    L_1FD5
  1FDF  31 21             LEAY   1,Y
  1FE1  EC A0             LDD    ,Y+
  1FE3  1F 01             TFR    D,X
  1FE5  DD 02             STD    <$02
  1FE7  34 20             PSHS   Y
  1FE9  BD 44 3F          JSR    >SUB_443F
  1FEC  35 20             PULS   Y
  1FEE  BF 63 AB          STX    >$63AB
  1FF1  D6 02             LDB    <$02
  1FF3  C4 07             ANDB   #$07
  1FF5  F7 63 B4          STB    >$63B4
  1FF8  D6 03             LDB    <$03
  1FFA  C4 07             ANDB   #$07
  1FFC  F7 63 AF          STB    >$63AF
  1FFF  31 21             LEAY   1,Y
  2001  E6 A0             LDB    ,Y+
  2003  1F 98             TFR    B,A
  2005  D0 02             SUBB   <$02
  2007  24 01             BCC    L_200A
  2009  50                NEGB
L_200A:
  200A  F7 63 B1          STB    >$63B1
  200D  E6 A4             LDB    ,Y
  200F  1F 01             TFR    D,X
  2011  D0 03             SUBB   <$03
  2013  F7 63 B2          STB    >$63B2
  2016  E6 A4             LDB    ,Y
  2018  C4 07             ANDB   #$07
  201A  F7 63 B0          STB    >$63B0
  201D  34 20             PSHS   Y
  201F  BD 44 3F          JSR    >SUB_443F
  2022  35 20             PULS   Y
  2024  BF 63 AD          STX    >$63AD
  2027  F6 63 B3          LDB    >$63B3
  202A  C1 02             CMPB   #$02
  202C  2A 5F             BPL    L_208D
  202E  F6 63 B2          LDB    >$63B2
  2031  C0 10             SUBB   #$10
  2033  D7 02             STB    <$02
  2035  F6 63 AF          LDB    >$63AF
  2038  DB 02             ADDB   <$02
  203A  F7 63 B2          STB    >$63B2
  203D  F6 63 AF          LDB    >$63AF
  2040  CB F0             ADDB   #$F0
  2042  BE 63 AB          LDX    >$63AB
  2045  E7 80             STB    ,X+
  2047  C0 30             SUBB   #$30
  2049  E7 84             STB    ,X
  204B  F6 63 B3          LDB    >$63B3
  204E  C1 01             CMPB   #$01
  2050  26 04             BNE    L_2056
  2052  5F                CLRB
  2053  F7 63 B2          STB    >$63B2
L_2056:
  2056  F6 63 B2          LDB    >$63B2
  2059  C0 08             SUBB   #$08
  205B  F7 63 B2          STB    >$63B2
  205E  25 08             BCS    L_2068
  2060  30 01             LEAX   1,X
  2062  86 C0             LDA    #$C0
  2064  A7 84             STA    ,X
  2066  20 EE             BRA    L_2056
L_2068:
  2068  F6 63 B0          LDB    >$63B0
  206B  CB D0             ADDB   #$D0
  206D  BE 63 AD          LDX    >$63AD
  2070  E7 84             STB    ,X
  2072  F6 63 B3          LDB    >$63B3
  2075  C1 01             CMPB   #$01
  2077  26 04             BNE    L_207D
  2079  86 C0             LDA    #$C0
  207B  A7 1F             STA    -1,X
L_207D:
  207D  F6 63 B0          LDB    >$63B0
  2080  27 06             BEQ    L_2088
  2082  CB E0             ADDB   #$E0
  2084  30 01             LEAX   1,X
  2086  E7 84             STB    ,X
L_2088:
  2088  31 21             LEAY   1,Y
  208A  7E 1F D6          JMP    >SUB_1FD6
L_208D:
  208D  F6 63 B3          LDB    >$63B3
  2090  C1 02             CMPB   #$02
  2092  10 26 00 89       LBNE   L_211F
  2096  F6 63 AF          LDB    >$63AF
  2099  CB F0             ADDB   #$F0
  209B  F7 63 B5          STB    >$63B5
  209E  BE 63 AB          LDX    >$63AB
L_20A1:
  20A1  F6 63 B5          LDB    >$63B5
  20A4  E7 80             STB    ,X+
  20A6  1F 10             TFR    X,D
  20A8  C4 1F             ANDB   #$1F
  20AA  27 0B             BEQ    L_20B7
  20AC  F6 63 B5          LDB    >$63B5
  20AF  C1 F0             CMPB   #$F0
  20B1  27 04             BEQ    L_20B7
  20B3  C0 10             SUBB   #$10
  20B5  E7 84             STB    ,X
L_20B7:
  20B7  30 88 1F          LEAX   <31,X
  20BA  F6 63 B1          LDB    >$63B1
  20BD  C0 08             SUBB   #$08
  20BF  25 44             BCS    L_2105
  20C1  F7 63 B1          STB    >$63B1
  20C4  F6 63 B2          LDB    >$63B2
  20C7  27 D8             BEQ    L_20A1
  20C9  F6 63 B5          LDB    >$63B5
  20CC  E7 80             STB    ,X+
  20CE  1F 10             TFR    X,D
  20D0  C4 1F             ANDB   #$1F
  20D2  27 07             BEQ    L_20DB
  20D4  F6 63 B5          LDB    >$63B5
  20D7  C0 10             SUBB   #$10
  20D9  E7 84             STB    ,X
L_20DB:
  20DB  30 88 1F          LEAX   <31,X
  20DE  F6 63 B1          LDB    >$63B1
  20E1  C0 08             SUBB   #$08
  20E3  25 20             BCS    L_2105
  20E5  F7 63 B1          STB    >$63B1
  20E8  F6 63 B2          LDB    >$63B2
  20EB  2B 1D             BMI    L_210A
  20ED  F6 63 B5          LDB    >$63B5
  20F0  5C                INCB
  20F1  F7 63 B5          STB    >$63B5
  20F4  C1 F8             CMPB   #$F8
  20F6  26 07             BNE    L_20FF
  20F8  30 01             LEAX   1,X
  20FA  C6 F0             LDB    #$F0
  20FC  F7 63 B5          STB    >$63B5
L_20FF:
  20FF  1F 10             TFR    X,D
  2101  C4 1F             ANDB   #$1F
  2103  26 9C             BNE    L_20A1
L_2105:
  2105  31 21             LEAY   1,Y
  2107  7E 1F D6          JMP    >SUB_1FD6
L_210A:
  210A  F6 63 B5          LDB    >$63B5
  210D  5A                DECB
  210E  F7 63 B5          STB    >$63B5
  2111  C1 F0             CMPB   #$F0
  2113  2A 07             BPL    L_211C
  2115  30 1F             LEAX   -1,X
  2117  C6 F7             LDB    #$F7
  2119  F7 63 B5          STB    >$63B5
L_211C:
  211C  7E 20 A1          JMP    >L_20A1
L_211F:
  211F  F6 63 B3          LDB    >$63B3
  2122  C1 03             CMPB   #$03
  2124  26 2B             BNE    L_2151
  2126  BE 63 AB          LDX    >$63AB
  2129  C6 B3             LDB    #$B3
  212B  E7 84             STB    ,X
  212D  30 88 20          LEAX   <32,X
  2130  F6 63 B1          LDB    >$63B1
  2133  C0 10             SUBB   #$10
L_2135:
  2135  25 11             BCS    L_2148
  2137  F7 63 B1          STB    >$63B1
  213A  C6 B1             LDB    #$B1
  213C  E7 84             STB    ,X
  213E  30 88 20          LEAX   <32,X
  2141  F6 63 B1          LDB    >$63B1
  2144  C0 08             SUBB   #$08
  2146  20 ED             BRA    L_2135
L_2148:
  2148  C6 B2             LDB    #$B2
  214A  E7 84             STB    ,X
  214C  31 21             LEAY   1,Y
  214E  7E 1F D6          JMP    >SUB_1FD6
L_2151:
  2151  F6 63 B3          LDB    >$63B3
  2154  C1 07             CMPB   #$07
  2156  2A AD             BPL    L_2105
  2158  C1 04             CMPB   #$04
  215A  27 23             BEQ    L_217F
  215C  C1 05             CMPB   #$05
  215E  27 23             BEQ    L_2183
  2160  C6 FE             LDB    #$FE
L_2162:
  2162  F7 63 B5          STB    >$63B5
  2165  BE 63 AB          LDX    >$63AB
L_2168:
  2168  F6 63 B5          LDB    >$63B5
  216B  E7 84             STB    ,X
  216D  30 88 20          LEAX   <32,X
  2170  F6 63 B1          LDB    >$63B1
  2173  C0 08             SUBB   #$08
  2175  F7 63 B1          STB    >$63B1
  2178  24 EE             BCC    L_2168
  217A  31 21             LEAY   1,Y
  217C  7E 1F D6          JMP    >SUB_1FD6
L_217F:
  217F  C6 10             LDB    #$10
  2181  20 DF             BRA    L_2162
L_2183:
  2183  C6 B0             LDB    #$B0
  2185  20 DB             BRA    L_2162

; =====================================================================
; InitStage: clear Mario ($6200) and object tables ($6280-$6AFF),
; load defaults, bonus timer = level*10+40 (max 80, i.e. 8000), then the
; per-screen setup through TBL_InitStage.
; =====================================================================
InitStage:
  2187  86 27             LDA    #$27
  2189  8E 62 00          LDX    #MarioAlive
  218C  5F                CLRB
L_218D:
  218D  E7 80             STB    ,X+
  218F  4A                DECA
  2190  26 FB             BNE    L_218D
  2192  86 11             LDA    #$11
  2194  97 03             STA    <$03
  2196  8E 62 80          LDX    #$6280
L_2199:
  2199  86 80             LDA    #$80
L_219B:
  219B  E7 80             STB    ,X+
  219D  4A                DECA
  219E  26 FB             BNE    L_219B
  21A0  0A 03             DEC    <$03
  21A2  26 F5             BNE    L_2199
  21A4  8E 51 C9          LDX    #D_51C9
  21A7  10 8E 62 80       LDY    #$6280
  21AB  86 20             LDA    #$20
  21AD  DF 08             STU    <$08
L_21AF:
  21AF  EE 81             LDU    ,X++
  21B1  EF A1             STU    ,Y++
  21B3  4A                DECA
  21B4  26 F9             BNE    L_21AF
  21B6  DE 08             LDU    <$08
  21B8  F6 62 29          LDB    >Level                  ; level number
  21BB  86 0A             LDA    #$0A
  21BD  3D                MUL
  21BE  CB 28             ADDB   #$28
  21C0  C1 51             CMPB   #$51
  21C2  25 02             BCS    L_21C6
  21C4  C6 50             LDB    #$50
L_21C6:
  21C6  8E 62 B0          LDX    #$62B0
  21C9  86 03             LDA    #$03
L_21CB:
  21CB  E7 80             STB    ,X+
  21CD  4A                DECA
  21CE  26 FB             BNE    L_21CB
  21D0  58                ASLB
  21D1  D7 02             STB    <$02
  21D3  C6 DC             LDB    #$DC
  21D5  D0 02             SUBB   <$02
  21D7  C1 28             CMPB   #$28
  21D9  24 02             BCC    L_21DD
  21DB  C6 28             LDB    #$28
L_21DD:
  21DD  E7 80             STB    ,X+
  21DF  E7 84             STB    ,X
  21E1  8E 62 09          LDX    #$6209
  21E4  86 04             LDA    #$04
  21E6  A7 80             STA    ,X+
  21E8  86 08             LDA    #$08
  21EA  A7 84             STA    ,X
  21EC  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  21EF  D7 03             STB    <$03
  21F1  C4 04             ANDB   #$04
  21F3  26 1D             BNE    L_2212
  21F5  8E 6A 00          LDX    #$6A00
  21F8  C6 4F             LDB    #$4F
  21FA  86 03             LDA    #$03
  21FC  97 02             STA    <$02
L_21FE:
  21FE  E7 80             STB    ,X+
  2200  86 3A             LDA    #$3A
  2202  A7 80             STA    ,X+
  2204  86 0F             LDA    #$0F
  2206  A7 80             STA    ,X+
  2208  86 18             LDA    #$18
  220A  A7 80             STA    ,X+
  220C  CB 10             ADDB   #$10
  220E  0A 02             DEC    <$02
  2210  26 EC             BNE    L_21FE
L_2212:
  2212  D6 03             LDB    <$03
  2214  9D 47             JSR    <RST_JumpTable
TBL_InitStage:
  2216  11 14             FDB    ColdStart
  2218  22 20             FDB    InitStage_Girders
  221A  22 7A             FDB    InitStage_Conveyors
  221C  22 FE             FDB    InitStage_Elevators
  221E  23 BA             FDB    InitStage_Rivets
InitStage_Girders:
  2220  8E 52 09          LDX    #D_5209
  2223  10 8E 69 A8       LDY    #$69A8
  2227  C6 10             LDB    #$10
L_2229:
  2229  A6 80             LDA    ,X+
  222B  A7 A0             STA    ,Y+
  222D  5A                DECB
  222E  26 F9             BNE    L_2229
  2230  8E 52 19          LDX    #D_5219
  2233  10 8E 64 07       LDY    #$6407
  2237  CC 05 1C          LDD    #$051C
  223A  DD 02             STD    <$02
  223C  BD 24 CA          JSR    >SUB_24CA
  223F  8E 52 21          LDX    #D_5221
  2242  BD 24 9E          JSR    >SUB_249E
  2245  8E 52 2D          LDX    #D_522D
  2248  10 8E 69 FC       LDY    #$69FC
  224C  C6 04             LDB    #$04
L_224E:
  224E  A6 80             LDA    ,X+
  2250  A7 A0             STA    ,Y+
  2252  5A                DECB
  2253  26 F9             BNE    L_224E
  2255  8E 52 39          LDX    #D_5239
  2258  BD 24 40          JSR    >SUB_2440
  225B  8E 22 76          LDX    #D_2276
  225E  10 8E 67 07       LDY    #$6707
  2262  CC 08 1C          LDD    #$081C
  2265  DD 02             STD    <$02
  2267  BD 24 CA          JSR    >SUB_24CA
  226A  10 8E 68 07       LDY    #$6807
  226E  86 02             LDA    #$02
  2270  97 02             STA    <$02
  2272  BD 24 CA          JSR    >SUB_24CA
  2275  39                RTS
D_2276:
  2276  00 00 02 02       FCB    $00,$00,$02,$02
InitStage_Conveyors:
  227A  8E 52 19          LDX    #D_5219
  227D  10 8E 64 07       LDY    #$6407
  2281  CC 05 1C          LDD    #$051C
  2284  DD 02             STD    <$02
  2286  BD 24 CA          JSR    >SUB_24CA
  2289  BD 24 1C          JSR    >SUB_241C
  228C  8E 52 45          LDX    #D_5245
  228F  10 8E 65 A7       LDY    #$65A7
  2293  CC 06 0C          LDD    #$060C
  2296  DD 02             STD    <$02
  2298  BD 24 CA          JSR    >SUB_24CA
  229B  CE 65 A0          LDU    #$65A0
  229E  8E 69 B8          LDX    #$69B8
  22A1  10 8E 00 10       LDY    #$0010
  22A5  86 06             LDA    #$06
  22A7  97 02             STA    <$02
  22A9  BD 24 72          JSR    >SUB_2472
  22AC  8E 52 27          LDX    #D_5227
  22AF  BD 24 9E          JSR    >SUB_249E
  22B2  8E 52 31          LDX    #D_5231
  22B5  10 8E 69 FC       LDY    #$69FC
  22B9  C6 04             LDB    #$04
L_22BB:
  22BB  A6 80             LDA    ,X+
  22BD  A7 A0             STA    ,Y+
  22BF  5A                DECB
  22C0  26 F9             BNE    L_22BB
  22C2  8E 52 49          LDX    #D_5249
  22C5  10 8E 69 44       LDY    #$6944
  22C9  C6 08             LDB    #$08
L_22CB:
  22CB  A6 80             LDA    ,X+
  22CD  A7 A0             STA    ,Y+
  22CF  5A                DECB
  22D0  26 F9             BNE    L_22CB
  22D2  8E 52 51          LDX    #D_5251
  22D5  10 8E 69 E4       LDY    #$69E4
  22D9  C6 18             LDB    #$18
L_22DB:
  22DB  A6 80             LDA    ,X+
  22DD  A7 A0             STA    ,Y+
  22DF  5A                DECB
  22E0  26 F9             BNE    L_22DB
  22E2  8E 52 3D          LDX    #D_523D
  22E5  BD 24 40          JSR    >SUB_2440
  22E8  8E 52 69          LDX    #D_5269
  22EB  10 8E 6A 0C       LDY    #$6A0C
  22EF  C6 0C             LDB    #$0C
L_22F1:
  22F1  A6 80             LDA    ,X+
  22F3  A7 A0             STA    ,Y+
  22F5  5A                DECB
  22F6  26 F9             BNE    L_22F1
  22F8  C6 01             LDB    #$01
  22FA  F7 62 B9          STB    >$62B9
  22FD  39                RTS
InitStage_Elevators:
  22FE  8E 52 19          LDX    #D_5219
  2301  10 8E 64 07       LDY    #$6407
  2305  CC 05 1C          LDD    #$051C
  2308  DD 02             STD    <$02
  230A  BD 24 CA          JSR    >SUB_24CA
  230D  BD 24 1C          JSR    >SUB_241C
  2310  8E 66 00          LDX    #$6600
  2313  C6 01             LDB    #$01
  2315  86 06             LDA    #$06
L_2317:
  2317  E7 84             STB    ,X
  2319  30 88 10          LEAX   <16,X
  231C  4A                DECA
  231D  26 F8             BNE    L_2317
  231F  86 02             LDA    #$02
  2321  97 03             STA    <$03
  2323  C6 08             LDB    #$08
L_2325:
  2325  86 03             LDA    #$03
  2327  8E 66 0D          LDX    #$660D
L_232A:
  232A  E7 84             STB    ,X
  232C  30 88 10          LEAX   <16,X
  232F  4A                DECA
  2330  26 F8             BNE    L_232A
  2332  0A 03             DEC    <$03
  2334  26 EF             BNE    L_2325
  2336  8E 52 91          LDX    #D_5291
  2339  10 8E 66 03       LDY    #$6603
  233D  CC 06 0E          LDD    #$060E
  2340  97 02             STA    <$02
  2342  BD 24 8F          JSR    >SUB_248F
  2345  8E 52 8D          LDX    #D_528D
  2348  10 8E 66 07       LDY    #$6607
  234C  CC 06 0C          LDD    #$060C
  234F  DD 02             STD    <$02
  2351  BD 24 CA          JSR    >SUB_24CA
  2354  CE 66 00          LDU    #$6600
  2357  8E 69 58          LDX    #$6958
  235A  86 06             LDA    #$06
  235C  97 02             STA    <$02
  235E  10 8E 00 10       LDY    #$0010
  2362  BD 24 72          JSR    >SUB_2472
  2365  8E 52 75          LDX    #D_5275
  2368  10 8E 6A 0C       LDY    #$6A0C
  236C  C6 06             LDB    #$06
L_236E:
  236E  EE 81             LDU    ,X++
  2370  EF A1             STU    ,Y++
  2372  5A                DECB
  2373  26 F9             BNE    L_236E
  2375  CE 64 00          LDU    #Fireballs
  2378  CC 01 58          LDD    #$0158
  237B  A7 C4             STA    ,U
  237D  E7 43             STB    3,U
  237F  E7 4E             STB    14,U
  2381  C6 80             LDB    #$80
  2383  E7 45             STB    5,U
  2385  E7 4F             STB    15,U
  2387  A7 C8 20          STA    <32,U
  238A  CC EB 60          LDD    #$EB60
  238D  A7 C8 23          STA    <35,U
  2390  A7 C8 2E          STA    <46,U
  2393  E7 C8 25          STB    <37,U
  2396  E7 C8 2F          STB    <47,U
  2399  10 8E 69 70       LDY    #$6970
  239D  8E 23 AA          LDX    #D_23AA
  23A0  C6 10             LDB    #$10
L_23A2:
  23A2  A6 80             LDA    ,X+
  23A4  A7 A0             STA    ,Y+
  23A6  5A                DECB
  23A7  26 F9             BNE    L_23A2
  23A9  39                RTS
D_23AA:
  23AA  37 45 0F 60 37    FCB    $37,$45,$0F,$60,$37,$C5,$0F,$F7
  23B2  77 45 0F 60 77    FCB    $77,$45,$0F,$60,$77,$C5,$0F,$F7
InitStage_Rivets:
  23BA  8E 52 1D          LDX    #D_521D
  23BD  10 8E 64 07       LDY    #$6407
  23C1  CC 05 1C          LDD    #$051C
  23C4  DD 02             STD    <$02
  23C6  BD 24 CA          JSR    >SUB_24CA
  23C9  8E 52 41          LDX    #D_5241
  23CC  8D 72             BSR    SUB_2440
  23CE  8E 52 81          LDX    #D_5281
  23D1  10 8E 6A 0C       LDY    #$6A0C
  23D5  C6 0C             LDB    #$0C
L_23D7:
  23D7  A6 80             LDA    ,X+
  23D9  A7 A0             STA    ,Y+
  23DB  5A                DECB
  23DC  26 F9             BNE    L_23D7
  23DE  8E 24 18          LDX    #D_2418
  23E1  10 8E 64 A3       LDY    #$64A3
  23E5  CC 02 1E          LDD    #$021E
  23E8  97 02             STA    <$02
  23EA  BD 24 8F          JSR    >SUB_248F
  23ED  8E 24 14          LDX    #D_2414
  23F0  10 8E 64 A7       LDY    #$64A7
  23F4  CC 02 1C          LDD    #$021C
  23F7  DD 02             STD    <$02
  23F9  BD 24 CA          JSR    >SUB_24CA
  23FC  CE 64 A0          LDU    #$64A0
  23FF  86 01             LDA    #$01
  2401  A7 C4             STA    ,U
  2403  A7 C8 20          STA    <32,U
  2406  8E 69 50          LDX    #$6950
  2409  86 02             LDA    #$02
  240B  97 02             STA    <$02
  240D  10 8E 00 20       LDY    #$0020
  2411  8D 5F             BSR    SUB_2472
  2413  39                RTS
D_2414:
  2414  3F 0C 08 08       FCB    $3F,$0C,$08,$08
D_2418:
  2418  73 50 8D 50       FCB    $73,$50,$8D,$50

; =====================================================================
; SUB_241C (12 instructions)
; Uses:  $6507 $6500 $6980
; Calls: SUB_24CA SUB_2472
; =====================================================================
SUB_241C:
  241C  8E 24 3C          LDX    #D_243C
  241F  10 8E 65 07       LDY    #$6507
  2423  CC 0A 0C          LDD    #$0A0C
  2426  DD 02             STD    <$02
  2428  BD 24 CA          JSR    >SUB_24CA
  242B  CE 65 00          LDU    #$6500
  242E  8E 69 80          LDX    #$6980
  2431  86 0A             LDA    #$0A
  2433  97 02             STA    <$02
  2435  10 8E 00 10       LDY    #$0010
  2439  8D 37             BSR    SUB_2472
  243B  39                RTS
D_243C:
  243C  3B 00 02 02       FCB    $3B,$00,$02,$02

; =====================================================================
; SUB_2440 (19 instructions)
; Uses:  $6683 $6687 $6680 $6A18
; Calls: SUB_248F SUB_24CA SUB_2472
; =====================================================================
SUB_2440:
  2440  10 8E 66 83       LDY    #$6683
  2444  CC 02 0E          LDD    #$020E
  2447  97 02             STA    <$02
  2449  8D 44             BSR    SUB_248F
  244B  8E 52 35          LDX    #D_5235
  244E  10 8E 66 87       LDY    #$6687
  2452  CC 02 0C          LDD    #$020C
  2455  DD 02             STD    <$02
  2457  BD 24 CA          JSR    >SUB_24CA
  245A  CE 66 80          LDU    #$6680
  245D  86 01             LDA    #$01
  245F  A7 C4             STA    ,U
  2461  A7 C8 10          STA    <16,U
  2464  8E 6A 18          LDX    #$6A18
  2467  86 02             LDA    #$02
  2469  97 02             STA    <$02
  246B  10 8E 00 10       LDY    #$0010
  246F  8D 01             BSR    SUB_2472
  2471  39                RTS

; =====================================================================
; SUB_2472 (15 instructions)
; =====================================================================
SUB_2472:
  2472  E6 43             LDB    3,U
  2474  C4 FE             ANDB   #$FE
  2476  E7 84             STB    ,X
  2478  E6 47             LDB    7,U
  247A  E7 01             STB    1,X
  247C  E6 45             LDB    5,U
  247E  E7 03             STB    3,X
  2480  30 04             LEAX   4,X
  2482  D7 01             STB    <$01
  2484  1F 20             TFR    Y,D
  2486  33 CB             LEAU   D,U
  2488  D6 01             LDB    <$01
  248A  0A 02             DEC    <$02
  248C  26 E4             BNE    SUB_2472
  248E  39                RTS

; =====================================================================
; SUB_248F (8 instructions)
; =====================================================================
SUB_248F:
  248F  A6 80             LDA    ,X+
  2491  A7 A1             STA    ,Y++
  2493  A6 80             LDA    ,X+
  2495  A7 A4             STA    ,Y
  2497  31 A5             LEAY   B,Y
  2499  0A 02             DEC    <$02
  249B  26 F2             BNE    SUB_248F
  249D  39                RTS

; =====================================================================
; SUB_249E (21 instructions)
; Uses:  $66A0 $6A28
; =====================================================================
SUB_249E:
  249E  CE 66 A0          LDU    #$66A0
  24A1  10 8E 6A 28       LDY    #$6A28
  24A5  86 01             LDA    #$01
  24A7  A7 C4             STA    ,U
  24A9  E6 80             LDB    ,X+
  24AB  E7 43             STB    3,U
  24AD  C4 FE             ANDB   #$FE
  24AF  E7 A4             STB    ,Y
  24B1  E6 80             LDB    ,X+
  24B3  E7 47             STB    7,U
  24B5  E7 21             STB    1,Y
  24B7  E6 80             LDB    ,X+
  24B9  E7 48             STB    8,U
  24BB  E6 80             LDB    ,X+
  24BD  E7 45             STB    5,U
  24BF  E7 23             STB    3,Y
  24C1  E6 80             LDB    ,X+
  24C3  E7 49             STB    9,U
  24C5  E6 84             LDB    ,X
  24C7  E7 4A             STB    10,U
  24C9  39                RTS

; =====================================================================
; SUB_24CA (215 instructions)
; Uses:  ScreenNum MarioAlive $694C GameState $639D $694D $639E WaitTimer SndDeath Player2Ctrl $622C Lives $6040 ScoreP1 ...
; Calls: RST_WaitTimer AddTask SUB_3195 RST_JumpTable SUB_453E SUB_455A SoundReset SUB_26AC SUB_2B55
; =====================================================================
SUB_24CA:
  24CA  34 10             PSHS   X
  24CC  86 04             LDA    #$04
L_24CE:
  24CE  E6 80             LDB    ,X+
  24D0  E7 A0             STB    ,Y+
  24D2  4A                DECA
  24D3  26 F9             BNE    L_24CE
  24D5  35 10             PULS   X
  24D7  96 03             LDA    <$03
  24D9  31 A6             LEAY   A,Y
  24DB  0A 02             DEC    <$02
  24DD  26 EB             BNE    SUB_24CA
  24DF  39                RTS
L_24E0:
  24E0  9D 3F             JSR    <RST_WaitTimer
  24E2  CC E0 16          LDD    #$E016
  24E5  DD 02             STD    <$02
  24E7  B6 62 27          LDA    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  24EA  81 03             CMPA   #$03
  24EC  27 05             BEQ    L_24F3
  24EE  CC F0 3F          LDD    #$F03F
  24F1  DD 02             STD    <$02
L_24F3:
  24F3  CE 62 00          LDU    #MarioAlive
  24F6  8E 69 4C          LDX    #$694C
  24F9  86 01             LDA    #$01
  24FB  A7 C4             STA    ,U
  24FD  E7 43             STB    3,U
  24FF  C4 FE             ANDB   #$FE
  2501  E7 84             STB    ,X
  2503  86 80             LDA    #$80
  2505  A7 47             STA    7,U
  2507  A7 01             STA    1,X
  2509  86 02             LDA    #$02
  250B  A7 48             STA    8,U
  250D  96 02             LDA    <$02
  250F  A7 45             STA    5,U
  2511  A7 03             STA    3,X
  2513  86 01             LDA    #$01
  2515  A7 4F             STA    15,U
  2517  8E 60 0A          LDX    #GameState
  251A  6C 84             INC    ,X
  251C  10 8E 06 01       LDY    #$0601                  ; queue ShowLivesLevel(1)
  2520  BD 45 21          JSR    >AddTask
  2523  39                RTS
L_2524:
  2524  BD 31 95          JSR    >SUB_3195
  2527  F6 63 9D          LDB    >$639D
  252A  9D 47             JSR    <RST_JumpTable
TBL_252C:
  252C  25 32             FDB    L_2532
  252E  25 56             FDB    L_2556
  2530  25 A1             FDB    L_25A1
L_2532:
  2532  9D 3F             JSR    <RST_WaitTimer
  2534  8E 69 4D          LDX    #$694D
  2537  C6 F0             LDB    #$F0
  2539  69 84             ROL    ,X
  253B  56                RORB
  253C  E7 84             STB    ,X
  253E  8E 63 9D          LDX    #$639D
  2541  6C 84             INC    ,X
  2543  C6 0D             LDB    #$0D
  2545  F7 63 9E          STB    >$639E
  2548  C6 08             LDB    #$08
  254A  F7 60 09          STB    >WaitTimer              ; frame countdown (RST_WaitTimer)
  254D  BD 45 3E          JSR    >SUB_453E
  2550  C6 03             LDB    #$03
  2552  F7 60 88          STB    >SndDeath
  2555  39                RTS
L_2556:
  2556  9D 3F             JSR    <RST_WaitTimer
  2558  C6 08             LDB    #$08
  255A  F7 60 09          STB    >WaitTimer              ; frame countdown (RST_WaitTimer)
  255D  8E 63 9E          LDX    #$639E
  2560  6A 84             DEC    ,X
  2562  27 28             BEQ    L_258C
  2564  8E 69 4D          LDX    #$694D
  2567  E6 84             LDB    ,X
  2569  56                RORB
  256A  C6 02             LDB    #$02
  256C  56                RORB
  256D  D7 02             STB    <$02
  256F  E8 84             EORB   ,X
  2571  E7 80             STB    ,X+
  2573  D6 02             LDB    <$02
  2575  C4 80             ANDB   #$80
  2577  A6 1F             LDA    -1,X
  2579  8A 40             ORA    #$40
  257B  E8 84             EORB   ,X
  257D  2A 0A             BPL    L_2589
  257F  81 79             CMPA   #$79
  2581  27 06             BEQ    L_2589
  2583  81 F9             CMPA   #$F9
  2585  27 02             BEQ    L_2589
  2587  84 BF             ANDA   #$BF
L_2589:
  2589  ED 1F             STD    -1,X
  258B  39                RTS
L_258C:
  258C  8E 69 4D          LDX    #$694D
  258F  C6 F4             LDB    #$F4
  2591  69 84             ROL    ,X
  2593  56                RORB
  2594  E7 84             STB    ,X
  2596  8E 63 9D          LDX    #$639D
  2599  6C 84             INC    ,X
  259B  C6 80             LDB    #$80
  259D  F7 60 09          STB    >WaitTimer              ; frame countdown (RST_WaitTimer)
  25A0  39                RTS
L_25A1:
  25A1  9D 3F             JSR    <RST_WaitTimer
  25A3  BD 45 5A          JSR    >SUB_455A
  25A6  8E 60 0A          LDX    #GameState
  25A9  F6 60 0E          LDB    >Player2Ctrl
  25AC  27 02             BEQ    L_25B0
  25AE  6C 84             INC    ,X
L_25B0:
  25B0  6C 84             INC    ,X
  25B2  86 01             LDA    #$01
  25B4  A7 82             STA    ,-X
  25B6  39                RTS
L_25B7:
  25B7  BD 11 B1          JSR    >SoundReset
  25BA  5F                CLRB
  25BB  F7 62 2C          STB    >$622C
  25BE  8E 62 28          LDX    #Lives
  25C1  6A 84             DEC    ,X
  25C3  E6 84             LDB    ,X
  25C5  10 8E 60 40       LDY    #$6040
  25C9  86 04             LDA    #$04
  25CB  DF 08             STU    <$08
L_25CD:
  25CD  EE 81             LDU    ,X++
  25CF  EF A1             STU    ,Y++
  25D1  4A                DECA
  25D2  26 F9             BNE    L_25CD
  25D4  DE 08             LDU    <$08
  25D6  5D                TSTB
  25D7  26 2F             BNE    L_2608
  25D9  C6 01             LDB    #$01
  25DB  8E 60 B2          LDX    #ScoreP1
  25DE  BD 26 AC          JSR    >SUB_26AC
  25E1  8E 76 D4          LDX    #$76D4
  25E4  F6 60 0F          LDB    >TwoPlayers
  25E7  27 09             BEQ    L_25F2
  25E9  10 8E 03 02       LDY    #$0302                  ; show "PLAYER ~~~"
  25ED  BD 45 21          JSR    >AddTask
  25F0  30 1F             LEAX   -1,X
L_25F2:
  25F2  BD 2B 55          JSR    >SUB_2B55
  25F5  10 8E 03 00       LDY    #$0300                  ; show "GAME  OVER"
  25F9  BD 45 21          JSR    >AddTask
  25FC  8E 60 09          LDX    #WaitTimer
  25FF  86 C0             LDA    #$C0
  2601  A7 80             STA    ,X+
  2603  86 10             LDA    #$10
  2605  A7 84             STA    ,X
  2607  39                RTS
L_2608:
  2608  C6 08             LDB    #$08
  260A  B6 60 0F          LDA    >TwoPlayers
  260D  27 02             BEQ    L_2611
  260F  C6 17             LDB    #$17
L_2611:
  2611  D7 03             STB    <$03
  2613  F7 60 0A          STB    >GameState              ; sub-state of GameMode
  2616  39                RTS
L_2617:
  2617  BD 11 B1          JSR    >SoundReset
  261A  5F                CLRB
  261B  F7 62 2C          STB    >$622C
  261E  8E 62 28          LDX    #Lives
  2621  6A 84             DEC    ,X
  2623  E6 84             LDB    ,X
  2625  10 8E 60 48       LDY    #$6048
  2629  86 04             LDA    #$04
  262B  DF 08             STU    <$08
L_262D:
  262D  EE 81             LDU    ,X++
  262F  EF A1             STU    ,Y++
  2631  4A                DECA
  2632  26 F9             BNE    L_262D
  2634  DE 08             LDU    <$08
  2636  5D                TSTB
  2637  26 27             BNE    L_2660
  2639  C6 03             LDB    #$03
  263B  8E 60 B5          LDX    #ScoreP2
  263E  8D 6C             BSR    SUB_26AC
  2640  10 8E 03 03       LDY    #$0303                  ; show "PLAYER ~~~"
  2644  BD 45 21          JSR    >AddTask
  2647  10 8E 03 00       LDY    #$0300                  ; show "GAME  OVER"
  264B  BD 45 21          JSR    >AddTask
  264E  8E 76 D3          LDX    #$76D3
  2651  BD 2B 55          JSR    >SUB_2B55
  2654  8E 60 09          LDX    #WaitTimer
  2657  86 C0             LDA    #$C0
  2659  A7 80             STA    ,X+
  265B  86 11             LDA    #$11
  265D  A7 84             STA    ,X
  265F  39                RTS
L_2660:
  2660  C6 17             LDB    #$17
  2662  B6 60 40          LDA    >$6040
  2665  26 02             BNE    L_2669
  2667  C6 08             LDB    #$08
L_2669:
  2669  D7 03             STB    <$03
  266B  F7 60 0A          STB    >GameState              ; sub-state of GameMode
  266E  39                RTS
L_266F:
  266F  9D 3F             JSR    <RST_WaitTimer
  2671  C6 17             LDB    #$17
  2673  B6 60 48          LDA    >$6048
L_2676:
  2676  6C 84             INC    ,X
  2678  4D                TSTA
  2679  26 02             BNE    L_267D
  267B  C6 14             LDB    #$14
L_267D:
  267D  D7 03             STB    <$03
  267F  F7 60 0A          STB    >GameState              ; sub-state of GameMode
  2682  39                RTS
L_2683:
  2683  9D 3F             JSR    <RST_WaitTimer
  2685  C6 17             LDB    #$17
  2687  B6 60 40          LDA    >$6040
  268A  20 EA             BRA    L_2676
L_268C:
  268C  F6 60 26          LDB    >DipCabinet
  268F  F7 7D 82          STB    >FlipScreen             ; flip screen
  2692  5F                CLRB
  2693  F7 60 0A          STB    >GameState              ; sub-state of GameMode
  2696  8E 01 01          LDX    #$0101
  2699  BF 60 0D          STX    >PlayerUp               ; 0 = player 1, 1 = player 2
  269C  39                RTS
L_269D:
  269D  5F                CLRB
  269E  F7 60 0D          STB    >PlayerUp               ; 0 = player 1, 1 = player 2
  26A1  F7 60 0E          STB    >Player2Ctrl
  26A4  F7 60 0A          STB    >GameState              ; sub-state of GameMode
  26A7  5C                INCB
  26A8  F7 7D 82          STB    >FlipScreen             ; flip screen
  26AB  39                RTS

; =====================================================================
; SUB_26AC (260 instructions)
; Uses:  $61C6 $61B1 $61A5 $61C7 Player2Ctrl PlayerUp $611C DipCabinet FlipScreen WaitTimer GameState GameMode AttractFlag PaletteBank0 ...
; Calls: RST_RetIfAttract ShowCredits RST_WaitTimer ClearPlayfield AddTask PaletteBankUpdate SUB_28F7 DrawBCD
; =====================================================================
SUB_26AC:
  26AC  10 8E 61 C6       LDY    #$61C6
  26B0  E7 A4             STB    ,Y
  26B2  9D 2F             JSR    <RST_RetIfAttract
  26B4  31 21             LEAY   1,Y
  26B6  C6 03             LDB    #$03
L_26B8:
  26B8  A6 80             LDA    ,X+
  26BA  A7 A0             STA    ,Y+
  26BC  5A                DECB
  26BD  26 F9             BNE    L_26B8
  26BF  86 03             LDA    #$03
  26C1  8E 61 B1          LDX    #$61B1
L_26C4:
  26C4  E6 A2             LDB    ,-Y
  26C6  54                LSRB
  26C7  54                LSRB
  26C8  54                LSRB
  26C9  54                LSRB
  26CA  E7 80             STB    ,X+
  26CC  E6 A4             LDB    ,Y
  26CE  C4 0F             ANDB   #$0F
  26D0  E7 80             STB    ,X+
  26D2  4A                DECA
  26D3  26 EF             BNE    L_26C4
  26D5  86 0E             LDA    #$0E
  26D7  C6 10             LDB    #$10
L_26D9:
  26D9  E7 80             STB    ,X+
  26DB  4A                DECA
  26DC  26 FB             BNE    L_26D9
  26DE  C6 3F             LDB    #$3F
  26E0  E7 84             STB    ,X
  26E2  86 05             LDA    #$05
  26E4  97 02             STA    <$02
  26E6  8E 61 A5          LDX    #$61A5
  26E9  10 8E 61 C7       LDY    #$61C7
L_26ED:
  26ED  E6 A0             LDB    ,Y+
  26EF  E0 80             SUBB   ,X+
  26F1  E6 A0             LDB    ,Y+
  26F3  E2 80             SBCB   ,X+
  26F5  E6 A4             LDB    ,Y
  26F7  E2 84             SBCB   ,X
  26F9  25 1C             BCS    L_2717
  26FB  86 19             LDA    #$19
  26FD  97 01             STA    <$01
L_26FF:
  26FF  A6 84             LDA    ,X
  2701  E6 A4             LDB    ,Y
  2703  E7 84             STB    ,X
  2705  A7 A4             STA    ,Y
  2707  30 1F             LEAX   -1,X
  2709  31 3F             LEAY   -1,Y
  270B  0A 01             DEC    <$01
  270D  26 F0             BNE    L_26FF
  270F  30 15             LEAX   -11,X
  2711  31 35             LEAY   -11,Y
  2713  0A 02             DEC    <$02
  2715  26 D6             BNE    L_26ED
L_2717:
  2717  39                RTS
L_2718:
  2718  BD 17 3D          JSR    >ShowCredits
  271B  9D 3F             JSR    <RST_WaitTimer
  271D  BD 19 F9          JSR    >ClearPlayfield
  2720  5F                CLRB
  2721  F7 60 0E          STB    >Player2Ctrl
  2724  F7 60 0D          STB    >PlayerUp               ; 0 = player 1, 1 = player 2
  2727  8E 61 1C          LDX    #$611C
  272A  10 8E 00 22       LDY    #$0022
  272E  86 05             LDA    #$05
  2730  C6 01             LDB    #$01
L_2732:
  2732  E1 84             CMPB   ,X
  2734  27 21             BEQ    L_2757
  2736  30 88 22          LEAX   <34,X
  2739  4A                DECA
  273A  26 F6             BNE    L_2732
  273C  8E 61 1C          LDX    #$611C
  273F  CC 05 03          LDD    #$0503
L_2742:
  2742  E1 84             CMPB   ,X
  2744  27 08             BEQ    L_274E
  2746  30 88 22          LEAX   <34,X
  2749  4A                DECA
  274A  26 F6             BNE    L_2742
  274C  20 2B             BRA    L_2779
L_274E:
  274E  C6 01             LDB    #$01
  2750  F7 60 0E          STB    >Player2Ctrl
  2753  F7 60 0D          STB    >PlayerUp               ; 0 = player 1, 1 = player 2
  2756  5F                CLRB
L_2757:
  2757  8E 60 26          LDX    #DipCabinet
  275A  EA 84             ORB    ,X
  275C  F7 7D 82          STB    >FlipScreen             ; flip screen
  275F  7F 60 09          CLR    >WaitTimer              ; frame countdown (RST_WaitTimer)
  2762  8E 60 0A          LDX    #GameState
  2765  6C 84             INC    ,X
  2767  10 8E 03 0D       LDY    #$030D
  276B  86 0C             LDA    #$0C
  276D  97 02             STA    <$02
L_276F:
  276F  BD 45 21          JSR    >AddTask
  2772  31 21             LEAY   1,Y
  2774  0A 02             DEC    <$02
  2776  26 F7             BNE    L_276F
  2778  39                RTS
L_2779:
  2779  C6 01             LDB    #$01
  277B  F7 7D 82          STB    >FlipScreen             ; flip screen
  277E  F7 60 05          STB    >GameMode               ; 0 init, 1 attract, 2 credited, 3 game
  2781  F7 60 07          STB    >AttractFlag            ; 1 = attract / no game
  2784  7F 60 0A          CLR    >GameState              ; sub-state of GameMode
  2787  39                RTS
L_2788:
  2788  BD 17 3D          JSR    >ShowCredits
  278B  8E 60 09          LDX    #WaitTimer
  278E  E6 84             LDB    ,X
  2790  26 56             BNE    L_27E8
  2792  F7 7D 86          STB    >PaletteBank0           ; palette bank bit 0
  2795  F7 7D 87          STB    >PaletteBank1           ; palette bank bit 1
  2798  BD 53 66          JSR    >PaletteBankUpdate
  279B  86 01             LDA    #$01
  279D  A7 84             STA    ,X
  279F  8E 60 30          LDX    #$6030
  27A2  86 0A             LDA    #$0A
  27A4  A7 80             STA    ,X+
  27A6  6F 80             CLR    ,X+
  27A8  86 10             LDA    #$10
  27AA  A7 80             STA    ,X+
  27AC  86 1E             LDA    #$1E
  27AE  A7 80             STA    ,X+
  27B0  86 3E             LDA    #$3E
  27B2  A7 80             STA    ,X+
  27B4  6F 84             CLR    ,X
  27B6  8E 75 E8          LDX    #$75E8
  27B9  BF 60 36          STX    >$6036
  27BC  8E 61 1C          LDX    #$611C
  27BF  F6 60 0E          LDB    >Player2Ctrl
  27C2  58                ASLB
  27C3  5C                INCB
  27C4  D7 03             STB    <$03
  27C6  86 04             LDA    #$04
L_27C8:
  27C8  E6 84             LDB    ,X
  27CA  D1 03             CMPB   <$03
  27CC  27 06             BEQ    L_27D4
  27CE  30 88 22          LEAX   <34,X
  27D1  4A                DECA
  27D2  26 F4             BNE    L_27C8
L_27D4:
  27D4  BF 60 38          STX    >$6038
  27D7  10 8E FF F3       LDY    #$FFF3
  27DB  30 13             LEAX   -13,X
  27DD  BF 60 3A          STX    >$603A
  27E0  F6 60 35          LDB    >$6035
  27E3  D7 03             STB    <$03
  27E5  BD 28 F7          JSR    >SUB_28F7
L_27E8:
  27E8  8E 60 34          LDX    #$6034
  27EB  6A 84             DEC    ,X
  27ED  26 1B             BNE    L_280A
  27EF  86 3E             LDA    #$3E
  27F1  A7 84             STA    ,X
  27F3  6A 82             DEC    ,-X
  27F5  10 27 00 BF       LBEQ   L_28B8
  27F9  E6 84             LDB    ,X
  27FB  86 FF             LDA    #$FF
L_27FD:
  27FD  4C                INCA
  27FE  C0 0A             SUBB   #$0A
  2800  24 FB             BCC    L_27FD
  2802  CB 0A             ADDB   #$0A
  2804  F7 75 52          STB    >$7552
  2807  B7 75 72          STA    >$7572
L_280A:
  280A  8E 60 30          LDX    #$6030
  280D  A6 84             LDA    ,X
  280F  97 02             STA    <$02
  2811  86 0A             LDA    #$0A
  2813  A7 84             STA    ,X
  2815  F6 60 10          LDB    >InputState             ; joystick+jump, bit7 = jump edge
  2818  2B 36             BMI    L_2850
  281A  C4 03             ANDB   #$03
  281C  26 06             BNE    L_2824
  281E  5C                INCB
  281F  E7 84             STB    ,X
  2821  7E 28 84          JMP    >L_2884
L_2824:
  2824  0A 02             DEC    <$02
  2826  27 06             BEQ    L_282E
  2828  D6 02             LDB    <$02
  282A  E7 84             STB    ,X
  282C  20 56             BRA    L_2884
L_282E:
  282E  C4 02             ANDB   #$02
  2830  26 13             BNE    L_2845
  2832  F6 60 35          LDB    >$6035
  2835  5C                INCB
  2836  C1 1E             CMPB   #$1E
  2838  26 01             BNE    L_283B
  283A  5F                CLRB
L_283B:
  283B  F7 60 35          STB    >$6035
  283E  D7 03             STB    <$03
  2840  BD 28 F7          JSR    >SUB_28F7
  2843  20 3F             BRA    L_2884
L_2845:
  2845  F6 60 35          LDB    >$6035
  2848  C0 01             SUBB   #$01
  284A  2A EF             BPL    L_283B
  284C  C6 1D             LDB    #$1D
  284E  20 EB             BRA    L_283B
L_2850:
  2850  F6 60 35          LDB    >$6035
  2853  C1 1C             CMPB   #$1C
  2855  27 19             BEQ    L_2870
  2857  C1 1D             CMPB   #$1D
  2859  27 5D             BEQ    L_28B8
  285B  BE 60 36          LDX    >$6036
  285E  5D                TSTB
  285F  8C 75 88          CMPX   #$7588
  2862  27 20             BEQ    L_2884
  2864  CB 11             ADDB   #$11
  2866  E7 84             STB    ,X
  2868  30 88 E0          LEAX   <-32,X
L_286B:
  286B  BF 60 36          STX    >$6036
  286E  20 14             BRA    L_2884
L_2870:
  2870  BE 60 36          LDX    >$6036
  2873  30 88 20          LEAX   <32,X
  2876  8C 76 08          CMPX   #$7608
  2879  26 03             BNE    L_287E
  287B  8E 75 E8          LDX    #$75E8
L_287E:
  287E  C6 10             LDB    #$10
  2880  E7 84             STB    ,X
  2882  20 E7             BRA    L_286B
L_2884:
  2884  8E 60 32          LDX    #$6032
  2887  6A 84             DEC    ,X
  2889  26 6B             BNE    L_28F6
  288B  F6 60 31          LDB    >$6031
  288E  26 1C             BNE    L_28AC
  2890  C6 01             LDB    #$01
  2892  F7 60 31          STB    >$6031
  2895  10 8E 12 2E       LDY    #D_122E
L_2899:
  2899  BE 60 38          LDX    >$6038
  289C  9F 0A             STX    <$0A
  289E  AE 04             LDX    4,X
  28A0  1F 13             TFR    X,U
  28A2  BD 16 9A          JSR    >DrawBCD
  28A5  C6 10             LDB    #$10
  28A7  F7 60 32          STB    >$6032
  28AA  20 4A             BRA    L_28F6
L_28AC:
  28AC  5F                CLRB
  28AD  F7 60 31          STB    >$6031
  28B0  10 BE 60 38       LDY    >$6038
  28B4  31 23             LEAY   3,Y
  28B6  20 E1             BRA    L_2899
L_28B8:
  28B8  10 BE 60 38       LDY    >$6038
  28BC  5F                CLRB
  28BD  E7 A4             STB    ,Y
  28BF  8E 60 09          LDX    #WaitTimer
  28C2  86 80             LDA    #$80
  28C4  A7 80             STA    ,X+
  28C6  6A 84             DEC    ,X
  28C8  86 0C             LDA    #$0C
  28CA  8E 75 E8          LDX    #$75E8
  28CD  10 BE 60 3A       LDY    >$603A
L_28D1:
  28D1  E6 84             LDB    ,X
  28D3  E7 A0             STB    ,Y+
  28D5  30 88 E0          LEAX   <-32,X
  28D8  4A                DECA
  28D9  26 F6             BNE    L_28D1
  28DB  10 9F 0A          STY    <$0A
  28DE  86 05             LDA    #$05
  28E0  97 02             STA    <$02
  28E2  10 8E 03 14       LDY    #$0314                  ; show #14
L_28E6:
  28E6  BD 45 21          JSR    >AddTask
  28E9  31 21             LEAY   1,Y
  28EB  0A 02             DEC    <$02
  28ED  26 F7             BNE    L_28E6
  28EF  10 8E 03 1A       LDY    #$031A                  ; show "YOUR NAME WAS REGISTERED~"
  28F3  BD 45 21          JSR    >AddTask
L_28F6:
  28F6  39                RTS

; =====================================================================
; SUB_28F7 (109 instructions)
; Uses:  $6974 ScreenNum $6388 WaitTimer $690B $690C $6924 $692C $62AF $6910 $6908 $62A0 $63A3
; Calls: SUB_453E RST_JumpTable SUB_3195 SUB_2A0F RST_CopySprites RST_RetIfNotScreen RST_AddToObjects RST_WaitTimer SUB_3A32
; =====================================================================
SUB_28F7:
  28F7  34 30             PSHS   X,Y
  28F9  08 03             ASL    <$03
  28FB  8E 4A 2B          LDX    #D_4A2B
  28FE  D6 03             LDB    <$03
  2900  3A                ABX
  2901  1F 12             TFR    X,Y
  2903  8E 69 74          LDX    #$6974
  2906  E6 A0             LDB    ,Y+
  2908  E7 84             STB    ,X
  290A  86 72             LDA    #$72
  290C  A7 01             STA    1,X
  290E  E6 A4             LDB    ,Y
  2910  E7 03             STB    3,X
  2912  35 B0             PULS   X,Y,PC
L_2914:
  2914  BD 45 3E          JSR    >SUB_453E
  2917  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  291A  54                LSRB
  291B  24 11             BCC    L_292E
  291D  F6 63 88          LDB    >$6388
  2920  9D 47             JSR    <RST_JumpTable
TBL_2922:
  2922  29 54             FDB    L_2954
  2924  29 74             FDB    L_2974
  2926  29 93             FDB    L_2993
  2928  2A 42             FDB    L_2A42
  292A  2A 6A             FDB    L_2A6A
  292C  2A B0             FDB    L_2AB0
L_292E:
  292E  54                LSRB
  292F  24 0F             BCC    L_2940
  2931  F6 63 88          LDB    >$6388
  2934  9D 47             JSR    <RST_JumpTable
TBL_2936:
  2936  29 AB             FDB    L_29AB
  2938  29 C4             FDB    L_29C4
  293A  2A 42             FDB    L_2A42
  293C  2A 6A             FDB    L_2A6A
  293E  2A B0             FDB    L_2AB0
L_2940:
  2940  BD 31 95          JSR    >SUB_3195
  2943  F6 63 88          LDB    >$6388
  2946  9D 47             JSR    <RST_JumpTable
TBL_2948:
  2948  2A DF             FDB    L_2ADF
  294A  44 D4             FDB    L_44D4
  294C  2B 73             FDB    L_2B73
  294E  2B B5             FDB    L_2BB5
  2950  2B C7             FDB    L_2BC7
  2952  2C 19             FDB    L_2C19
L_2954:
  2954  BD 2A 0F          JSR    >SUB_2A0F
  2957  8E 4D B7          LDX    #D_4DB7
  295A  9D 77             JSR    <RST_CopySprites
  295C  C6 20             LDB    #$20
  295E  F7 60 09          STB    >WaitTimer              ; frame countdown (RST_WaitTimer)
L_2961:
  2961  8E 63 88          LDX    #$6388
  2964  6C 84             INC    ,X
  2966  C6 01             LDB    #$01
  2968  9D 64             JSR    <RST_RetIfNotScreen
  296A  8E 69 0B          LDX    #$690B
  296D  86 FC             LDA    #$FC
  296F  97 03             STA    <$03
  2971  9D 4F             JSR    <RST_AddToObjects
  2973  39                RTS
L_2974:
  2974  9D 3F             JSR    <RST_WaitTimer
  2976  8E 4D 1A          LDX    #D_4D1A
  2979  9D 77             JSR    <RST_CopySprites
  297B  C6 20             LDB    #$20
  297D  F7 60 09          STB    >WaitTimer              ; frame countdown (RST_WaitTimer)
  2980  8E 63 88          LDX    #$6388
  2983  6C 84             INC    ,X
  2985  C6 04             LDB    #$04
  2987  9D 64             JSR    <RST_RetIfNotScreen
  2989  8E 69 0B          LDX    #$690B
  298C  86 04             LDA    #$04
  298E  97 03             STA    <$03
  2990  9D 4F             JSR    <RST_AddToObjects
  2992  39                RTS
L_2993:
  2993  9D 3F             JSR    <RST_WaitTimer
  2995  8E 4C 74          LDX    #D_4C74
  2998  9D 77             JSR    <RST_CopySprites
  299A  C6 66             LDB    #$66
  299C  F7 69 0C          STB    >$690C
  299F  5F                CLRB
  29A0  F7 69 24          STB    >$6924
  29A3  F7 69 2C          STB    >$692C
  29A6  F7 62 AF          STB    >$62AF
  29A9  20 B6             BRA    L_2961
L_29AB:
  29AB  8D 62             BSR    SUB_2A0F
  29AD  F6 69 10          LDB    >$6910
  29B0  C0 3B             SUBB   #$3B
  29B2  8E 4D B7          LDX    #D_4DB7
  29B5  9D 77             JSR    <RST_CopySprites
  29B7  8E 69 08          LDX    #$6908
  29BA  D7 03             STB    <$03
  29BC  9D 4F             JSR    <RST_AddToObjects
  29BE  8E 63 88          LDX    #$6388
  29C1  6C 84             INC    ,X
  29C3  39                RTS
L_29C4:
  29C4  5F                CLRB
  29C5  F7 62 A0          STB    >$62A0
  29C8  F6 63 A3          LDB    >$63A3
  29CB  D7 03             STB    <$03
  29CD  F6 69 10          LDB    >$6910
  29D0  C1 5A             CMPB   #$5A
  29D2  24 17             BCC    L_29EB
  29D4  96 03             LDA    <$03
  29D6  2A 05             BPL    L_29DD
L_29D8:
  29D8  C6 01             LDB    #$01
  29DA  F7 62 A0          STB    >$62A0
L_29DD:
  29DD  BD 3A 32          JSR    >SUB_3A32
  29E0  F6 63 A3          LDB    >$63A3
  29E3  D7 03             STB    <$03
  29E5  8E 69 08          LDX    #$6908
  29E8  9D 4F             JSR    <RST_AddToObjects
  29EA  39                RTS
L_29EB:
  29EB  C1 5D             CMPB   #$5D
  29ED  25 06             BCS    L_29F5
  29EF  96 03             LDA    <$03
  29F1  2A E5             BPL    L_29D8
  29F3  20 E8             BRA    L_29DD
L_29F5:
  29F5  8E 4C 74          LDX    #D_4C74
  29F8  9D 77             JSR    <RST_CopySprites
  29FA  C6 66             LDB    #$66
  29FC  F7 69 0C          STB    >$690C
  29FF  5F                CLRB
  2A00  F7 69 24          STB    >$6924
  2A03  F7 69 2C          STB    >$692C
  2A06  F7 62 AF          STB    >$62AF
  2A09  8E 63 88          LDX    #$6388
  2A0C  6C 84             INC    ,X
  2A0E  39                RTS

; =====================================================================
; SUB_2A0F (49 instructions)
; Uses:  $6A20 $6905 $75C4 MusicReq2 $6913 SpriteBuf $6904 $690C $6924 $692C $6A21 $6388 WaitTimer
; Calls: SoundReset SUB_161C SUB_44DC SUB_2A80 SUB_2A99
; =====================================================================
SUB_2A0F:
  2A0F  BD 11 B1          JSR    >SoundReset
  2A12  8E 6A 20          LDX    #$6A20
  2A15  86 80             LDA    #$80
  2A17  A7 80             STA    ,X+
  2A19  86 76             LDA    #$76
  2A1B  A7 80             STA    ,X+
  2A1D  86 09             LDA    #$09
  2A1F  A7 80             STA    ,X+
  2A21  86 20             LDA    #$20
  2A23  A7 84             STA    ,X
  2A25  86 13             LDA    #$13
  2A27  B7 69 05          STA    >$6905
  2A2A  8E 75 C4          LDX    #$75C4
  2A2D  10 8E 00 20       LDY    #$0020
  2A31  C6 10             LDB    #$10
  2A33  BD 16 1C          JSR    >SUB_161C
  2A36  8E 60 8A          LDX    #MusicReq2
  2A39  86 07             LDA    #$07
  2A3B  A7 80             STA    ,X+
  2A3D  86 03             LDA    #$03
  2A3F  A7 84             STA    ,X
  2A41  39                RTS
L_2A42:
  2A42  BD 44 DC          JSR    >SUB_44DC
  2A45  F6 69 13          LDB    >$6913
  2A48  C1 2C             CMPB   #$2C
  2A4A  24 1D             BCC    L_2A69
  2A4C  5F                CLRB
  2A4D  F7 69 00          STB    >SpriteBuf              ; arcade sprite list, 4 bytes/sprite
  2A50  F7 69 04          STB    >$6904
  2A53  F7 69 0C          STB    >$690C
  2A56  C6 6B             LDB    #$6B
  2A58  F7 69 24          STB    >$6924
  2A5B  5A                DECB
  2A5C  F7 69 2C          STB    >$692C
  2A5F  8E 6A 21          LDX    #$6A21
  2A62  6C 84             INC    ,X
  2A64  8E 63 88          LDX    #$6388
  2A67  6C 84             INC    ,X
L_2A69:
  2A69  39                RTS
L_2A6A:
  2A6A  BD 44 DC          JSR    >SUB_44DC
  2A6D  8D 11             BSR    SUB_2A80
  2A6F  30 01             LEAX   1,X
  2A71  31 21             LEAY   1,Y
  2A73  8D 24             BSR    SUB_2A99
  2A75  C6 40             LDB    #$40
  2A77  F7 60 09          STB    >WaitTimer              ; frame countdown (RST_WaitTimer)
  2A7A  8E 63 88          LDX    #$6388
  2A7D  6C 84             INC    ,X
  2A7F  39                RTS

; =====================================================================
; SUB_2A80 (12 instructions)
; Uses:  $692F
; =====================================================================
SUB_2A80:
  2A80  10 8E 00 03       LDY    #$0003
  2A84  8E 69 2F          LDX    #$692F
  2A87  86 0A             LDA    #$0A
L_2A89:
  2A89  E6 84             LDB    ,X
  2A8B  30 1D             LEAX   -3,X
  2A8D  C1 19             CMPB   #$19
  2A8F  24 02             BCC    L_2A93
  2A91  6F 84             CLR    ,X
L_2A93:
  2A93  30 1F             LEAX   -1,X
  2A95  4A                DECA
  2A96  26 F1             BNE    L_2A89
  2A98  39                RTS

; =====================================================================
; SUB_2A99 (76 instructions)
; Uses:  $622A ScreenNum $6388 WaitTimer MusicReq2 $7623 $7583 $76DA $76D5 $76D0 $76CB $6908 $6905 $6390 ...
; Calls: RST_WaitTimer AddTask SoundReset SUB_161C SUB_2B55 SUB_1FD6 RST_CopySprites RST_AddToObjects
; =====================================================================
SUB_2A99:
  2A99  86 0A             LDA    #$0A
  2A9B  97 02             STA    <$02
L_2A9D:
  2A9D  E6 84             LDB    ,X
  2A9F  27 02             BEQ    L_2AA3
  2AA1  35 90             PULS   X,PC
L_2AA3:
  2AA3  D7 01             STB    <$01
  2AA5  1F 20             TFR    Y,D
  2AA7  30 8B             LEAX   D,X
  2AA9  D6 01             LDB    <$01
  2AAB  0A 02             DEC    <$02
  2AAD  26 EE             BNE    L_2A9D
  2AAF  39                RTS
L_2AB0:
  2AB0  9D 3F             JSR    <RST_WaitTimer
  2AB2  BE 62 2A          LDX    >$622A
  2AB5  30 01             LEAX   1,X
  2AB7  E6 84             LDB    ,X
  2AB9  C1 7F             CMPB   #$7F
  2ABB  26 05             BNE    L_2AC2
  2ABD  8E 4E 8B          LDX    #D_4E8B
  2AC0  E6 84             LDB    ,X
L_2AC2:
  2AC2  BF 62 2A          STX    >$622A
  2AC5  F7 62 27          STB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  2AC8  10 8E 05 00       LDY    #$0500                  ; queue BonusTimer(0)
  2ACC  BD 45 21          JSR    >AddTask
  2ACF  5F                CLRB
  2AD0  F7 63 88          STB    >$6388
  2AD3  8E 60 09          LDX    #WaitTimer
  2AD6  86 30             LDA    #$30
  2AD8  A7 80             STA    ,X+
  2ADA  86 08             LDA    #$08
  2ADC  A7 84             STA    ,X
  2ADE  39                RTS
L_2ADF:
  2ADF  BD 11 B1          JSR    >SoundReset
  2AE2  8E 60 8A          LDX    #MusicReq2
  2AE5  86 0E             LDA    #$0E
  2AE7  A7 80             STA    ,X+
  2AE9  86 03             LDA    #$03
  2AEB  A7 84             STA    ,X
  2AED  C6 10             LDB    #$10
  2AEF  10 8E 00 20       LDY    #$0020
  2AF3  8E 76 23          LDX    #$7623
  2AF6  BD 16 1C          JSR    >SUB_161C
  2AF9  8E 75 83          LDX    #$7583
  2AFC  BD 16 1C          JSR    >SUB_161C
  2AFF  8E 76 DA          LDX    #$76DA
  2B02  8D 51             BSR    SUB_2B55
  2B04  10 8E 4E 5F       LDY    #D_4E5F
  2B08  BD 1F D6          JSR    >SUB_1FD6
  2B0B  8E 76 D5          LDX    #$76D5
  2B0E  8D 45             BSR    SUB_2B55
  2B10  10 8E 4E 65       LDY    #D_4E65
  2B14  BD 1F D6          JSR    >SUB_1FD6
  2B17  8E 76 D0          LDX    #$76D0
  2B1A  8D 39             BSR    SUB_2B55
  2B1C  10 8E 4E 6B       LDY    #D_4E6B
  2B20  BD 1F D6          JSR    >SUB_1FD6
  2B23  8E 76 CB          LDX    #$76CB
  2B26  8D 2D             BSR    SUB_2B55
  2B28  10 8E 4E 71       LDY    #D_4E71
  2B2C  BD 1F D6          JSR    >SUB_1FD6
  2B2F  8E 4D B7          LDX    #D_4DB7
  2B32  9D 77             JSR    <RST_CopySprites
  2B34  8E 69 08          LDX    #$6908
  2B37  86 44             LDA    #$44
  2B39  97 03             STA    <$03
  2B3B  9D 4F             JSR    <RST_AddToObjects
  2B3D  86 13             LDA    #$13
  2B3F  B7 69 05          STA    >$6905
  2B42  C6 20             LDB    #$20
  2B44  F7 60 09          STB    >WaitTimer              ; frame countdown (RST_WaitTimer)
  2B47  C6 80             LDB    #$80
  2B49  F7 63 90          STB    >$6390
  2B4C  8E 63 88          LDX    #$6388
  2B4F  6C 84             INC    ,X
  2B51  BF 63 C0          STX    >$63C0
  2B54  39                RTS

; =====================================================================
; SUB_2B55 (212 instructions)
; Uses:  $6390 $6908 WaitTimer $6388 SndFx4 $690B $691B $6919 $6A24 $76C6 $6903 $62AF SndBoom $6A25 ...
; Calls: RST_CopySprites RST_AddToObjects RST_WaitTimer SUB_2B55 SUB_1FD6 RST_AddToObjectsB SUB_4459 AddTask ClearScreenAll SUB_360F ...
; =====================================================================
SUB_2B55:
  2B55  10 8E FF DB       LDY    #$FFDB
  2B59  86 0E             LDA    #$0E
  2B5B  97 03             STA    <$03
  2B5D  C6 10             LDB    #$10
L_2B5F:
  2B5F  86 05             LDA    #$05
L_2B61:
  2B61  E7 80             STB    ,X+
  2B63  4A                DECA
  2B64  26 FB             BNE    L_2B61
  2B66  D7 01             STB    <$01
  2B68  1F 20             TFR    Y,D
  2B6A  30 8B             LEAX   D,X
  2B6C  D6 01             LDB    <$01
  2B6E  0A 03             DEC    <$03
  2B70  26 ED             BNE    L_2B5F
  2B72  39                RTS
L_2B73:
  2B73  8E 63 90          LDX    #$6390
  2B76  6C 84             INC    ,X
  2B78  27 22             BEQ    L_2B9C
  2B7A  E6 84             LDB    ,X
  2B7C  C4 07             ANDB   #$07
  2B7E  26 1B             BNE    L_2B9B
  2B80  10 8E 4D E7       LDY    #D_4DE7
  2B84  A6 84             LDA    ,X
  2B86  84 08             ANDA   #$08
  2B88  26 04             BNE    L_2B8E
  2B8A  10 8E 4E 0F       LDY    #D_4E0F
L_2B8E:
  2B8E  1E 21             EXG    Y,X
  2B90  9D 77             JSR    <RST_CopySprites
  2B92  8E 69 08          LDX    #$6908
  2B95  86 44             LDA    #$44
  2B97  97 03             STA    <$03
  2B99  9D 4F             JSR    <RST_AddToObjects
L_2B9B:
  2B9B  39                RTS
L_2B9C:
  2B9C  8E 4D B7          LDX    #D_4DB7
  2B9F  9D 77             JSR    <RST_CopySprites
  2BA1  8E 69 08          LDX    #$6908
  2BA4  86 44             LDA    #$44
  2BA6  97 03             STA    <$03
  2BA8  9D 4F             JSR    <RST_AddToObjects
  2BAA  C6 20             LDB    #$20
  2BAC  F7 60 09          STB    >WaitTimer              ; frame countdown (RST_WaitTimer)
  2BAF  8E 63 88          LDX    #$6388
  2BB2  6C 84             INC    ,X
  2BB4  39                RTS
L_2BB5:
  2BB5  9D 3F             JSR    <RST_WaitTimer
  2BB7  8E 4E 37          LDX    #D_4E37
  2BBA  9D 77             JSR    <RST_CopySprites
  2BBC  C6 03             LDB    #$03
  2BBE  F7 60 84          STB    >SndFx4
  2BC1  8E 63 88          LDX    #$6388
  2BC4  6C 84             INC    ,X
  2BC6  39                RTS
L_2BC7:
  2BC7  8E 69 0B          LDX    #$690B
  2BCA  86 01             LDA    #$01
  2BCC  97 03             STA    <$03
  2BCE  9D 4F             JSR    <RST_AddToObjects
  2BD0  F6 69 1B          LDB    >$691B
  2BD3  C1 D0             CMPB   #$D0
  2BD5  26 41             BNE    L_2C18
  2BD7  C6 20             LDB    #$20
  2BD9  F7 69 19          STB    >$6919
  2BDC  8E 6A 24          LDX    #$6A24
  2BDF  86 7F             LDA    #$7F
  2BE1  A7 80             STA    ,X+
  2BE3  86 39             LDA    #$39
  2BE5  A7 80             STA    ,X+
  2BE7  86 01             LDA    #$01
  2BE9  A7 80             STA    ,X+
  2BEB  86 D8             LDA    #$D8
  2BED  A7 84             STA    ,X
  2BEF  8E 76 C6          LDX    #$76C6
  2BF2  BD 2B 55          JSR    >SUB_2B55
  2BF5  10 8E 4E 77       LDY    #D_4E77
  2BF9  BD 1F D6          JSR    >SUB_1FD6
  2BFC  10 8E 00 04       LDY    #$0004
  2C00  CC 02 28          LDD    #$0228
  2C03  DD 02             STD    <$02
  2C05  8E 69 03          LDX    #$6903
  2C08  9D 57             JSR    <RST_AddToObjectsB
  2C0A  5F                CLRB
  2C0B  F7 62 AF          STB    >$62AF
  2C0E  C6 03             LDB    #$03
  2C10  F7 60 82          STB    >SndBoom
  2C13  8E 63 88          LDX    #$6388
  2C16  6C 84             INC    ,X
L_2C18:
  2C18  39                RTS
L_2C19:
  2C19  8E 62 AF          LDX    #$62AF
  2C1C  6A 84             DEC    ,X
  2C1E  10 27 00 85       LBEQ   L_2CA7
  2C22  E6 84             LDB    ,X
  2C24  C4 07             ANDB   #$07
  2C26  26 F0             BNE    L_2C18
  2C28  8E 6A 25          LDX    #$6A25
  2C2B  E6 84             LDB    ,X
  2C2D  C8 80             EORB   #$80
  2C2F  E7 84             STB    ,X
  2C31  8E 69 19          LDX    #$6919
  2C34  A6 84             LDA    ,X
  2C36  84 DF             ANDA   #$DF
  2C38  97 02             STA    <$02
  2C3A  5F                CLRB
  2C3B  BD 44 59          JSR    >SUB_4459
  2C3E  CA 20             ORB    #$20
  2C40  E7 84             STB    ,X
  2C42  8E 62 AF          LDX    #$62AF
  2C45  E6 84             LDB    ,X
  2C47  C1 E0             CMPB   #$E0
  2C49  26 21             BNE    L_2C6C
  2C4B  C6 50             LDB    #$50
  2C4D  F7 69 4F          STB    >$694F
  2C50  5F                CLRB
  2C51  F7 69 4D          STB    >$694D
  2C54  C6 9F             LDB    #$9F
  2C56  F7 69 4C          STB    >$694C
  2C59  F6 62 03          LDB    >MarioX
  2C5C  C1 80             CMPB   #$80
  2C5E  24 0A             BCC    L_2C6A
  2C60  C6 80             LDB    #$80
  2C62  F7 69 4D          STB    >$694D
  2C65  C6 5F             LDB    #$5F
  2C67  F7 69 4C          STB    >$694C
L_2C6A:
  2C6A  E6 84             LDB    ,X
L_2C6C:
  2C6C  C1 C0             CMPB   #$C0
  2C6E  26 36             BNE    L_2CA6
  2C70  8E 60 8A          LDX    #MusicReq2
  2C73  86 0C             LDA    #$0C
  2C75  A7 84             STA    ,X
  2C77  F6 62 29          LDB    >Level                  ; level number
  2C7A  56                RORB
  2C7B  25 04             BCS    L_2C81
  2C7D  86 05             LDA    #$05
  2C7F  A7 84             STA    ,X
L_2C81:
  2C81  30 01             LEAX   1,X
  2C83  86 03             LDA    #$03
  2C85  A7 84             STA    ,X
  2C87  8E 6A 23          LDX    #$6A23
  2C8A  86 40             LDA    #$40
  2C8C  A7 84             STA    ,X
  2C8E  86 09             LDA    #$09
  2C90  A7 82             STA    ,-X
  2C92  86 76             LDA    #$76
  2C94  A7 82             STA    ,-X
  2C96  86 8F             LDA    #$8F
  2C98  A7 82             STA    ,-X
  2C9A  F6 62 03          LDB    >MarioX
  2C9D  C1 80             CMPB   #$80
  2C9F  24 05             BCC    L_2CA6
  2CA1  C6 6F             LDB    #$6F
  2CA3  F7 6A 20          STB    >$6A20
L_2CA6:
  2CA6  39                RTS
L_2CA7:
  2CA7  BE 62 2A          LDX    >$622A
  2CAA  30 01             LEAX   1,X
  2CAC  E6 84             LDB    ,X
  2CAE  C1 7F             CMPB   #$7F
  2CB0  26 05             BNE    L_2CB7
  2CB2  8E 4E 8B          LDX    #D_4E8B
  2CB5  E6 84             LDB    ,X
L_2CB7:
  2CB7  BF 62 2A          STX    >$622A
  2CBA  F7 62 27          STB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  2CBD  8E 62 29          LDX    #Level
  2CC0  6C 84             INC    ,X
  2CC2  10 8E 05 00       LDY    #$0500                  ; queue BonusTimer(0)
  2CC6  BD 45 21          JSR    >AddTask
  2CC9  5F                CLRB
  2CCA  F7 62 2E          STB    >$622E
  2CCD  F7 63 88          STB    >$6388
  2CD0  8E 60 09          LDX    #WaitTimer
  2CD3  86 E0             LDA    #$E0
  2CD5  A7 80             STA    ,X+
  2CD7  86 08             LDA    #$08
  2CD9  A7 84             STA    ,X
  2CDB  39                RTS
L_2CDC:
  2CDC  BD 19 D2          JSR    >ClearScreenAll
  2CDF  F6 60 0E          LDB    >Player2Ctrl
  2CE2  CB 12             ADDB   #$12
  2CE4  F7 60 0A          STB    >GameState              ; sub-state of GameMode
  2CE7  39                RTS
L_2CE8:
  2CE8  BD 36 0F          JSR    >SUB_360F
L_2CEB:
  2CEB  BD 31 95          JSR    >SUB_3195
  2CEE  BD 32 8B          JSR    >SUB_328B
  2CF1  BD 2E 4D          JSR    >SUB_2E4D
  2CF4  BD 33 7D          JSR    >SUB_337D
  2CF7  BD 40 F7          JSR    >SUB_40F7
  2CFA  BD 40 65          JSR    >SUB_4065
  2CFD  BD 45 6C          JSR    >SUB_456C
  2D00  BD 42 6B          JSR    >SUB_426B
  2D03  BD 39 2B          JSR    >SUB_392B
  2D06  BD 42 39          JSR    >SUB_4239
  2D09  BD 43 25          JSR    >SUB_4325
  2D0C  BD 36 30          JSR    >SUB_3630
  2D0F  BD 2D A7          JSR    >SUB_2DA7
  2D12  BD 3E DD          JSR    >SUB_3EDD
  2D15  BD 33 51          JSR    >SUB_3351
  2D18  BD 3B 3C          JSR    >SUB_3B3C
  2D1B  BD 3A 23          JSR    >SUB_3A23
  2D1E  8D 28             BSR    SUB_2D48
  2D20  BD 15 06          JSR    >SUB_1506
  2D23  BD 3C 3B          JSR    >SUB_3C3B
  2D26  BD 3C 52          JSR    >SUB_3C52
  2D29  BD 32 58          JSR    >SUB_3258
  2D2C  8D 49             BSR    SUB_2D77
  2D2E  BD 44 13          JSR    >SUB_4413
  2D31  F6 62 00          LDB    >MarioAlive             ; bit0 = Mario alive
  2D34  26 11             BNE    L_2D47
  2D36  BD 11 B1          JSR    >SoundReset
  2D39  86 03             LDA    #$03
  2D3B  B7 60 82          STA    >SndBoom
L_2D3E:
  2D3E  8E 60 0A          LDX    #GameState
  2D41  6C 84             INC    ,X
  2D43  86 40             LDA    #$40
  2D45  A7 82             STA    ,-X
L_2D47:
  2D47  39                RTS

; =====================================================================
; SUB_2D48 (23 instructions)
; Uses:  MarioX $6A0C MarioY $6343 $6342 $6340
; =====================================================================
SUB_2D48:
  2D48  F6 62 03          LDB    >MarioX
  2D4B  86 03             LDA    #$03
  2D4D  8E 6A 0C          LDX    #$6A0C
L_2D50:
  2D50  E1 84             CMPB   ,X
  2D52  27 06             BEQ    L_2D5A
  2D54  30 04             LEAX   4,X
  2D56  4A                DECA
  2D57  26 F7             BNE    L_2D50
  2D59  39                RTS
L_2D5A:
  2D5A  F6 62 05          LDB    >MarioY
  2D5D  30 03             LEAX   3,X
  2D5F  E1 84             CMPB   ,X
  2D61  26 13             BNE    L_2D76
  2D63  A6 83             LDA    ,--X
  2D65  84 08             ANDA   #$08
  2D67  26 0D             BNE    L_2D76
  2D69  30 1F             LEAX   -1,X
  2D6B  BF 63 43          STX    >$6343
  2D6E  5F                CLRB
  2D6F  F7 63 42          STB    >$6342
  2D72  5C                INCB
  2D73  F7 63 40          STB    >$6340
L_2D76:
  2D76  39                RTS

; =====================================================================
; SUB_2D77 (17 instructions)
; Uses:  $6386 $6387 $6216
; Calls: RST_JumpTable
; =====================================================================
SUB_2D77:
  2D77  F6 63 86          LDB    >$6386
  2D7A  9D 47             JSR    <RST_JumpTable
TBL_2D7C:
  2D7C  2D 8F             FDB    L_2D8F
  2D7E  2D 86             FDB    L_2D86
  2D80  2D 90             FDB    L_2D90
  2D82  2D 9D             FDB    L_2D9D
  2D84  11 14             FDB    ColdStart
L_2D86:
  2D86  5F                CLRB
  2D87  F7 63 87          STB    >$6387
  2D8A  C6 02             LDB    #$02
  2D8C  F7 63 86          STB    >$6386
L_2D8F:
  2D8F  39                RTS
L_2D90:
  2D90  8E 63 87          LDX    #$6387
  2D93  6A 84             DEC    ,X
  2D95  26 F8             BNE    L_2D8F
  2D97  C6 03             LDB    #$03
  2D99  F7 63 86          STB    >$6386
  2D9C  39                RTS
L_2D9D:
  2D9D  F6 62 16          LDB    >$6216
  2DA0  26 ED             BNE    L_2D8F
  2DA2  35 10             PULS   X
  2DA4  7E 2D 3E          JMP    >L_2D3E

; =====================================================================
; SUB_2DA7 (82 instructions)
; Uses:  MarioX $6291 MarioY $6292 $6290 $6340 $6342 $6225 $6216
; Calls: RST_RetIfNotScreen SUB_316B
; =====================================================================
SUB_2DA7:
  2DA7  C6 08             LDB    #$08
  2DA9  9D 64             JSR    <RST_RetIfNotScreen
  2DAB  F6 62 03          LDB    >MarioX
  2DAE  C1 4B             CMPB   #$4B
  2DB0  27 0B             BEQ    L_2DBD
  2DB2  C1 B3             CMPB   #$B3
  2DB4  27 07             BEQ    L_2DBD
  2DB6  F6 62 91          LDB    >$6291
  2DB9  5A                DECB
  2DBA  27 07             BEQ    L_2DC3
L_2DBC:
  2DBC  39                RTS
L_2DBD:
  2DBD  C6 01             LDB    #$01
  2DBF  F7 62 91          STB    >$6291
  2DC2  39                RTS
L_2DC3:
  2DC3  F7 62 91          STB    >$6291
  2DC6  D7 02             STB    <$02
  2DC8  F6 62 05          LDB    >MarioY
  2DCB  5A                DECB
  2DCC  C1 D0             CMPB   #$D0
  2DCE  24 EC             BCC    L_2DBC
  2DD0  1F 98             TFR    B,A
  2DD2  49                ROLA
  2DD3  59                ROLB
  2DD4  24 06             BCC    L_2DDC
  2DD6  96 02             LDA    <$02
  2DD8  8A 04             ORA    #$04
  2DDA  97 02             STA    <$02
L_2DDC:
  2DDC  1F 98             TFR    B,A
  2DDE  49                ROLA
  2DDF  59                ROLB
  2DE0  49                ROLA
  2DE1  59                ROLB
  2DE2  24 06             BCC    L_2DEA
  2DE4  96 02             LDA    <$02
  2DE6  8A 02             ORA    #$02
  2DE8  97 02             STA    <$02
L_2DEA:
  2DEA  C4 07             ANDB   #$07
  2DEC  C1 06             CMPB   #$06
  2DEE  26 06             BNE    L_2DF6
  2DF0  96 02             LDA    <$02
  2DF2  8A 02             ORA    #$02
  2DF4  97 02             STA    <$02
L_2DF6:
  2DF6  F6 62 03          LDB    >MarioX
  2DF9  59                ROLB
  2DFA  24 06             BCC    L_2E02
  2DFC  96 02             LDA    <$02
  2DFE  8A 01             ORA    #$01
  2E00  97 02             STA    <$02
L_2E02:
  2E02  8E 62 92          LDX    #$6292
  2E05  1F 10             TFR    X,D
  2E07  DB 02             ADDB   <$02
  2E09  1F 01             TFR    D,X
  2E0B  E6 84             LDB    ,X
  2E0D  27 38             BEQ    L_2E47
  2E0F  6F 84             CLR    ,X
  2E11  8E 62 90          LDX    #$6290
  2E14  6A 84             DEC    ,X
  2E16  D6 02             LDB    <$02
  2E18  56                RORB
  2E19  25 2D             BCS    L_2E48
  2E1B  8E 02 CB          LDX    #$02CB
L_2E1E:
  2E1E  5D                TSTB
  2E1F  27 05             BEQ    L_2E26
L_2E21:
  2E21  30 05             LEAX   5,X
  2E23  5A                DECB
  2E24  26 FB             BNE    L_2E21
L_2E26:
  2E26  30 89 74 00       LEAX   >29696,X
  2E2A  C6 10             LDB    #$10
  2E2C  E7 84             STB    ,X
  2E2E  E7 82             STB    ,-X
  2E30  30 02             LEAX   2,X
  2E32  E7 84             STB    ,X
  2E34  C6 01             LDB    #$01
  2E36  F7 63 40          STB    >$6340
  2E39  F7 63 42          STB    >$6342
  2E3C  F7 62 25          STB    >$6225
  2E3F  F6 62 16          LDB    >$6216
  2E42  26 03             BNE    L_2E47
  2E44  BD 31 6B          JSR    >SUB_316B
L_2E47:
  2E47  39                RTS
L_2E48:
  2E48  8E 01 2B          LDX    #$012B
  2E4B  20 D1             BRA    L_2E1E

; =====================================================================
; SUB_2E4D (337 instructions)
; Uses:  $6216 $621E $6217 $6215 InputState MarioY MarioX $6207 $621A $6218 $6202 $6210 $6204 $6206 ...
; Calls: SUB_3864 SUB_37B6 SUB_37F6 SUB_3850 SUB_3F7B CheckJumpOver SUB_3DA2 SUB_316B SUB_4459 SUB_3165 ...
; =====================================================================
SUB_2E4D:
  2E4D  F6 62 16          LDB    >$6216
  2E50  5A                DECB
  2E51  10 27 01 17       LBEQ   L_2F6C
  2E55  F6 62 1E          LDB    >$621E
  2E58  10 26 00 A4       LBNE   L_2F00
  2E5C  F6 62 17          LDB    >$6217
  2E5F  5A                DECB
  2E60  27 0E             BEQ    L_2E70
  2E62  F6 62 15          LDB    >$6215
  2E65  5A                DECB
  2E66  27 71             BEQ    L_2ED9
  2E68  F6 60 10          LDB    >InputState             ; joystick+jump, bit7 = jump edge
  2E6B  59                ROLB
  2E6C  10 25 00 B0       LBCS   L_2F20
L_2E70:
  2E70  BD 38 64          JSR    >SUB_3864
  2E73  F6 60 10          LDB    >InputState             ; joystick+jump, bit7 = jump edge
  2E76  0A 05             DEC    <$05
  2E78  27 08             BEQ    L_2E82
  2E7A  1F 98             TFR    B,A
  2E7C  84 01             ANDA   #$01
  2E7E  10 26 01 CA       LBNE   L_304C
L_2E82:
  2E82  0A 04             DEC    <$04
  2E84  27 08             BEQ    L_2E8E
  2E86  1F 98             TFR    B,A
  2E88  84 02             ANDA   #$02
  2E8A  10 26 01 DD       LBNE   L_306B
L_2E8E:
  2E8E  F6 62 17          LDB    >$6217
  2E91  5A                DECB
  2E92  27 5C             BEQ    L_2EF0
  2E94  F6 62 05          LDB    >MarioY
  2E97  CB 08             ADDB   #$08
  2E99  D7 04             STB    <$04
  2E9B  F6 62 03          LDB    >MarioX
  2E9E  CA 03             ORB    #$03
  2EA0  C4 FB             ANDB   #$FB
  2EA2  8E 00 15          LDX    #$0015
  2EA5  9F 02             STX    <$02
  2EA7  BD 37 B6          JSR    >SUB_37B6
  2EAA  34 04             PSHS   B
  2EAC  8E 62 07          LDX    #$6207
  2EAF  E6 84             LDB    ,X
  2EB1  C4 80             ANDB   #$80
  2EB3  CA 06             ORB    #$06
  2EB5  E7 84             STB    ,X
  2EB7  8E 62 1A          LDX    #$621A
  2EBA  C6 04             LDB    #$04
  2EBC  D1 03             CMPB   <$03
  2EBE  86 01             LDA    #$01
  2EC0  A7 84             STA    ,X
  2EC2  24 02             BCC    L_2EC6
  2EC4  6A 84             DEC    ,X
L_2EC6:
  2EC6  35 04             PULS   B
  2EC8  5D                TSTB
  2EC9  27 29             BEQ    L_2EF4
  2ECB  E6 84             LDB    ,X
  2ECD  26 21             BNE    L_2EF0
  2ECF  30 01             LEAX   1,X
  2ED1  96 04             LDA    <$04
  2ED3  A7 80             STA    ,X+
  2ED5  96 02             LDA    <$02
  2ED7  A7 84             STA    ,X
L_2ED9:
  2ED9  F6 60 10          LDB    >InputState             ; joystick+jump, bit7 = jump edge
  2EDC  C4 08             ANDB   #$08
  2EDE  10 26 01 DD       LBNE   L_30BF
  2EE2  F6 62 15          LDB    >$6215
  2EE5  27 09             BEQ    L_2EF0
L_2EE7:
  2EE7  F6 60 10          LDB    >InputState             ; joystick+jump, bit7 = jump edge
  2EEA  C4 04             ANDB   #$04
  2EEC  10 26 01 E2       LBNE   L_30D2
L_2EF0:
  2EF0  10 9E 04          LDY    <$04
  2EF3  39                RTS
L_2EF4:
  2EF4  30 01             LEAX   1,X
  2EF6  96 02             LDA    <$02
  2EF8  A7 80             STA    ,X+
  2EFA  96 04             LDA    <$04
  2EFC  A7 84             STA    ,X
  2EFE  20 E7             BRA    L_2EE7
L_2F00:
  2F00  8E 62 1E          LDX    #$621E
  2F03  6A 84             DEC    ,X
  2F05  26 64             BNE    L_2F6B
  2F07  F6 62 18          LDB    >$6218
  2F0A  F7 62 17          STB    >$6217
  2F0D  8E 62 07          LDX    #$6207
  2F10  E6 84             LDB    ,X
  2F12  C4 80             ANDB   #$80
  2F14  E7 84             STB    ,X
  2F16  5F                CLRB
  2F17  F7 62 02          STB    >$6202
  2F1A  10 9E 04          LDY    <$04
  2F1D  7E 31 80          JMP    >L_3180
L_2F20:
  2F20  C6 01             LDB    #$01
  2F22  F7 62 16          STB    >$6216
  2F25  F6 60 10          LDB    >InputState             ; joystick+jump, bit7 = jump edge
  2F28  8E 00 80          LDX    #$0080
  2F2B  56                RORB
  2F2C  25 09             BCS    L_2F37
  2F2E  8E FF 80          LDX    #$FF80
  2F31  56                RORB
  2F32  25 03             BCS    L_2F37
  2F34  8E 00 00          LDX    #$0000
L_2F37:
  2F37  9F 02             STX    <$02
  2F39  1F 10             TFR    X,D
  2F3B  8E 62 10          LDX    #$6210
  2F3E  ED 81             STD    ,X++
  2F40  86 01             LDA    #$01
  2F42  A7 80             STA    ,X+
  2F44  86 48             LDA    #$48
  2F46  A7 80             STA    ,X+
  2F48  5F                CLRB
  2F49  E7 84             STB    ,X
  2F4B  F7 62 04          STB    >$6204
  2F4E  F7 62 06          STB    >$6206
  2F51  F6 62 07          LDB    >$6207
  2F54  C4 80             ANDB   #$80
  2F56  CA 0E             ORB    #$0E
  2F58  F7 62 07          STB    >$6207
  2F5B  F6 62 05          LDB    >MarioY
  2F5E  F7 62 0E          STB    >$620E
  2F61  8E 60 81          LDX    #SndJump
  2F64  86 03             LDA    #$03
  2F66  A7 84             STA    ,X
  2F68  10 9E 04          LDY    <$04
L_2F6B:
  2F6B  39                RTS
L_2F6C:
  2F6C  CE 62 00          LDU    #MarioAlive
  2F6F  F6 62 03          LDB    >MarioX
  2F72  E7 4B             STB    11,U
  2F74  F6 62 05          LDB    >MarioY
  2F77  E7 4C             STB    12,U
  2F79  BD 37 F6          JSR    >SUB_37F6
  2F7C  BD 38 64          JSR    >SUB_3864
  2F7F  0A 04             DEC    <$04
  2F81  26 22             BNE    L_2FA5
  2F83  6F C8 10          CLR    <16,U
  2F86  86 80             LDA    #$80
  2F88  A7 C8 11          STA    <17,U
  2F8B  A6 47             LDA    7,U
  2F8D  8A 80             ORA    #$80
  2F8F  A7 47             STA    7,U
L_2F91:
  2F91  F6 62 20          LDB    >$6220
  2F94  5A                DECB
  2F95  27 09             BEQ    L_2FA0
  2F97  BD 38 50          JSR    >SUB_3850
  2F9A  AF C8 12          STX    <18,U
  2F9D  6F C8 14          CLR    <20,U
L_2FA0:
  2FA0  BD 37 F6          JSR    >SUB_37F6
  2FA3  20 12             BRA    L_2FB7
L_2FA5:
  2FA5  0A 05             DEC    <$05
  2FA7  26 0E             BNE    L_2FB7
  2FA9  CC FF 80          LDD    #$FF80
  2FAC  ED C8 10          STD    <16,U
  2FAF  A6 47             LDA    7,U
  2FB1  84 7F             ANDA   #$7F
  2FB3  A7 47             STA    7,U
  2FB5  20 DA             BRA    L_2F91
L_2FB7:
  2FB7  10 9E 04          LDY    <$04
  2FBA  BD 3F 7B          JSR    >SUB_3F7B
  2FBD  5A                DECB
  2FBE  27 2E             BEQ    L_2FEE
  2FC0  F6 62 1F          LDB    >$621F
  2FC3  5A                DECB
  2FC4  27 69             BEQ    L_302F
  2FC6  F6 62 14          LDB    >$6214
  2FC9  C0 14             SUBB   #$14
  2FCB  26 18             BNE    L_2FE5
  2FCD  C6 01             LDB    #$01
  2FCF  F7 62 1F          STB    >$621F
  2FD2  BD 3C 91          JSR    >CheckJumpOver
  2FD5  5D                TSTB
  2FD6  10 27 01 A6       LBEQ   L_3180
  2FDA  F7 63 42          STB    >$6342
  2FDD  C6 01             LDB    #$01
  2FDF  F7 63 40          STB    >$6340
  2FE2  F7 62 25          STB    >$6225
L_2FE5:
  2FE5  5C                INCB
  2FE6  26 03             BNE    L_2FEB
  2FE8  BD 3D A2          JSR    >SUB_3DA2
L_2FEB:
  2FEB  7E 31 80          JMP    >L_3180
L_2FEE:
  2FEE  0A 02             DEC    <$02
  2FF0  27 12             BEQ    L_3004
  2FF2  5C                INCB
  2FF3  F7 62 1F          STB    >$621F
  2FF6  5F                CLRB
  2FF7  8E 62 10          LDX    #$6210
  2FFA  86 05             LDA    #$05
L_2FFC:
  2FFC  E7 80             STB    ,X+
  2FFE  4A                DECA
  2FFF  26 FB             BNE    L_2FFC
  3001  7E 31 80          JMP    >L_3180
L_3004:
  3004  F7 62 16          STB    >$6216
  3007  F6 62 20          LDB    >$6220
  300A  C8 01             EORB   #$01
  300C  F7 62 00          STB    >MarioAlive             ; bit0 = Mario alive
  300F  8E 62 07          LDX    #$6207
  3012  E6 84             LDB    ,X
  3014  C4 80             ANDB   #$80
  3016  CA 0F             ORB    #$0F
  3018  E7 84             STB    ,X
  301A  C6 04             LDB    #$04
  301C  F7 62 1E          STB    >$621E
  301F  5F                CLRB
  3020  F7 62 1F          STB    >$621F
  3023  F6 62 25          LDB    >$6225
  3026  5A                DECB
  3027  26 03             BNE    L_302C
  3029  BD 31 6B          JSR    >SUB_316B
L_302C:
  302C  7E 31 80          JMP    >L_3180
L_302F:
  302F  F6 62 05          LDB    >MarioY
  3032  8E 62 0E          LDX    #$620E
  3035  C0 0F             SUBB   #$0F
  3037  E1 84             CMPB   ,X
  3039  10 25 01 43       LBCS   L_3180
  303D  C6 01             LDB    #$01
  303F  F7 62 20          STB    >$6220
  3042  8E 60 84          LDX    #SndFx4
  3045  86 03             LDA    #$03
  3047  A7 84             STA    ,X
  3049  7E 31 80          JMP    >L_3180
L_304C:
  304C  86 01             LDA    #$01
  304E  97 02             STA    <$02
  3050  10 9E 04          LDY    <$04
  3053  F6 62 0F          LDB    >$620F
  3056  26 41             BNE    L_3099
  3058  F6 62 02          LDB    >$6202
  305B  D7 02             STB    <$02
  305D  C6 05             LDB    #$05
  305F  BD 44 59          JSR    >SUB_4459
  3062  F7 62 02          STB    >$6202
  3065  C4 03             ANDB   #$03
  3067  CA 80             ORB    #$80
  3069  20 1B             BRA    L_3086
L_306B:
  306B  86 FF             LDA    #$FF
  306D  97 02             STA    <$02
  306F  10 9E 04          LDY    <$04
  3072  F6 62 0F          LDB    >$620F
  3075  26 22             BNE    L_3099
  3077  F6 62 02          LDB    >$6202
  307A  D7 02             STB    <$02
  307C  C6 01             LDB    #$01
  307E  BD 44 59          JSR    >SUB_4459
  3081  F7 62 02          STB    >$6202
  3084  C4 03             ANDB   #$03
L_3086:
  3086  8E 62 07          LDX    #$6207
  3089  E7 84             STB    ,X
  308B  56                RORB
  308C  24 03             BCC    L_3091
  308E  BD 31 65          JSR    >SUB_3165
L_3091:
  3091  C6 02             LDB    #$02
  3093  F7 62 0F          STB    >$620F
  3096  7E 31 80          JMP    >L_3180
L_3099:
  3099  8E 62 03          LDX    #MarioX
  309C  E6 84             LDB    ,X
  309E  DB 02             ADDB   <$02
  30A0  E7 84             STB    ,X
  30A2  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  30A5  5A                DECB
  30A6  26 0F             BNE    L_30B7
  30A8  A6 84             LDA    ,X
  30AA  F6 62 05          LDB    >MarioY
  30AD  1F 01             TFR    D,X
  30AF  BD 37 6C          JSR    >SUB_376C
  30B2  D6 07             LDB    <$07
  30B4  F7 62 05          STB    >MarioY
L_30B7:
  30B7  8E 62 0F          LDX    #$620F
  30BA  6A 84             DEC    ,X
  30BC  7E 31 80          JMP    >L_3180
L_30BF:
  30BF  10 9E 04          LDY    <$04
  30C2  F6 62 0F          LDB    >$620F
  30C5  10 26 00 96       LBNE   L_315F
  30C9  C6 03             LDB    #$03
  30CB  F7 62 0F          STB    >$620F
  30CE  C6 02             LDB    #$02
  30D0  20 0F             BRA    L_30E1
L_30D2:
  30D2  10 9E 04          LDY    <$04
  30D5  F6 62 0F          LDB    >$620F
  30D8  26 71             BNE    L_314B
  30DA  C6 04             LDB    #$04
  30DC  F7 62 0F          STB    >$620F
  30DF  C6 FE             LDB    #$FE
L_30E1:
  30E1  8E 62 05          LDX    #MarioY
  30E4  EB 84             ADDB   ,X
  30E6  E7 84             STB    ,X
  30E8  D7 02             STB    <$02
  30EA  F6 62 22          LDB    >$6222
  30ED  C8 01             EORB   #$01
  30EF  F7 62 22          STB    >$6222
  30F2  26 33             BNE    L_3127
  30F4  D6 02             LDB    <$02
  30F6  CB 08             ADDB   #$08
  30F8  8E 62 1C          LDX    #$621C
  30FB  E1 84             CMPB   ,X
  30FD  27 3E             BEQ    L_313D
  30FF  E0 82             SUBB   ,-X
  3101  27 3A             BEQ    L_313D
  3103  86 05             LDA    #$05
  3105  97 02             STA    <$02
  3107  C0 08             SUBB   #$08
  3109  27 08             BEQ    L_3113
  310B  0A 02             DEC    <$02
  310D  C0 04             SUBB   #$04
  310F  27 02             BEQ    L_3113
  3111  0A 02             DEC    <$02
L_3113:
  3113  C6 80             LDB    #$80
  3115  8E 62 07          LDX    #$6207
  3118  E4 84             ANDB   ,X
  311A  C8 80             EORB   #$80
  311C  DA 02             ORB    <$02
  311E  E7 84             STB    ,X
L_3120:
  3120  C6 01             LDB    #$01
  3122  F7 62 15          STB    >$6215
  3125  20 59             BRA    L_3180
L_3127:
  3127  E6 83             LDB    ,--X
  3129  CA 03             ORB    #$03
  312B  C4 FB             ANDB   #$FB
  312D  E7 84             STB    ,X
  312F  F6 62 24          LDB    >$6224
  3132  C8 01             EORB   #$01
  3134  F7 62 24          STB    >$6224
  3137  26 E7             BNE    L_3120
  3139  8D 2A             BSR    SUB_3165
  313B  20 E3             BRA    L_3120
L_313D:
  313D  C6 06             LDB    #$06
  313F  F7 62 07          STB    >$6207
  3142  5F                CLRB
  3143  F7 62 19          STB    >$6219
  3146  F7 62 15          STB    >$6215
  3149  20 35             BRA    L_3180
L_314B:
  314B  F6 62 1A          LDB    >$621A
  314E  27 0F             BEQ    L_315F
  3150  F7 62 19          STB    >$6219
  3153  F6 62 1C          LDB    >$621C
  3156  C0 13             SUBB   #$13
  3158  8E 62 05          LDX    #MarioY
  315B  E1 84             CMPB   ,X
  315D  24 05             BCC    L_3164
L_315F:
  315F  8E 62 0F          LDX    #$620F
  3162  6A 84             DEC    ,X
L_3164:
  3164  39                RTS

; =====================================================================
; SUB_3165 (3 instructions)
; Uses:  SndWalk
; =====================================================================
SUB_3165:
  3165  C6 03             LDB    #$03
  3167  F7 60 80          STB    >SndWalk                ; sound buffer: frames to hold latch
  316A  39                RTS

; =====================================================================
; SUB_316B (19 instructions)
; Uses:  $6225 ScreenNum MusicReq2 $694C MarioX $6207 MarioY
; =====================================================================
SUB_316B:
  316B  F7 62 25          STB    >$6225
  316E  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  3171  5A                DECB
  3172  27 0B             BEQ    L_317F
  3174  8E 60 8A          LDX    #MusicReq2
  3177  86 0D             LDA    #$0D
  3179  A7 80             STA    ,X+
  317B  86 03             LDA    #$03
  317D  A7 84             STA    ,X
L_317F:
  317F  39                RTS
L_3180:
  3180  8E 69 4C          LDX    #$694C
  3183  F6 62 03          LDB    >MarioX
  3186  C4 FE             ANDB   #$FE
  3188  E7 80             STB    ,X+
  318A  F6 62 07          LDB    >$6207
  318D  E7 81             STB    ,X++
  318F  F6 62 05          LDB    >MarioY
  3192  E7 84             STB    ,X
  3194  39                RTS

; =====================================================================
; SUB_3195 (85 instructions)
; Uses:  $6340 $6341 $6342 SndFx5 Level RandNum $6343 MarioY MarioX $6A30
; Calls: RST_JumpTable AddTask RST_RetIfNotScreen
; =====================================================================
SUB_3195:
  3195  F6 63 40          LDB    >$6340
  3198  9D 47             JSR    <RST_JumpTable
TBL_MarioJump:
  319A  32 48             FDB    L_3248
  319C  31 A2             FDB    L_31A2
  319E  32 49             FDB    L_3249
  31A0  11 14             FDB    ColdStart
L_31A2:
  31A2  C6 40             LDB    #$40
  31A4  F7 63 41          STB    >$6341
  31A7  C6 02             LDB    #$02
  31A9  F7 63 40          STB    >$6340
  31AC  F6 63 42          LDB    >$6342
  31AF  56                RORB
  31B0  25 4F             BCS    L_3201
  31B2  56                RORB
  31B3  25 1E             BCS    L_31D3
  31B5  56                RORB
  31B6  25 12             BCS    L_31CA
  31B8  8E 60 85          LDX    #SndFx5
  31BB  86 03             LDA    #$03
  31BD  A7 84             STA    ,X
  31BF  F6 62 29          LDB    >Level                  ; level number
  31C2  5A                DECB
  31C3  27 0E             BEQ    L_31D3
  31C5  5A                DECB
  31C6  27 15             BEQ    L_31DD
  31C8  20 1D             BRA    L_31E7
L_31CA:
  31CA  F6 60 18          LDB    >RandNum                ; random number
  31CD  56                RORB
  31CE  25 0D             BCS    L_31DD
  31D0  56                RORB
  31D1  25 14             BCS    L_31E7
L_31D3:
  31D3  86 7D             LDA    #$7D
  31D5  97 02             STA    <$02
  31D7  10 8E 00 03       LDY    #$0003
  31DB  20 12             BRA    L_31EF
L_31DD:
  31DD  86 7E             LDA    #$7E
  31DF  97 02             STA    <$02
  31E1  10 8E 00 05       LDY    #$0005
  31E5  20 08             BRA    L_31EF
L_31E7:
  31E7  86 7F             LDA    #$7F
  31E9  97 02             STA    <$02
  31EB  10 8E 00 08       LDY    #$0008                  ; queue AddScore(8)
L_31EF:
  31EF  BD 45 21          JSR    >AddTask
  31F2  BE 63 43          LDX    >$6343
  31F5  E6 84             LDB    ,X
  31F7  6F 84             CLR    ,X
  31F9  30 03             LEAX   3,X
  31FB  A6 84             LDA    ,X
  31FD  97 03             STA    <$03
  31FF  20 2B             BRA    L_322C
L_3201:
  3201  10 8E 00 01       LDY    #$0001
  3205  86 7B             LDA    #$7B
  3207  97 02             STA    <$02
  3209  56                RORB
  320A  24 13             BCC    L_321F
  320C  10 8E 00 03       LDY    #$0003
  3210  86 7D             LDA    #$7D
  3212  97 02             STA    <$02
  3214  56                RORB
  3215  24 08             BCC    L_321F
  3217  10 8E 00 05       LDY    #$0005
  321B  86 7F             LDA    #$7F
  321D  97 02             STA    <$02
L_321F:
  321F  BD 45 21          JSR    >AddTask
  3222  F6 62 05          LDB    >MarioY
  3225  CB 14             ADDB   #$14
  3227  D7 03             STB    <$03
  3229  F6 62 03          LDB    >MarioX
L_322C:
  322C  8E 6A 30          LDX    #$6A30
  322F  E7 80             STB    ,X+
  3231  96 02             LDA    <$02
  3233  A7 80             STA    ,X+
  3235  86 07             LDA    #$07
  3237  A7 80             STA    ,X+
  3239  96 03             LDA    <$03
  323B  A7 84             STA    ,X
  323D  C6 05             LDB    #$05
  323F  9D 64             JSR    <RST_RetIfNotScreen
  3241  8E 60 85          LDX    #SndFx5
  3244  86 03             LDA    #$03
  3246  A7 84             STA    ,X
L_3248:
  3248  39                RTS
L_3249:
  3249  8E 63 41          LDX    #$6341
  324C  6A 84             DEC    ,X
  324E  26 F8             BNE    L_3248
  3250  5F                CLRB
  3251  F7 6A 30          STB    >$6A30
  3254  F7 63 40          STB    >$6340
  3257  39                RTS

; =====================================================================
; SUB_3258 (24 instructions)
; Uses:  ScreenNum MarioY MarioX $694D $6290 GameState
; =====================================================================
SUB_3258:
  3258  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  325B  1F 98             TFR    B,A
  325D  84 04             ANDA   #$04
  325F  26 1E             BNE    L_327F
  3261  56                RORB
  3262  F6 62 05          LDB    >MarioY
  3265  25 13             BCS    L_327A
  3267  C1 51             CMPB   #$51
  3269  24 DD             BCC    L_3248
  326B  F6 62 03          LDB    >MarioX
  326E  59                ROLB
L_326F:
  326F  C6 00             LDB    #$00
  3271  25 02             BCS    L_3275
  3273  C6 80             LDB    #$80
L_3275:
  3275  F7 69 4D          STB    >$694D
  3278  20 0A             BRA    L_3284
L_327A:
  327A  C1 31             CMPB   #$31
  327C  25 F1             BCS    L_326F
  327E  39                RTS
L_327F:
  327F  F6 62 90          LDB    >$6290
  3282  26 10             BNE    L_3294
L_3284:
  3284  C6 16             LDB    #$16
  3286  F7 60 0A          STB    >GameState              ; sub-state of GameMode
  3289  35 90             PULS   X,PC

; =====================================================================
; SUB_328B (5 instructions)
; Uses:  $6350
; Calls: SUB_3295
; =====================================================================
SUB_328B:
  328B  F6 63 50          LDB    >$6350
  328E  27 04             BEQ    L_3294
  3290  8D 03             BSR    SUB_3295
  3292  35 90             PULS   X,PC
L_3294:
  3294  39                RTS

; =====================================================================
; SUB_3295 (85 instructions)
; Uses:  $6345 $6351 $69B8 $69D0 $6980 $6353 $6354 $6342 $6A2C MusicReq2 $6346 $6A2D $6350 $6340 ...
; Calls: RST_JumpTable
; =====================================================================
SUB_3295:
  3295  F6 63 45          LDB    >$6345
  3298  9D 47             JSR    <RST_JumpTable
TBL_329A:
  329A  32 A0             FDB    L_32A0
  329C  33 0B             FDB    L_330B
  329E  33 2B             FDB    L_332B
L_32A0:
  32A0  F6 63 51          LDB    >$6351
  32A3  8E 69 B8          LDX    #$69B8
  32A6  C1 65             CMPB   #$65
  32A8  27 08             BEQ    L_32B2
  32AA  8E 69 D0          LDX    #$69D0
  32AD  25 03             BCS    L_32B2
  32AF  8E 69 80          LDX    #$6980
L_32B2:
  32B2  FE 63 51          LDU    >$6351
  32B5  4F                CLRA
  32B6  F6 63 53          LDB    >$6353
  32B9  1F 02             TFR    D,Y
  32BB  F6 63 54          LDB    >$6354
  32BE  27 0D             BEQ    L_32CD
L_32C0:
  32C0  30 04             LEAX   4,X
  32C2  D7 01             STB    <$01
  32C4  1F 20             TFR    Y,D
  32C6  33 CB             LEAU   D,U
  32C8  D6 01             LDB    <$01
  32CA  5A                DECB
  32CB  26 F3             BNE    L_32C0
L_32CD:
  32CD  6F C4             CLR    ,U
  32CF  C6 02             LDB    #$02
  32D1  A6 C8 15          LDA    <21,U
  32D4  27 02             BEQ    L_32D8
  32D6  C6 04             LDB    #$04
L_32D8:
  32D8  F7 63 42          STB    >$6342
  32DB  DF 08             STU    <$08
  32DD  CE 6A 2C          LDU    #$6A2C
  32E0  E6 84             LDB    ,X
  32E2  6F 84             CLR    ,X
  32E4  E7 C4             STB    ,U
  32E6  C6 60             LDB    #$60
  32E8  E7 41             STB    1,U
  32EA  30 03             LEAX   3,X
  32EC  E6 84             LDB    ,X
  32EE  E7 43             STB    3,U
  32F0  DE 08             LDU    <$08
  32F2  8E 63 45          LDX    #$6345
  32F5  6C 80             INC    ,X+
  32F7  86 06             LDA    #$06
  32F9  A7 80             STA    ,X+
  32FB  86 05             LDA    #$05
  32FD  A7 84             STA    ,X
  32FF  8E 60 8A          LDX    #MusicReq2
  3302  86 06             LDA    #$06
  3304  A7 80             STA    ,X+
  3306  86 03             LDA    #$03
  3308  A7 84             STA    ,X
  330A  39                RTS
L_330B:
  330B  8E 63 46          LDX    #$6346
  330E  6A 84             DEC    ,X
  3310  26 18             BNE    L_332A
  3312  86 06             LDA    #$06
  3314  A7 80             STA    ,X+
  3316  6A 84             DEC    ,X
  3318  27 0A             BEQ    L_3324
  331A  8E 6A 2D          LDX    #$6A2D
  331D  E6 84             LDB    ,X
  331F  C8 01             EORB   #$01
  3321  E7 84             STB    ,X
  3323  39                RTS
L_3324:
  3324  86 04             LDA    #$04
  3326  A7 84             STA    ,X
  3328  6C 83             INC    ,--X
L_332A:
  332A  39                RTS
L_332B:
  332B  8E 63 46          LDX    #$6346
  332E  6A 84             DEC    ,X
  3330  26 1E             BNE    L_3350
  3332  86 0C             LDA    #$0C
  3334  A7 80             STA    ,X+
  3336  6A 84             DEC    ,X
  3338  27 06             BEQ    L_3340
  333A  8E 6A 2D          LDX    #$6A2D
  333D  6C 84             INC    ,X
  333F  39                RTS
L_3340:
  3340  5F                CLRB
  3341  E7 83             STB    ,--X
  3343  F7 63 50          STB    >$6350
  3346  5C                INCB
  3347  F7 63 40          STB    >$6340
  334A  8E 6A 2C          LDX    #$6A2C
  334D  BF 63 43          STX    >$6343
L_3350:
  3350  39                RTS

; =====================================================================
; SUB_3351 (17 instructions)
; Uses:  $6221 $6204 $6206 $6210 $6211 $6212 $6213 $6214 $6216 $621F MarioY $620E
; =====================================================================
SUB_3351:
  3351  F6 62 21          LDB    >$6221
  3354  27 26             BEQ    L_337C
  3356  5F                CLRB
  3357  F7 62 04          STB    >$6204
  335A  F7 62 06          STB    >$6206
  335D  F7 62 21          STB    >$6221
  3360  F7 62 10          STB    >$6210
  3363  F7 62 11          STB    >$6211
  3366  F7 62 12          STB    >$6212
  3369  F7 62 13          STB    >$6213
  336C  F7 62 14          STB    >$6214
  336F  5C                INCB
  3370  F7 62 16          STB    >$6216
  3373  F7 62 1F          STB    >$621F
  3376  F6 62 05          LDB    >MarioY
  3379  F7 62 0E          STB    >$620E
L_337C:
  337C  39                RTS

; =====================================================================
; SUB_337D (227 instructions)
; Uses:  ScreenNum Barrels $6980 MarioY
; Calls: Z80_EXX SUB_376C SUB_3827 SUB_38F6 SUB_37F6 SUB_3E8A SUB_3850 SUB_3706 SUB_356C
; =====================================================================
SUB_337D:
  337D  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  3380  5A                DECB
  3381  26 F9             BNE    L_337C
  3383  CE 67 00          LDU    #Barrels
  3386  8E 69 80          LDX    #$6980
  3389  10 8E 00 20       LDY    #$0020
  338D  86 0A             LDA    #$0A
  338F  97 02             STA    <$02
L_3391:
  3391  E6 C4             LDB    ,U
  3393  5A                DECB
  3394  27 11             BEQ    L_33A7
  3396  30 03             LEAX   3,X
L_3398:
  3398  30 01             LEAX   1,X
  339A  D7 01             STB    <$01
  339C  1F 20             TFR    Y,D
  339E  33 CB             LEAU   D,U
  33A0  D6 01             LDB    <$01
  33A2  0A 02             DEC    <$02
  33A4  26 EB             BNE    L_3391
  33A6  39                RTS
L_33A7:
  33A7  E6 41             LDB    1,U
  33A9  5A                DECB
  33AA  10 27 01 40       LBEQ   L_34EE
  33AE  E6 42             LDB    2,U
  33B0  56                RORB
  33B1  25 09             BCS    L_33BC
  33B3  56                RORB
  33B4  25 3A             BCS    L_33F0
  33B6  56                RORB
  33B7  25 43             BCS    L_33FC
  33B9  7E 34 67          JMP    >L_3467
L_33BC:
  33BC  BD 53 3C          JSR    >Z80_EXX
  33BF  6C 45             INC    5,U
  33C1  E6 C8 17          LDB    <23,U
  33C4  E1 45             CMPB   5,U
  33C6  26 16             BNE    L_33DE
  33C8  E6 C8 15          LDB    <21,U
  33CB  1F 98             TFR    B,A
  33CD  49                ROLA
  33CE  59                ROLB
  33CF  49                ROLA
  33D0  59                ROLB
  33D1  CB 15             ADDB   #$15
  33D3  E7 47             STB    7,U
  33D5  E6 42             LDB    2,U
  33D7  C8 07             EORB   #$07
  33D9  E7 42             STB    2,U
  33DB  7E 35 C5          JMP    >L_35C5
L_33DE:
  33DE  E6 4F             LDB    15,U
  33E0  5A                DECB
  33E1  26 08             BNE    L_33EB
  33E3  E6 47             LDB    7,U
  33E5  C8 01             EORB   #$01
  33E7  E7 47             STB    7,U
  33E9  C6 04             LDB    #$04
L_33EB:
  33EB  E7 4F             STB    15,U
  33ED  7E 35 C5          JMP    >L_35C5
L_33F0:
  33F0  BD 53 3C          JSR    >Z80_EXX
  33F3  8E 01 00          LDX    #$0100
  33F6  9F 02             STX    <$02
  33F8  6C 43             INC    3,U
  33FA  20 0A             BRA    L_3406
L_33FC:
  33FC  BD 53 3C          JSR    >Z80_EXX
  33FF  8E FF 04          LDX    #$FF04
  3402  9F 02             STX    <$02
  3404  6A 43             DEC    3,U
L_3406:
  3406  A6 43             LDA    3,U
  3408  E6 45             LDB    5,U
  340A  1F 01             TFR    D,X
  340C  84 07             ANDA   #$07
  340E  81 03             CMPA   #$03
  3410  10 27 01 44       LBEQ   L_3558
  3414  1F 10             TFR    X,D
  3416  C0 03             SUBB   #$03
  3418  1F 01             TFR    D,X
  341A  BD 37 6C          JSR    >SUB_376C
  341D  DC 06             LDD    <$06
  341F  CB 03             ADDB   #$03
  3421  1F 01             TFR    D,X
  3423  E7 45             STB    5,U
  3425  BD 38 27          JSR    >SUB_3827
  3428  BD 38 F6          JSR    >SUB_38F6
  342B  E6 43             LDB    3,U
  342D  C1 1C             CMPB   #$1C
  342F  25 11             BCS    L_3442
  3431  C1 E4             CMPB   #$E4
  3433  10 25 01 8E       LBCS   L_35C5
  3437  5F                CLRB
  3438  E7 C8 10          STB    <16,U
  343B  86 60             LDA    #$60
  343D  A7 C8 11          STA    <17,U
  3440  20 0B             BRA    L_344D
L_3442:
  3442  5F                CLRB
  3443  86 FF             LDA    #$FF
  3445  A7 C8 10          STA    <16,U
  3448  86 A0             LDA    #$A0
  344A  A7 C8 11          STA    <17,U
L_344D:
  344D  86 FF             LDA    #$FF
  344F  A7 C8 12          STA    <18,U
  3452  86 F0             LDA    #$F0
  3454  A7 C8 13          STA    <19,U
  3457  E7 C8 14          STB    <20,U
  345A  E7 4E             STB    14,U
  345C  E7 44             STB    4,U
  345E  E7 46             STB    6,U
  3460  86 08             LDA    #$08
  3462  A7 42             STA    2,U
  3464  7E 35 C5          JMP    >L_35C5
L_3467:
  3467  BD 53 3C          JSR    >Z80_EXX
  346A  BD 37 F6          JSR    >SUB_37F6
  346D  BD 3E 8A          JSR    >SUB_3E8A
  3470  5D                TSTB
  3471  26 22             BNE    L_3495
  3473  E6 43             LDB    3,U
  3475  CB 08             ADDB   #$08
  3477  C1 10             CMPB   #$10
  3479  25 12             BCS    L_348D
  347B  BD 38 F6          JSR    >SUB_38F6
  347E  E6 C8 10          LDB    <16,U
  3481  C4 01             ANDB   #$01
  3483  58                ASLB
  3484  58                ASLB
  3485  D7 03             STB    <$03
  3487  BD 38 27          JSR    >SUB_3827
  348A  7E 35 C5          JMP    >L_35C5
L_348D:
  348D  5F                CLRB
  348E  E7 C4             STB    ,U
  3490  E7 43             STB    3,U
  3492  7E 35 C5          JMP    >L_35C5
L_3495:
  3495  6C 4E             INC    14,U
  3497  E6 4E             LDB    14,U
  3499  5A                DECB
  349A  27 12             BEQ    L_34AE
  349C  5A                DECB
  349D  27 2C             BEQ    L_34CB
  349F  C6 04             LDB    #$04
  34A1  A6 C8 10          LDA    <16,U
  34A4  4A                DECA
  34A5  26 02             BNE    L_34A9
  34A7  C6 02             LDB    #$02
L_34A9:
  34A9  E7 42             STB    2,U
  34AB  7E 35 C5          JMP    >L_35C5
L_34AE:
  34AE  E6 C8 15          LDB    <21,U
  34B1  26 0B             BNE    L_34BE
  34B3  8E 62 05          LDX    #MarioY
  34B6  E6 45             LDB    5,U
  34B8  C0 16             SUBB   #$16
  34BA  E1 84             CMPB   ,X
  34BC  24 0D             BCC    L_34CB
L_34BE:
  34BE  E6 C8 10          LDB    <16,U
  34C1  26 21             BNE    L_34E4
  34C3  E7 C8 11          STB    <17,U
  34C6  86 FF             LDA    #$FF
  34C8  A7 C8 10          STA    <16,U
L_34CB:
  34CB  BD 38 50          JSR    >SUB_3850
  34CE  1F 10             TFR    X,D
  34D0  44                LSRA
  34D1  56                RORB
  34D2  44                LSRA
  34D3  56                RORB
  34D4  1F 01             TFR    D,X
  34D6  ED C8 12          STD    <18,U
  34D9  5F                CLRB
  34DA  E7 C8 14          STB    <20,U
  34DD  E7 44             STB    4,U
  34DF  E7 46             STB    6,U
  34E1  7E 35 C5          JMP    >L_35C5
L_34E4:
  34E4  86 01             LDA    #$01
  34E6  A7 C8 10          STA    <16,U
  34E9  6F C8 11          CLR    <17,U
  34EC  20 DD             BRA    L_34CB
L_34EE:
  34EE  BD 53 3C          JSR    >Z80_EXX
  34F1  BD 37 F6          JSR    >SUB_37F6
  34F4  1F 10             TFR    X,D
  34F6  80 1A             SUBA   #$1A
  34F8  E6 C8 19          LDB    <25,U
  34FB  D7 02             STB    <$02
  34FD  91 02             CMPA   <$02
  34FF  25 09             BCS    L_350A
  3501  BD 3E 8A          JSR    >SUB_3E8A
  3504  5D                TSTB
  3505  26 15             BNE    L_351C
  3507  BD 38 F6          JSR    >SUB_38F6
L_350A:
  350A  E6 43             LDB    3,U
  350C  CB 08             ADDB   #$08
  350E  C1 10             CMPB   #$10
  3510  10 24 FE CA       LBCC   L_33DE
  3514  5F                CLRB
  3515  E7 C4             STB    ,U
  3517  E7 43             STB    3,U
  3519  7E 35 C5          JMP    >L_35C5
L_351C:
  351C  E6 45             LDB    5,U
  351E  C1 E0             CMPB   #$E0
  3520  25 20             BCS    L_3542
  3522  E6 47             LDB    7,U
  3524  C4 FC             ANDB   #$FC
  3526  CA 01             ORB    #$01
  3528  E7 47             STB    7,U
  352A  5F                CLRB
  352B  E7 41             STB    1,U
  352D  E7 42             STB    2,U
  352F  86 FF             LDA    #$FF
  3531  ED C8 10          STD    <16,U
  3534  E7 C8 12          STB    <18,U
  3537  86 B0             LDA    #$B0
  3539  A7 C8 13          STA    <19,U
  353C  86 01             LDA    #$01
  353E  A7 4E             STA    14,U
  3540  20 0C             BRA    L_354E
L_3542:
  3542  BD 38 50          JSR    >SUB_3850
  3545  BD 37 06          JSR    >SUB_3706
  3548  E6 45             LDB    5,U
  354A  E7 C8 19          STB    <25,U
  354D  5F                CLRB
L_354E:
  354E  E7 C8 14          STB    <20,U
  3551  E7 44             STB    4,U
  3553  E7 46             STB    6,U
  3555  7E 35 C5          JMP    >L_35C5
L_3558:
  3558  1F 10             TFR    X,D
  355A  CB 05             ADDB   #$05
  355C  10 9F 04          STY    <$04
  355F  D7 04             STB    <$04
  3561  1F 89             TFR    A,B
  3563  8E 00 15          LDX    #$0015
  3566  9F 02             STX    <$02
  3568  8D 02             BSR    SUB_356C
  356A  20 59             BRA    L_35C5

; =====================================================================
; SUB_356C (51 instructions)
; Uses:  $6348 MarioY Difficulty RandNum InputState MarioX
; Calls: SUB_37B6 Z80_EXX
; =====================================================================
SUB_356C:
  356C  BD 37 B6          JSR    >SUB_37B6
  356F  5A                DECB
  3570  26 52             BNE    L_35C4
  3572  D6 02             LDB    <$02
  3574  C0 05             SUBB   #$05
  3576  E7 C8 17          STB    <23,U
  3579  F6 63 48          LDB    >$6348
  357C  27 3E             BEQ    L_35BC
  357E  F6 62 05          LDB    >MarioY
L_3581:
  3581  C0 10             SUBB   #$10                    ; difficulty operand: $10 easy / $04 hard (patched by Setup)  [SMC: operand patched by $58E1]
  3583  10 9F 04          STY    <$04
  3586  D1 04             CMPB   <$04
  3588  25 3A             BCS    L_35C4
  358A  F6 63 80          LDB    >Difficulty
  358D  56                RORB
  358E  5C                INCB
  358F  D7 02             STB    <$02
  3591  F6 60 18          LDB    >RandNum                ; random number
  3594  D7 03             STB    <$03
  3596  C4 03             ANDB   #$03
  3598  D1 02             CMPB   <$02
  359A  24 28             BCC    L_35C4
  359C  8E 60 10          LDX    #InputState
  359F  F6 62 03          LDB    >MarioX
  35A2  D1 05             CMPB   <$05
  35A4  27 16             BEQ    L_35BC
  35A6  24 08             BCC    L_35B0
  35A8  A6 84             LDA    ,X
  35AA  84 01             ANDA   #$01
  35AC  27 08             BEQ    L_35B6
  35AE  20 0C             BRA    L_35BC
L_35B0:
  35B0  A6 84             LDA    ,X
  35B2  84 02             ANDA   #$02
  35B4  26 06             BNE    L_35BC
L_35B6:
  35B6  D6 03             LDB    <$03
  35B8  C4 18             ANDB   #$18
  35BA  26 08             BNE    L_35C4
L_35BC:
  35BC  6C 47             INC    7,U
  35BE  A6 42             LDA    2,U
  35C0  8A 01             ORA    #$01
  35C2  A7 42             STA    2,U
L_35C4:
  35C4  39                RTS
L_35C5:
  35C5  BD 53 3C          JSR    >Z80_EXX
  35C8  E6 43             LDB    3,U
  35CA  C4 FE             ANDB   #$FE
  35CC  E7 80             STB    ,X+
  35CE  E6 47             LDB    7,U
  35D0  E7 81             STB    ,X++
  35D2  E6 45             LDB    5,U
  35D4  E7 84             STB    ,X
  35D6  7E 33 98          JMP    >L_3398
D_35D9:
  35D9  80 FE 01 C0 04    FCB    $80,$FE,$01,$C0,$04,$50,$02,$10
  35E1  82 60 02 10 82    FCB    $82,$60,$02,$10,$82,$CA,$01,$10
  35E9  81 FF 02 38 01    FCB    $81,$FF,$02,$38,$01,$80,$02,$FF
  35F1  04 80 04 60 80    FCB    $04,$80,$04,$60,$80,$11,$D1,$21
  35F9  21 CC 63 7E 07    FCB    $21,$CC,$63,$7E,$07,$83,$5F,$1A
  3601  32 10 60 2C 7E    FCB    $32,$10,$60,$2C,$7E,$35,$A7,$C0
  3609  1C 1A 77 2D 34    FCB    $1C,$1A,$77,$2D,$34,$C9

; =====================================================================
; SUB_360F (16 instructions)
; Uses:  $63CC InputState
; =====================================================================
SUB_360F:
  360F  10 8E 35 D9       LDY    #D_35D9
  3613  8E 63 CC          LDX    #$63CC
  3616  E6 80             LDB    ,X+
  3618  58                ASLB
  3619  31 A5             LEAY   B,Y
  361B  E6 A4             LDB    ,Y
  361D  F7 60 10          STB    >InputState             ; joystick+jump, bit7 = jump edge
  3620  E6 84             LDB    ,X
  3622  6A 84             DEC    ,X
  3624  5D                TSTB
  3625  26 08             BNE    L_362F
  3627  31 21             LEAY   1,Y
  3629  E6 A4             LDB    ,Y
  362B  E7 84             STB    ,X
  362D  6C 82             INC    ,-X
L_362F:
  362F  39                RTS

; =====================================================================
; SUB_3630 (26 instructions)
; Uses:  FrameCounter $6280 $6288 $621A
; Calls: RST_RetIfNotScreen RST_JumpTable SUB_3671
; =====================================================================
SUB_3630:
  3630  C6 02             LDB    #$02
  3632  9D 64             JSR    <RST_RetIfNotScreen
  3634  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  3637  56                RORB
  3638  8E 62 80          LDX    #$6280
  363B  E6 84             LDB    ,X
  363D  25 05             BCS    L_3644
  363F  8E 62 88          LDX    #$6288
  3642  E6 84             LDB    ,X
L_3644:
  3644  34 10             PSHS   X
  3646  9D 47             JSR    <RST_JumpTable
TBL_3648:
  3648  36 54             FDB    L_3654
  364A  36 87             FDB    L_3687
  364C  36 C7             FDB    L_36C7
  364E  36 D3             FDB    L_36D3
  3650  11 14             FDB    ColdStart
  3652  11 14             FDB    ColdStart
L_3654:
  3654  35 10             PULS   X
  3656  30 01             LEAX   1,X
  3658  6A 84             DEC    ,X
  365A  26 0C             BNE    L_3668
  365C  6C 82             INC    ,-X
  365E  30 02             LEAX   2,X
  3660  8D 0F             BSR    SUB_3671
  3662  C6 01             LDB    #$01
  3664  F7 62 1A          STB    >$621A
  3667  39                RTS
L_3668:
  3668  30 01             LEAX   1,X
  366A  8D 05             BSR    SUB_3671
  366C  5F                CLRB
  366D  F7 62 1A          STB    >$621A
  3670  39                RTS

; =====================================================================
; SUB_3671 (65 instructions)
; Uses:  MarioY $6216 MarioX $6222 RandNum
; Calls: SUB_36F3 SUB_3671 SUB_5334
; =====================================================================
SUB_3671:
  3671  F6 62 05          LDB    >MarioY
  3674  C1 7A             CMPB   #$7A
  3676  24 0C             BCC    L_3684
  3678  F6 62 16          LDB    >$6216
  367B  26 07             BNE    L_3684
  367D  F6 62 03          LDB    >MarioX
  3680  E1 84             CMPB   ,X
  3682  27 02             BEQ    L_3686
L_3684:
  3684  35 90             PULS   X,PC
L_3686:
  3686  39                RTS
L_3687:
  3687  35 10             PULS   X
  3689  30 04             LEAX   4,X
  368B  6A 84             DEC    ,X
  368D  26 F7             BNE    L_3686
  368F  C6 04             LDB    #$04
  3691  E7 84             STB    ,X
  3693  6C 82             INC    ,-X
  3695  BD 36 F3          JSR    >SUB_36F3
  3698  C6 78             LDB    #$78
  369A  E1 84             CMPB   ,X
  369C  26 06             BNE    L_36A4
  369E  30 1D             LEAX   -3,X
  36A0  6C 84             INC    ,X
  36A2  30 03             LEAX   3,X
L_36A4:
  36A4  30 1F             LEAX   -1,X
  36A6  8D C9             BSR    SUB_3671
  36A8  F6 62 05          LDB    >MarioY
  36AB  C1 68             CMPB   #$68
  36AD  24 0B             BCC    L_36BA
L_36AF:
  36AF  8E 62 05          LDX    #MarioY
  36B2  6C 84             INC    ,X
  36B4  BD 53 34          JSR    >SUB_5334
  36B7  6C 84             INC    ,X
  36B9  39                RTS
L_36BA:
  36BA  56                RORB
  36BB  25 F2             BCS    L_36AF
  36BD  56                RORB
  36BE  C6 01             LDB    #$01
  36C0  25 01             BCS    L_36C3
  36C2  5F                CLRB
L_36C3:
  36C3  F7 62 22          STB    >$6222
  36C6  39                RTS
L_36C7:
  36C7  35 10             PULS   X
  36C9  F6 60 18          LDB    >RandNum                ; random number
  36CC  C4 3C             ANDB   #$3C
  36CE  26 02             BNE    L_36D2
  36D0  6C 84             INC    ,X
L_36D2:
  36D2  39                RTS
L_36D3:
  36D3  35 10             PULS   X
  36D5  30 04             LEAX   4,X
  36D7  6A 84             DEC    ,X
  36D9  26 17             BNE    L_36F2
  36DB  86 02             LDA    #$02
  36DD  A7 84             STA    ,X
  36DF  6A 82             DEC    ,-X
  36E1  8D 10             BSR    SUB_36F3
  36E3  C6 68             LDB    #$68
  36E5  E1 84             CMPB   ,X
  36E7  26 09             BNE    L_36F2
  36E9  5F                CLRB
  36EA  86 80             LDA    #$80
  36EC  97 02             STA    <$02
  36EE  A7 83             STA    ,--X
  36F0  E7 82             STB    ,-X
L_36F2:
  36F2  39                RTS

; =====================================================================
; SUB_36F3 (8 instructions)
; Uses:  $694B $6947
; =====================================================================
SUB_36F3:
  36F3  1F 10             TFR    X,D
  36F5  A6 84             LDA    ,X
  36F7  10 8E 69 4B       LDY    #$694B
  36FB  C4 08             ANDB   #$08
  36FD  26 04             BNE    L_3703
  36FF  10 8E 69 47       LDY    #$6947
L_3703:
  3703  A7 A4             STA    ,Y
  3705  39                RTS

; =====================================================================
; SUB_3706 (45 instructions)
; Uses:  $6348 Difficulty Level RandNum MarioX
; Calls: RST_JumpTable
; =====================================================================
SUB_3706:
  3706  F6 63 48          LDB    >$6348
  3709  27 10             BEQ    L_371B
  370B  F6 63 80          LDB    >Difficulty
  370E  5A                DECB
  370F  9D 47             JSR    <RST_JumpTable
TBL_3711:
  3711  37 2F             FDB    L_372F
  3713  37 2F             FDB    L_372F
  3715  37 3C             FDB    L_373C
  3717  37 3C             FDB    L_373C
  3719  37 51             FDB    L_3751
L_371B:
  371B  B6 62 29          LDA    >Level                  ; level number
  371E  C6 01             LDB    #$01
  3720  4A                DECA
  3721  97 02             STA    <$02
  3723  27 0D             BEQ    L_3732
  3725  C6 B1             LDB    #$B1
  3727  0A 02             DEC    <$02
  3729  27 07             BEQ    L_3732
  372B  C6 E9             LDB    #$E9
  372D  20 03             BRA    L_3732
L_372F:
  372F  F6 60 18          LDB    >RandNum                ; random number
L_3732:
  3732  E7 C8 11          STB    <17,U
  3735  C4 01             ANDB   #$01
  3737  5A                DECB
  3738  E7 C8 10          STB    <16,U
  373B  39                RTS
L_373C:
  373C  F6 60 18          LDB    >RandNum                ; random number
  373F  E7 C8 11          STB    <17,U
  3742  F6 62 03          LDB    >MarioX
  3745  E1 43             CMPB   3,U
  3747  C6 01             LDB    #$01
  3749  24 02             BCC    L_374D
  374B  C6 FF             LDB    #$FF
L_374D:
  374D  E7 C8 10          STB    <16,U
  3750  39                RTS
L_3751:
  3751  F6 62 03          LDB    >MarioX
  3754  E0 43             SUBB   3,U
  3756  D7 01             STB    <$01
  3758  86 FF             LDA    #$FF
  375A  25 01             BCS    L_375D
  375C  4C                INCA
L_375D:
  375D  09 01             ROL    <$01
  375F  59                ROLB
  3760  49                ROLA
  3761  09 01             ROL    <$01
  3763  59                ROLB
  3764  49                ROLA
  3765  A7 C8 10          STA    <16,U
  3768  E7 C8 11          STB    <17,U
  376B  39                RTS

; =====================================================================
; SUB_376C (38 instructions)
; =====================================================================
SUB_376C:
  376C  C6 0F             LDB    #$0F
  376E  9F 06             STX    <$06
  3770  D4 06             ANDB   <$06
  3772  0A 02             DEC    <$02
  3774  27 0A             BEQ    L_3780
  3776  C1 0F             CMPB   #$0F
  3778  25 31             BCS    L_37AB
  377A  86 FF             LDA    #$FF
  377C  97 02             STA    <$02
  377E  20 08             BRA    L_3788
L_3780:
  3780  C1 01             CMPB   #$01
  3782  24 27             BCC    L_37AB
  3784  86 01             LDA    #$01
  3786  97 02             STA    <$02
L_3788:
  3788  C6 F0             LDB    #$F0
  378A  D1 07             CMPB   <$07
  378C  27 19             BEQ    L_37A7
  378E  C6 4C             LDB    #$4C
  3790  D1 07             CMPB   <$07
  3792  27 18             BEQ    L_37AC
  3794  D6 07             LDB    <$07
  3796  96 07             LDA    <$07
  3798  84 20             ANDA   #$20
  379A  27 07             BEQ    L_37A3
L_379C:
  379C  D0 02             SUBB   <$02
L_379E:
  379E  D7 07             STB    <$07
  37A0  9E 06             LDX    <$06
  37A2  39                RTS
L_37A3:
  37A3  DB 02             ADDB   <$02
  37A5  20 F7             BRA    L_379E
L_37A7:
  37A7  96 06             LDA    <$06
  37A9  2B F1             BMI    L_379C
L_37AB:
  37AB  39                RTS
L_37AC:
  37AC  D6 06             LDB    <$06
  37AE  C1 98             CMPB   #$98
  37B0  25 F9             BCS    L_37AB
  37B2  D6 07             LDB    <$07
  37B4  20 ED             BRA    L_37A3

; =====================================================================
; SUB_37B6 (30 instructions)
; Uses:  $6300
; =====================================================================
SUB_37B6:
  37B6  8E 63 00          LDX    #$6300
L_37B9:
  37B9  E1 80             CMPB   ,X+
  37BB  27 06             BEQ    L_37C3
  37BD  0A 03             DEC    <$03
  37BF  26 F8             BNE    L_37B9
  37C1  20 2D             BRA    L_37F0
L_37C3:
  37C3  34 10             PSHS   X
  37C5  0A 03             DEC    <$03
  37C7  30 88 14          LEAX   <20,X
  37CA  D7 05             STB    <$05
  37CC  D6 04             LDB    <$04
  37CE  E1 84             CMPB   ,X
  37D0  27 0F             BEQ    L_37E1
  37D2  30 88 15          LEAX   <21,X
  37D5  E1 84             CMPB   ,X
  37D7  27 0F             BEQ    L_37E8
  37D9  D7 04             STB    <$04
  37DB  D6 05             LDB    <$05
  37DD  35 10             PULS   X
  37DF  20 D8             BRA    L_37B9
L_37E1:
  37E1  30 88 15          LEAX   <21,X
  37E4  C6 01             LDB    #$01
  37E6  20 04             BRA    L_37EC
L_37E8:
  37E8  5F                CLRB
  37E9  30 88 EB          LEAX   <-21,X
L_37EC:
  37EC  A6 84             LDA    ,X
  37EE  97 02             STA    <$02
L_37F0:
  37F0  35 10             PULS   X
  37F2  10 9E 04          LDY    <$04
  37F5  39                RTS

; =====================================================================
; SUB_37F6 (27 instructions)
; =====================================================================
SUB_37F6:
  37F6  E6 44             LDB    4,U
  37F8  EB C8 11          ADDB   <17,U
  37FB  E7 44             STB    4,U
  37FD  E6 43             LDB    3,U
  37FF  E9 C8 10          ADCB   <16,U
  3802  E7 43             STB    3,U
  3804  E6 46             LDB    6,U
  3806  E0 C8 13          SUBB   <19,U
  3809  A6 45             LDA    5,U
  380B  A2 C8 12          SBCA   <18,U
  380E  1F 01             TFR    D,X
  3810  E6 C8 14          LDB    <20,U
  3813  4F                CLRA
  3814  59                ROLB
  3815  5C                INCB
  3816  49                ROLA
  3817  58                ASLB
  3818  49                ROLA
  3819  58                ASLB
  381A  49                ROLA
  381B  58                ASLB
  381C  49                ROLA
  381D  DD 02             STD    <$02
  381F  30 8B             LEAX   D,X
  3821  AF 45             STX    5,U
  3823  6C C8 14          INC    <20,U
  3826  39                RTS

; =====================================================================
; SUB_3827 (24 instructions)
; Calls: SUB_4459
; =====================================================================
SUB_3827:
  3827  E6 4F             LDB    15,U
  3829  5A                DECB
  382A  26 21             BNE    L_384D
  382C  5F                CLRB
  382D  68 47             ASL    7,U
  382F  59                ROLB
  3830  68 48             ASL    8,U
  3832  59                ROLB
  3833  D7 02             STB    <$02
  3835  C6 03             LDB    #$03
  3837  DA 03             ORB    <$03
  3839  BD 44 59          JSR    >SUB_4459
  383C  56                RORB
  383D  A6 47             LDA    7,U
  383F  84 7F             ANDA   #$7F
  3841  24 02             BCC    L_3845
  3843  8A 80             ORA    #$80
L_3845:
  3845  66 48             ROR    8,U
  3847  56                RORB
  3848  46                RORA
  3849  A7 47             STA    7,U
  384B  C6 04             LDB    #$04
L_384D:
  384D  E7 4F             STB    15,U
  384F  39                RTS

; =====================================================================
; SUB_3850 (12 instructions)
; =====================================================================
SUB_3850:
  3850  A6 C8 14          LDA    <20,U
  3853  49                ROLA
  3854  49                ROLA
  3855  49                ROLA
  3856  49                ROLA
  3857  1F 89             TFR    A,B
  3859  49                ROLA
  385A  84 0F             ANDA   #$0F
  385C  C4 F0             ANDB   #$F0
  385E  A3 C8 12          SUBD   <18,U
  3861  1F 01             TFR    D,X
  3863  39                RTS

; =====================================================================
; SUB_3864 (22 instructions)
; Uses:  MarioX ScreenNum MarioY
; =====================================================================
SUB_3864:
  3864  CC 01 00          LDD    #$0100
  3867  D7 05             STB    <$05
  3869  F6 62 03          LDB    >MarioX
  386C  C1 16             CMPB   #$16
  386E  25 1E             BCS    L_388E
  3870  4A                DECA
  3871  0C 05             INC    <$05
  3873  C1 EA             CMPB   #$EA
  3875  24 17             BCC    L_388E
  3877  0A 05             DEC    <$05
  3879  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  387C  56                RORB
  387D  24 0F             BCC    L_388E
  387F  F6 62 05          LDB    >MarioY
  3882  C1 58             CMPB   #$58
  3884  24 08             BCC    L_388E
  3886  F6 62 03          LDB    >MarioX
  3889  C1 6C             CMPB   #$6C
  388B  24 01             BCC    L_388E
  388D  4C                INCA
L_388E:
  388E  97 04             STA    <$04
  3890  39                RTS

; =====================================================================
; SUB_3891 (44 instructions)
; Uses:  $6310 ScreenNum $6300
; =====================================================================
SUB_3891:
  3891  10 8E 63 10       LDY    #$6310
  3895  10 9F 0A          STY    <$0A
  3898  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  389B  8E 4F 11          LDX    #D_4F11
  389E  5A                DECB
  389F  27 0F             BEQ    L_38B0
  38A1  8E 4F 8A          LDX    #D_4F8A
  38A4  5A                DECB
  38A5  27 09             BEQ    L_38B0
  38A7  8E 50 12          LDX    #D_5012
  38AA  5A                DECB
  38AB  27 03             BEQ    L_38B0
  38AD  8E 50 B8          LDX    #D_50B8
L_38B0:
  38B0  CE 63 00          LDU    #$6300
L_38B3:
  38B3  E6 84             LDB    ,X
  38B5  27 0B             BEQ    L_38C2
  38B7  5A                DECB
  38B8  27 1C             BEQ    L_38D6
  38BA  C1 A9             CMPB   #$A9
  38BC  27 D0             BEQ    L_388E
  38BE  30 05             LEAX   5,X
  38C0  20 F1             BRA    L_38B3
L_38C2:
  38C2  30 01             LEAX   1,X
  38C4  E6 80             LDB    ,X+
  38C6  E7 C4             STB    ,U
  38C8  E6 81             LDB    ,X++
  38CA  E7 C8 15          STB    <21,U
  38CD  E6 80             LDB    ,X+
  38CF  E7 C8 2A          STB    <42,U
  38D2  33 41             LEAU   1,U
  38D4  20 DD             BRA    L_38B3
L_38D6:
  38D6  30 01             LEAX   1,X
  38D8  E6 80             LDB    ,X+
  38DA  10 9F 04          STY    <$04
  38DD  10 9E 0A          LDY    <$0A
  38E0  E7 A4             STB    ,Y
  38E2  E6 81             LDB    ,X++
  38E4  E7 A8 15          STB    <21,Y
  38E7  E6 80             LDB    ,X+
  38E9  E7 A8 2A          STB    <42,Y
  38EC  31 21             LEAY   1,Y
  38EE  10 9F 0A          STY    <$0A
  38F1  10 9E 04          LDY    <$04
  38F4  20 BD             BRA    L_38B3

; =====================================================================
; SUB_38F6 (24 instructions)
; Uses:  $62B9 SndBoom $6348
; =====================================================================
SUB_38F6:
  38F6  E6 45             LDB    5,U
  38F8  C1 E8             CMPB   #$E8
  38FA  24 01             BCC    L_38FD
L_38FC:
  38FC  39                RTS
L_38FD:
  38FD  E6 43             LDB    3,U
  38FF  C1 2A             CMPB   #$2A
  3901  24 F9             BCC    L_38FC
  3903  C1 20             CMPB   #$20
  3905  25 F5             BCS    L_38FC
  3907  E6 C8 15          LDB    <21,U
  390A  27 06             BEQ    L_3912
  390C  C6 03             LDB    #$03
  390E  F7 62 B9          STB    >$62B9
  3911  5F                CLRB
L_3912:
  3912  E7 C4             STB    ,U
  3914  E7 43             STB    3,U
  3916  86 03             LDA    #$03
  3918  B7 60 82          STA    >SndBoom
  391B  35 10             PULS   X
  391D  F6 63 48          LDB    >$6348
  3920  10 26 FC A1       LBNE   L_35C5
  3924  5C                INCB
  3925  F7 63 48          STB    >$6348
  3928  7E 35 C5          JMP    >L_35C5

; =====================================================================
; SUB_392B (26 instructions)
; Uses:  $65A0 $69B8
; Calls: RST_RetIfNotScreen SUB_3961 SUB_39C8
; =====================================================================
SUB_392B:
  392B  C6 02             LDB    #$02
  392D  9D 64             JSR    <RST_RetIfNotScreen
  392F  8D 30             BSR    SUB_3961
  3931  BD 39 C8          JSR    >SUB_39C8
  3934  CE 65 A0          LDU    #$65A0
  3937  86 06             LDA    #$06
  3939  97 02             STA    <$02
  393B  8E 69 B8          LDX    #$69B8
L_393E:
  393E  E6 C4             LDB    ,U
  3940  27 1B             BEQ    L_395D
  3942  E6 43             LDB    3,U
  3944  C4 FE             ANDB   #$FE
  3946  E7 80             STB    ,X+
  3948  E6 47             LDB    7,U
  394A  E7 81             STB    ,X++
  394C  E6 45             LDB    5,U
  394E  E7 80             STB    ,X+
L_3950:
  3950  D7 01             STB    <$01
  3952  1F 20             TFR    Y,D
  3954  33 CB             LEAU   D,U
  3956  D6 01             LDB    <$01
  3958  0A 02             DEC    <$02
  395A  26 E2             BNE    L_393E
  395C  39                RTS
L_395D:
  395D  30 04             LEAX   4,X
  395F  20 EF             BRA    L_3950

; =====================================================================
; SUB_3961 (48 instructions)
; Uses:  $639B $639A $65A0 $62A3 $62A6
; Calls: UpdateRandom
; =====================================================================
SUB_3961:
  3961  8E 63 9B          LDX    #$639B
  3964  E6 84             LDB    ,X
  3966  26 5D             BNE    L_39C5
  3968  F6 63 9A          LDB    >$639A
  396B  27 5A             BEQ    L_39C7
  396D  86 06             LDA    #$06
  396F  97 02             STA    <$02
  3971  10 8E 00 10       LDY    #$0010
  3975  CE 65 A0          LDU    #$65A0
L_3978:
  3978  A6 C4             LDA    ,U
  397A  84 01             ANDA   #$01
  397C  27 08             BEQ    L_3986
  397E  33 C8 10          LEAU   <16,U
  3981  0A 02             DEC    <$02
  3983  26 F3             BNE    L_3978
  3985  39                RTS
L_3986:
  3986  9D FC             JSR    <UpdateRandom
  3988  C1 60             CMPB   #$60
  398A  86 7C             LDA    #$7C
  398C  A7 45             STA    5,U
  398E  25 06             BCS    L_3996
  3990  F6 62 A3          LDB    >$62A3
  3993  5A                DECB
  3994  26 14             BNE    L_39AA
L_3996:
  3996  86 CC             LDA    #$CC
  3998  A7 45             STA    5,U
  399A  F6 62 A6          LDB    >$62A6
  399D  59                ROLB
L_399E:
  399E  86 07             LDA    #$07
  39A0  A7 43             STA    3,U
  39A2  24 0C             BCC    L_39B0
  39A4  86 F8             LDA    #$F8
  39A6  A7 43             STA    3,U
  39A8  20 06             BRA    L_39B0
L_39AA:
  39AA  9D FC             JSR    <UpdateRandom
  39AC  C1 68             CMPB   #$68
  39AE  20 EE             BRA    L_399E
L_39B0:
  39B0  CC 01 4B          LDD    #$014B
  39B3  A7 C4             STA    ,U
  39B5  E7 47             STB    7,U
  39B7  CC 08 03          LDD    #$0803
  39BA  ED 49             STD    9,U
  39BC  C6 7C             LDB    #$7C
  39BE  F7 63 9B          STB    >$639B
  39C1  5F                CLRB
  39C2  F7 63 9A          STB    >$639A
L_39C5:
  39C5  6A 84             DEC    ,X
L_39C7:
  39C7  39                RTS

; =====================================================================
; SUB_39C8 (43 instructions)
; Uses:  $65A0 $63A6 $63A5 $63A4 $69B8
; =====================================================================
SUB_39C8:
  39C8  CE 65 A0          LDU    #$65A0
  39CB  10 8E 00 10       LDY    #$0010
  39CF  86 06             LDA    #$06
  39D1  97 02             STA    <$02
L_39D3:
  39D3  A6 C4             LDA    ,U
  39D5  84 01             ANDA   #$01
  39D7  27 17             BEQ    L_39F0
  39D9  E6 43             LDB    3,U
  39DB  D7 06             STB    <$06
  39DD  CB 07             ADDB   #$07
  39DF  C1 0E             CMPB   #$0E
  39E1  25 29             BCS    L_3A0C
  39E3  E6 45             LDB    5,U
  39E5  C1 7C             CMPB   #$7C
  39E7  27 0F             BEQ    L_39F8
  39E9  F6 63 A6          LDB    >$63A6
  39EC  DB 06             ADDB   <$06
  39EE  E7 43             STB    3,U
L_39F0:
  39F0  33 C8 10          LEAU   <16,U
  39F3  0A 02             DEC    <$02
  39F5  26 DC             BNE    L_39D3
  39F7  39                RTS
L_39F8:
  39F8  D6 06             LDB    <$06
  39FA  C1 80             CMPB   #$80
  39FC  27 0E             BEQ    L_3A0C
  39FE  F6 63 A5          LDB    >$63A5
  3A01  24 03             BCC    L_3A06
  3A03  F6 63 A4          LDB    >$63A4
L_3A06:
  3A06  DB 06             ADDB   <$06
  3A08  E7 43             STB    3,U
  3A0A  20 E4             BRA    L_39F0
L_3A0C:
  3A0C  8E 69 B8          LDX    #$69B8
  3A0F  C6 06             LDB    #$06
  3A11  D0 02             SUBB   <$02
L_3A13:
  3A13  27 05             BEQ    L_3A1A
  3A15  30 04             LEAX   4,X
  3A17  5A                DECB
  3A18  20 F9             BRA    L_3A13
L_3A1A:
  3A1A  5F                CLRB
  3A1B  E7 C4             STB    ,U
  3A1D  E7 43             STB    3,U
  3A1F  E7 84             STB    ,X
  3A21  20 CD             BRA    L_39F0

; =====================================================================
; SUB_3A23 (7 instructions)
; Calls: RST_RetIfNotScreen SUB_3A32 SUB_3A62 SUB_3AAD SUB_3F2A
; =====================================================================
SUB_3A23:
  3A23  C6 02             LDB    #$02
  3A25  9D 64             JSR    <RST_RetIfNotScreen
  3A27  8D 09             BSR    SUB_3A32
  3A29  8D 37             BSR    SUB_3A62
  3A2B  BD 3A AD          JSR    >SUB_3AAD
  3A2E  BD 3F 2A          JSR    >SUB_3F2A
  3A31  39                RTS

; =====================================================================
; SUB_3A32 (20 instructions)
; Uses:  FrameCounter $62A0 $62A1 $63A3 $69E4
; Calls: SUB_3B1C SUB_3B2A SUB_3ADB
; =====================================================================
SUB_3A32:
  3A32  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  3A35  56                RORB
  3A36  25 0E             BCS    L_3A46
  3A38  8E 62 A0          LDX    #$62A0
  3A3B  6A 84             DEC    ,X
  3A3D  26 07             BNE    L_3A46
  3A3F  86 80             LDA    #$80
  3A41  A7 80             STA    ,X+
  3A43  BD 3B 1C          JSR    >SUB_3B1C
L_3A46:
  3A46  8E 62 A1          LDX    #$62A1
  3A49  BD 3B 2A          JSR    >SUB_3B2A
  3A4C  F7 63 A3          STB    >$63A3
  3A4F  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  3A52  C4 1F             ANDB   #$1F
  3A54  C1 01             CMPB   #$01
  3A56  26 09             BNE    L_3A61
  3A58  10 8E 69 E4       LDY    #$69E4
  3A5C  1E 21             EXG    Y,X
  3A5E  BD 3A DB          JSR    >SUB_3ADB
L_3A61:
  3A61  39                RTS

; =====================================================================
; SUB_3A62 (33 instructions)
; Uses:  $62A3 MarioY FrameCounter $63A5 $63A4 $69EC $69ED
; Calls: SUB_3B1C SUB_3B2A SUB_3ADB
; =====================================================================
SUB_3A62:
  3A62  8E 62 A3          LDX    #$62A3
  3A65  F6 62 05          LDB    >MarioY
  3A68  C1 C0             CMPB   #$C0
  3A6A  25 37             BCS    L_3AA3
  3A6C  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  3A6F  56                RORB
  3A70  25 0B             BCS    L_3A7D
  3A72  6A 82             DEC    ,-X
  3A74  26 07             BNE    L_3A7D
  3A76  86 C0             LDA    #$C0
  3A78  A7 80             STA    ,X+
  3A7A  BD 3B 1C          JSR    >SUB_3B1C
L_3A7D:
  3A7D  8E 62 A3          LDX    #$62A3
  3A80  BD 3B 2A          JSR    >SUB_3B2A
  3A83  F7 63 A5          STB    >$63A5
  3A86  50                NEGB
  3A87  F7 63 A4          STB    >$63A4
  3A8A  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  3A8D  C4 1F             ANDB   #$1F
  3A8F  26 11             BNE    L_3AA2
  3A91  30 1F             LEAX   -1,X
  3A93  10 8E 69 EC       LDY    #$69EC
  3A97  1E 21             EXG    Y,X
  3A99  8D 40             BSR    SUB_3ADB
  3A9B  C4 7F             ANDB   #$7F
  3A9D  8E 69 ED          LDX    #$69ED
  3AA0  E7 84             STB    ,X
L_3AA2:
  3AA2  39                RTS
L_3AA3:
  3AA3  A6 84             LDA    ,X
  3AA5  2B D6             BMI    L_3A7D
  3AA7  86 FF             LDA    #$FF
  3AA9  A7 84             STA    ,X
  3AAB  20 D0             BRA    L_3A7D

; =====================================================================
; SUB_3AAD (20 instructions)
; Uses:  FrameCounter $62A5 $62A6 $63A6 $69F4
; Calls: SUB_3B1C SUB_3B2A SUB_3ADB
; =====================================================================
SUB_3AAD:
  3AAD  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  3AB0  56                RORB
  3AB1  25 0D             BCS    L_3AC0
  3AB3  8E 62 A5          LDX    #$62A5
  3AB6  6A 84             DEC    ,X
  3AB8  26 06             BNE    L_3AC0
  3ABA  86 FF             LDA    #$FF
  3ABC  A7 80             STA    ,X+
  3ABE  8D 5C             BSR    SUB_3B1C
L_3AC0:
  3AC0  8E 62 A6          LDX    #$62A6
  3AC3  BD 3B 2A          JSR    >SUB_3B2A
  3AC6  F7 63 A6          STB    >$63A6
  3AC9  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  3ACC  C4 1F             ANDB   #$1F
  3ACE  C1 02             CMPB   #$02
  3AD0  26 08             BNE    L_3ADA
  3AD2  10 8E 69 F4       LDY    #$69F4
  3AD6  1E 21             EXG    Y,X
  3AD8  8D 01             BSR    SUB_3ADB
L_3ADA:
  3ADA  39                RTS

; =====================================================================
; SUB_3ADB (36 instructions)
; =====================================================================
SUB_3ADB:
  3ADB  30 01             LEAX   1,X
  3ADD  E6 A4             LDB    ,Y
  3ADF  59                ROLB
  3AE0  25 1D             BCS    L_3AFF
  3AE2  E6 84             LDB    ,X
  3AE4  5C                INCB
  3AE5  C1 53             CMPB   #$53
  3AE7  26 02             BNE    L_3AEB
  3AE9  C6 50             LDB    #$50
L_3AEB:
  3AEB  E7 84             STB    ,X
  3AED  1F 10             TFR    X,D
  3AEF  CB 04             ADDB   #$04
  3AF1  1F 01             TFR    D,X
  3AF3  E6 84             LDB    ,X
  3AF5  5A                DECB
  3AF6  C1 CF             CMPB   #$CF
  3AF8  26 02             BNE    L_3AFC
  3AFA  C6 D2             LDB    #$D2
L_3AFC:
  3AFC  E7 84             STB    ,X
  3AFE  39                RTS
L_3AFF:
  3AFF  E6 84             LDB    ,X
  3B01  5A                DECB
  3B02  C1 4F             CMPB   #$4F
  3B04  26 02             BNE    L_3B08
  3B06  C6 52             LDB    #$52
L_3B08:
  3B08  E7 84             STB    ,X
  3B0A  1F 10             TFR    X,D
  3B0C  CB 04             ADDB   #$04
  3B0E  1F 01             TFR    D,X
  3B10  E6 84             LDB    ,X
  3B12  5C                INCB
  3B13  C1 D3             CMPB   #$D3
  3B15  26 02             BNE    L_3B19
  3B17  C6 D0             LDB    #$D0
L_3B19:
  3B19  E7 84             STB    ,X
  3B1B  39                RTS

; =====================================================================
; SUB_3B1C (8 instructions)
; =====================================================================
SUB_3B1C:
  3B1C  A6 84             LDA    ,X
  3B1E  2A 05             BPL    L_3B25
  3B20  86 02             LDA    #$02
  3B22  A7 84             STA    ,X
  3B24  39                RTS
L_3B25:
  3B25  86 FE             LDA    #$FE
  3B27  A7 84             STA    ,X
  3B29  39                RTS

; =====================================================================
; SUB_3B2A (9 instructions)
; Uses:  FrameCounter
; =====================================================================
SUB_3B2A:
  3B2A  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  3B2D  C4 01             ANDB   #$01
  3B2F  27 0A             BEQ    L_3B3B
  3B31  C6 FF             LDB    #$FF
  3B33  A6 84             LDA    ,X
  3B35  2B 02             BMI    L_3B39
  3B37  C6 01             LDB    #$01
L_3B39:
  3B39  E7 84             STB    ,X
L_3B3B:
  3B3B  39                RTS

; =====================================================================
; SUB_3B3C (33 instructions)
; Uses:  MarioY FrameCounter Level $6958 $6600
; Calls: RST_RetIfNotScreen SUB_3B82 SUB_3BCE SUB_3C0A
; =====================================================================
SUB_3B3C:
  3B3C  C6 04             LDB    #$04
  3B3E  9D 64             JSR    <RST_RetIfNotScreen
  3B40  F6 62 05          LDB    >MarioY
  3B43  C1 F0             CMPB   #$F0
  3B45  24 70             BCC    L_3BB7
  3B47  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  3B4A  B6 62 29          LDA    >Level                  ; level number
  3B4D  4A                DECA
  3B4E  26 09             BNE    L_3B59
  3B50  C4 03             ANDB   #$03
  3B52  C1 01             CMPB   #$01
  3B54  27 06             BEQ    L_3B5C
  3B56  25 07             BCS    L_3B5F
  3B58  39                RTS
L_3B59:
  3B59  56                RORB
  3B5A  25 03             BCS    L_3B5F
L_3B5C:
  3B5C  8D 24             BSR    SUB_3B82
  3B5E  39                RTS
L_3B5F:
  3B5F  BD 3B CE          JSR    >SUB_3BCE
  3B62  BD 3C 0A          JSR    >SUB_3C0A
  3B65  86 06             LDA    #$06
  3B67  10 8E 00 10       LDY    #$0010
  3B6B  8E 69 58          LDX    #$6958
  3B6E  CE 66 00          LDU    #$6600
L_3B71:
  3B71  E6 43             LDB    3,U
  3B73  E7 84             STB    ,X
  3B75  30 03             LEAX   3,X
  3B77  E6 45             LDB    5,U
  3B79  E7 80             STB    ,X+
  3B7B  33 C8 10          LEAU   <16,U
  3B7E  4A                DECA
  3B7F  26 F0             BNE    L_3B71
  3B81  39                RTS

; =====================================================================
; SUB_3B82 (36 instructions)
; Uses:  $6398 $6216 MarioX $6221 MarioY $694F MarioAlive
; =====================================================================
SUB_3B82:
  3B82  F6 63 98          LDB    >$6398
  3B85  27 2F             BEQ    L_3BB6
  3B87  F6 62 16          LDB    >$6216
  3B8A  26 2A             BNE    L_3BB6
  3B8C  F6 62 03          LDB    >MarioX
  3B8F  C1 2C             CMPB   #$2C
  3B91  25 0C             BCS    L_3B9F
  3B93  C1 43             CMPB   #$43
  3B95  25 11             BCS    L_3BA8
  3B97  C1 6C             CMPB   #$6C
  3B99  25 04             BCS    L_3B9F
  3B9B  C1 83             CMPB   #$83
  3B9D  25 20             BCS    L_3BBF
L_3B9F:
  3B9F  5F                CLRB
  3BA0  F7 63 98          STB    >$6398
  3BA3  5C                INCB
  3BA4  F7 62 21          STB    >$6221
  3BA7  39                RTS
L_3BA8:
  3BA8  F6 62 05          LDB    >MarioY
  3BAB  C1 71             CMPB   #$71
  3BAD  25 08             BCS    L_3BB7
  3BAF  5A                DECB
  3BB0  F7 62 05          STB    >MarioY
  3BB3  F7 69 4F          STB    >$694F
L_3BB6:
  3BB6  39                RTS
L_3BB7:
  3BB7  5F                CLRB
  3BB8  F7 62 00          STB    >MarioAlive             ; bit0 = Mario alive
  3BBB  F7 63 98          STB    >$6398
  3BBE  39                RTS
L_3BBF:
  3BBF  F6 62 05          LDB    >MarioY
  3BC2  C1 E8             CMPB   #$E8
  3BC4  24 F1             BCC    L_3BB7
  3BC6  5C                INCB
  3BC7  F7 62 05          STB    >MarioY
  3BCA  F7 69 4F          STB    >$694F
  3BCD  39                RTS

; =====================================================================
; SUB_3BCE (29 instructions)
; Uses:  $6600 $7704
; =====================================================================
SUB_3BCE:
  3BCE  86 06             LDA    #$06
  3BD0  97 02             STA    <$02
  3BD2  10 8E 00 10       LDY    #$0010
  3BD6  CE 66 00          LDU    #$6600
L_3BD9:
  3BD9  A6 C4             LDA    ,U
  3BDB  84 01             ANDA   #$01
  3BDD  27 16             BEQ    L_3BF5
  3BDF  A6 4D             LDA    13,U
  3BE1  84 08             ANDA   #$08
  3BE3  27 18             BEQ    L_3BFD
  3BE5  E6 45             LDB    5,U
  3BE7  5A                DECB
  3BE8  E7 45             STB    5,U
  3BEA  C1 60             CMPB   #$60
  3BEC  26 07             BNE    L_3BF5
  3BEE  CC 77 04          LDD    #$7704
  3BF1  A7 43             STA    3,U
  3BF3  E7 4D             STB    13,U
L_3BF5:
  3BF5  33 C8 10          LEAU   <16,U
  3BF8  0A 02             DEC    <$02
  3BFA  26 DD             BNE    L_3BD9
  3BFC  39                RTS
L_3BFD:
  3BFD  E6 45             LDB    5,U
  3BFF  5C                INCB
  3C00  E7 45             STB    5,U
  3C02  C1 F8             CMPB   #$F8
  3C04  26 EF             BNE    L_3BF5
  3C06  6F C4             CLR    ,U
  3C08  20 EB             BRA    L_3BF5

; =====================================================================
; SUB_3C0A (23 instructions)
; Uses:  $62A7 $6600
; =====================================================================
SUB_3C0A:
  3C0A  8E 62 A7          LDX    #$62A7
  3C0D  E6 84             LDB    ,X
  3C0F  26 27             BNE    L_3C38
  3C11  86 06             LDA    #$06
  3C13  97 02             STA    <$02
  3C15  CE 66 00          LDU    #$6600
L_3C18:
  3C18  A6 C4             LDA    ,U
  3C1A  84 01             ANDA   #$01
  3C1C  27 08             BEQ    L_3C26
  3C1E  33 C8 10          LEAU   <16,U
  3C21  0A 02             DEC    <$02
  3C23  26 F3             BNE    L_3C18
  3C25  39                RTS
L_3C26:
  3C26  CC 01 37          LDD    #$0137
  3C29  A7 C4             STA    ,U
  3C2B  E7 43             STB    3,U
  3C2D  CC F8 08          LDD    #$F808
  3C30  A7 45             STA    5,U
  3C32  E7 4D             STB    13,U
  3C34  86 34             LDA    #$34
  3C36  A7 84             STA    ,X
L_3C38:
  3C38  6A 84             DEC    ,X
  3C3A  39                RTS

; =====================================================================
; SUB_3C3B (11 instructions)
; Uses:  MarioAlive MarioY
; Calls: SUB_3CAE
; =====================================================================
SUB_3C3B:
  3C3B  8E 62 00          LDX    #MarioAlive
  3C3E  9F 0A             STX    <$0A
  3C40  F6 62 05          LDB    >MarioY
  3C43  D7 03             STB    <$03
  3C45  8E 04 07          LDX    #$0407
  3C48  8D 64             BSR    SUB_3CAE
  3C4A  5D                TSTB
  3C4B  27 04             BEQ    L_3C51
  3C4D  5A                DECB
  3C4E  F7 62 00          STB    >MarioAlive             ; bit0 = Mario alive
L_3C51:
  3C51  39                RTS

; =====================================================================
; SUB_3C52 (27 instructions)
; Uses:  $6680 $6350 $63B9 $6354 $6353 $6351
; Calls: SUB_3CAE
; =====================================================================
SUB_3C52:
  3C52  86 02             LDA    #$02
  3C54  97 02             STA    <$02
  3C56  10 8E 66 80       LDY    #$6680
L_3C5A:
  3C5A  A6 21             LDA    1,Y
  3C5C  84 01             ANDA   #$01
  3C5E  26 0F             BNE    L_3C6F
  3C60  31 A8 10          LEAY   <16,Y
  3C63  0A 02             DEC    <$02
  3C65  26 F3             BNE    L_3C5A
  3C67  10 9F 0A          STY    <$0A
  3C6A  10 8E 00 10       LDY    #$0010
  3C6E  39                RTS
L_3C6F:
  3C6F  A6 25             LDA    5,Y
  3C71  97 03             STA    <$03
  3C73  AE 29             LDX    9,Y
  3C75  10 9F 0A          STY    <$0A
  3C78  8D 34             BSR    SUB_3CAE
  3C7A  5D                TSTB
  3C7B  27 13             BEQ    L_3C90
  3C7D  F7 63 50          STB    >$6350
  3C80  F6 63 B9          LDB    >$63B9
  3C83  D0 02             SUBB   <$02
  3C85  F7 63 54          STB    >$6354
  3C88  D6 05             LDB    <$05
  3C8A  F7 63 53          STB    >$6353
  3C8D  FF 63 51          STU    >$6351
L_3C90:
  3C90  39                RTS

; =====================================================================
; CheckJumpOver (12 instructions)
; Uses:  MarioAlive MarioY InputState
; Calls: JumpOverCheck
; =====================================================================
CheckJumpOver:
  3C91  8E 62 00          LDX    #MarioAlive
  3C94  9F 0A             STX    <$0A
  3C96  F6 62 05          LDB    >MarioY
  3C99  CB 0C             ADDB   #$0C
  3C9B  D7 03             STB    <$03
  3C9D  8E 05 08          LDX    #$0508
  3CA0  F6 60 10          LDB    >InputState             ; joystick+jump, bit7 = jump edge
  3CA3  C4 03             ANDB   #$03
  3CA5  27 03             BEQ    L_3CAA
  3CA7  8E 13 08          LDX    #$1308
L_3CAA:
  3CAA  BD 52 9D          JSR    >JumpOverCheck
  3CAD  39                RTS

; =====================================================================
; SUB_3CAE (65 instructions)
; Uses:  ScreenNum $63B9 Barrels Fireballs $66A0 $65A0 $6500
; Calls: RST_JumpTable SUB_3D56
; =====================================================================
SUB_3CAE:
  3CAE  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  3CB1  34 10             PSHS   X
  3CB3  9D 47             JSR    <RST_JumpTable
TBL_StageObjects:
  3CB5  11 14             FDB    ColdStart
  3CB7  3C C1             FDB    L_3CC1
  3CB9  3C F3             FDB    L_3CF3
  3CBB  3D 23             FDB    L_3D23
  3CBD  3D 44             FDB    L_3D44
  3CBF  11 14             FDB    ColdStart
L_3CC1:
  3CC1  35 10             PULS   X
  3CC3  CC 20 0A          LDD    #$200A
  3CC6  D7 02             STB    <$02
  3CC8  F7 63 B9          STB    >$63B9
  3CCB  97 05             STA    <$05
  3CCD  CE 67 00          LDU    #Barrels
  3CD0  BD 3D 56          JSR    >SUB_3D56
  3CD3  CC 20 05          LDD    #$2005
  3CD6  D7 02             STB    <$02
  3CD8  F7 63 B9          STB    >$63B9
  3CDB  97 05             STA    <$05
  3CDD  CE 64 00          LDU    #Fireballs
  3CE0  BD 3D 56          JSR    >SUB_3D56
  3CE3  CC 00 01          LDD    #$0001
  3CE6  D7 02             STB    <$02
  3CE8  F7 63 B9          STB    >$63B9
  3CEB  97 05             STA    <$05
  3CED  CE 66 A0          LDU    #$66A0
  3CF0  8D 64             BSR    SUB_3D56
  3CF2  39                RTS
L_3CF3:
  3CF3  35 10             PULS   X
  3CF5  CC 20 05          LDD    #$2005
  3CF8  D7 02             STB    <$02
  3CFA  F7 63 B9          STB    >$63B9
  3CFD  97 05             STA    <$05
  3CFF  CE 64 00          LDU    #Fireballs
  3D02  8D 52             BSR    SUB_3D56
  3D04  CC 10 06          LDD    #$1006
  3D07  D7 02             STB    <$02
  3D09  F7 63 B9          STB    >$63B9
  3D0C  97 05             STA    <$05
  3D0E  CE 65 A0          LDU    #$65A0
  3D11  8D 43             BSR    SUB_3D56
  3D13  CC 00 01          LDD    #$0001
  3D16  D7 02             STB    <$02
  3D18  F7 63 B9          STB    >$63B9
  3D1B  97 05             STA    <$05
  3D1D  CE 66 A0          LDU    #$66A0
  3D20  8D 34             BSR    SUB_3D56
  3D22  39                RTS
L_3D23:
  3D23  35 10             PULS   X
  3D25  CC 20 05          LDD    #$2005
  3D28  D7 02             STB    <$02
  3D2A  F7 63 B9          STB    >$63B9
  3D2D  97 05             STA    <$05
  3D2F  CE 64 00          LDU    #Fireballs
  3D32  8D 22             BSR    SUB_3D56
  3D34  CC 10 0A          LDD    #$100A
  3D37  D7 02             STB    <$02
  3D39  F7 63 B9          STB    >$63B9
  3D3C  97 05             STA    <$05
  3D3E  CE 65 00          LDU    #$6500
  3D41  8D 13             BSR    SUB_3D56
  3D43  39                RTS
L_3D44:
  3D44  35 10             PULS   X
  3D46  CC 20 07          LDD    #$2007
  3D49  D7 02             STB    <$02
  3D4B  F7 63 B9          STB    >$63B9
  3D4E  97 05             STA    <$05
  3D50  CE 64 00          LDU    #Fireballs
  3D53  8D 01             BSR    SUB_3D56
  3D55  39                RTS

; =====================================================================
; SUB_3D56 (42 instructions)
; =====================================================================
SUB_3D56:
  3D56  34 40             PSHS   U
  3D58  9F 06             STX    <$06
  3D5A  9E 0A             LDX    <$0A
L_3D5C:
  3D5C  A6 C4             LDA    ,U
  3D5E  84 01             ANDA   #$01
  3D60  27 2D             BEQ    L_3D8F
  3D62  D6 03             LDB    <$03
  3D64  E0 45             SUBB   5,U
  3D66  24 01             BCC    L_3D69
  3D68  50                NEGB
L_3D69:
  3D69  5C                INCB
  3D6A  D0 07             SUBB   <$07
  3D6C  25 04             BCS    L_3D72
  3D6E  E0 4A             SUBB   10,U
  3D70  24 1D             BCC    L_3D8F
L_3D72:
  3D72  E6 03             LDB    3,X
  3D74  E0 43             SUBB   3,U
  3D76  24 01             BCC    L_3D79
  3D78  50                NEGB
L_3D79:
  3D79  D0 06             SUBB   <$06
  3D7B  25 04             BCS    L_3D81
  3D7D  E0 49             SUBB   9,U
  3D7F  24 0E             BCC    L_3D8F
L_3D81:
  3D81  4F                CLRA
  3D82  D6 05             LDB    <$05
  3D84  1F 02             TFR    D,Y
  3D86  C6 01             LDB    #$01
  3D88  35 40             PULS   U
  3D8A  32 62             LEAS   2,S
  3D8C  9E 06             LDX    <$06
  3D8E  39                RTS
L_3D8F:
  3D8F  96 05             LDA    <$05
  3D91  33 C6             LEAU   A,U
  3D93  0A 02             DEC    <$02
  3D95  26 C5             BNE    L_3D5C
  3D97  4F                CLRA
  3D98  D6 05             LDB    <$05
  3D9A  1F 02             TFR    D,Y
  3D9C  5F                CLRB
  3D9D  35 40             PULS   U
  3D9F  9E 06             LDX    <$06
  3DA1  39                RTS

; =====================================================================
; SUB_3DA2 (19 instructions)
; Uses:  $6218 SndFx5
; Calls: RST_RetIfNotScreen SUB_3DC5
; =====================================================================
SUB_3DA2:
  3DA2  C6 0B             LDB    #$0B
  3DA4  9D 64             JSR    <RST_RetIfNotScreen
  3DA6  8D 1D             BSR    SUB_3DC5
  3DA8  F7 62 18          STB    >$6218
  3DAB  1F 98             TFR    B,A
  3DAD  47                ASRA
  3DAE  56                RORB
  3DAF  47                ASRA
  3DB0  56                RORB
  3DB1  F7 60 85          STB    >SndFx5
  3DB4  D6 02             LDB    <$02
  3DB6  27 0C             BEQ    L_3DC4
  3DB8  C1 01             CMPB   #$01
  3DBA  27 05             BEQ    L_3DC1
  3DBC  86 01             LDA    #$01
  3DBE  A7 41             STA    1,U
  3DC0  39                RTS
L_3DC1:
  3DC1  E7 C8 11          STB    <17,U
L_3DC4:
  3DC4  39                RTS

; =====================================================================
; SUB_3DC5 (11 instructions)
; Uses:  MarioAlive MarioY $6680
; Calls: SUB_3D56
; =====================================================================
SUB_3DC5:
  3DC5  8E 62 00          LDX    #MarioAlive
  3DC8  9F 0A             STX    <$0A
  3DCA  F6 62 05          LDB    >MarioY
  3DCD  D7 03             STB    <$03
  3DCF  8E 04 08          LDX    #$0408
  3DD2  CC 02 10          LDD    #$0210
  3DD5  97 02             STA    <$02
  3DD7  D7 05             STB    <$05
  3DD9  CE 66 80          LDU    #$6680
  3DDC  BD 3D 56          JSR    >SUB_3D56
  3DDF  39                RTS

; =====================================================================
; SUB_3DE0 (19 instructions)
; Uses:  $63C8
; Calls: SUB_443F
; =====================================================================
SUB_3DE0:
  3DE0  BE 63 C8          LDX    >$63C8
  3DE3  1F 10             TFR    X,D
  3DE5  CB 0E             ADDB   #$0E
  3DE7  1F 01             TFR    D,X
  3DE9  A6 80             LDA    ,X+
  3DEB  E6 84             LDB    ,X
  3DED  CB 0C             ADDB   #$0C
  3DEF  1F 01             TFR    D,X
  3DF1  BD 44 3F          JSR    >SUB_443F
  3DF4  E6 84             LDB    ,X
  3DF6  C1 B0             CMPB   #$B0
  3DF8  25 08             BCS    L_3E02
  3DFA  C4 0F             ANDB   #$0F
  3DFC  C1 08             CMPB   #$08
  3DFE  24 02             BCC    L_3E02
  3E00  5F                CLRB
  3E01  39                RTS
L_3E02:
  3E02  C6 01             LDB    #$01
  3E04  39                RTS

; =====================================================================
; SUB_3E05 (56 instructions)
; Uses:  MarioAlive MarioY $620C $6398 MarioX $6210 $694C
; Calls: RST_RetIfNotScreen SUB_3E7C
; =====================================================================
SUB_3E05:
  3E05  C6 04             LDB    #$04
  3E07  9D 64             JSR    <RST_RetIfNotScreen
  3E09  8E 62 00          LDX    #MarioAlive
  3E0C  9F 0A             STX    <$0A
  3E0E  F6 62 05          LDB    >MarioY
  3E11  D7 03             STB    <$03
  3E13  8E 04 08          LDX    #$0408
  3E16  BD 3E 7C          JSR    >SUB_3E7C
  3E19  5D                TSTB
  3E1A  27 5D             BEQ    L_3E79
  3E1C  C6 06             LDB    #$06
  3E1E  D0 02             SUBB   <$02
L_3E20:
  3E20  27 06             BEQ    L_3E28
  3E22  33 C8 10          LEAU   <16,U
  3E25  5A                DECB
  3E26  20 F8             BRA    L_3E20
L_3E28:
  3E28  A6 45             LDA    5,U
  3E2A  80 04             SUBA   #$04
  3E2C  1F 02             TFR    D,Y
  3E2E  97 04             STA    <$04
  3E30  F6 62 0C          LDB    >$620C
  3E33  CB 05             ADDB   #$05
  3E35  D1 04             CMPB   <$04
  3E37  24 11             BCC    L_3E4A
  3E39  D6 04             LDB    <$04
  3E3B  C0 08             SUBB   #$08
  3E3D  F7 62 05          STB    >MarioY
  3E40  C6 01             LDB    #$01
  3E42  D7 02             STB    <$02
  3E44  F7 63 98          STB    >$6398
  3E47  32 62             LEAS   2,S
  3E49  39                RTS
L_3E4A:
  3E4A  F6 62 0C          LDB    >$620C
  3E4D  C0 0E             SUBB   #$0E
  3E4F  D1 04             CMPB   <$04
  3E51  24 21             BCC    L_3E74
  3E53  F6 62 03          LDB    >MarioX
  3E56  B6 62 10          LDA    >$6210
  3E59  27 06             BEQ    L_3E61
  3E5B  CA 07             ORB    #$07
  3E5D  C0 04             SUBB   #$04
  3E5F  20 06             BRA    L_3E67
L_3E61:
  3E61  C0 08             SUBB   #$08
  3E63  CA 07             ORB    #$07
  3E65  CB 04             ADDB   #$04
L_3E67:
  3E67  F7 62 03          STB    >MarioX
  3E6A  F7 69 4C          STB    >$694C
  3E6D  C6 01             LDB    #$01
  3E6F  0F 02             CLR    <$02
  3E71  32 62             LEAS   2,S
  3E73  39                RTS
L_3E74:
  3E74  5F                CLRB
  3E75  F7 62 00          STB    >MarioAlive             ; bit0 = Mario alive
  3E78  39                RTS
L_3E79:
  3E79  D7 02             STB    <$02
  3E7B  39                RTS

; =====================================================================
; SUB_3E7C (6 instructions)
; Uses:  $6600
; Calls: SUB_3D56
; =====================================================================
SUB_3E7C:
  3E7C  CC 06 10          LDD    #$0610
  3E7F  97 02             STA    <$02
  3E81  D7 05             STB    <$05
  3E83  CE 66 00          LDU    #$6600
  3E86  BD 3D 56          JSR    >SUB_3D56
  3E89  39                RTS

; =====================================================================
; SUB_3E8A (43 instructions)
; Calls: SUB_443F
; =====================================================================
SUB_3E8A:
  3E8A  A6 43             LDA    3,U
  3E8C  E6 45             LDB    5,U
  3E8E  CB 04             ADDB   #$04
  3E90  1F 01             TFR    D,X
  3E92  34 10             PSHS   X
  3E94  BD 44 3F          JSR    >SUB_443F
  3E97  35 20             PULS   Y
  3E99  E6 84             LDB    ,X
  3E9B  C1 B0             CMPB   #$B0
  3E9D  25 35             BCS    L_3ED4
  3E9F  C4 0F             ANDB   #$0F
  3EA1  C1 08             CMPB   #$08
  3EA3  24 2F             BCC    L_3ED4
  3EA5  E6 84             LDB    ,X
  3EA7  C1 C0             CMPB   #$C0
  3EA9  27 29             BEQ    L_3ED4
  3EAB  25 11             BCS    L_3EBE
  3EAD  C1 D0             CMPB   #$D0
  3EAF  25 11             BCS    L_3EC2
  3EB1  C1 E0             CMPB   #$E0
  3EB3  25 04             BCS    L_3EB9
  3EB5  C1 F0             CMPB   #$F0
  3EB7  25 09             BCS    L_3EC2
L_3EB9:
  3EB9  C4 0F             ANDB   #$0F
  3EBB  5A                DECB
  3EBC  20 08             BRA    L_3EC6
L_3EBE:
  3EBE  C6 FF             LDB    #$FF
  3EC0  20 04             BRA    L_3EC6
L_3EC2:
  3EC2  C4 0F             ANDB   #$0F
  3EC4  C0 09             SUBB   #$09
L_3EC6:
  3EC6  D7 03             STB    <$03
  3EC8  1F 20             TFR    Y,D
  3ECA  D7 05             STB    <$05
  3ECC  C4 F8             ANDB   #$F8
  3ECE  DB 03             ADDB   <$03
  3ED0  D1 05             CMPB   <$05
  3ED2  25 02             BCS    L_3ED6
L_3ED4:
  3ED4  5F                CLRB
  3ED5  39                RTS
L_3ED6:
  3ED6  C0 04             SUBB   #$04
  3ED8  E7 45             STB    5,U
  3EDA  C6 01             LDB    #$01
  3EDC  39                RTS

; =====================================================================
; SUB_3EDD (36 instructions)
; Uses:  $6215 $6216 $6398 MarioX MarioY $6221
; Calls: SUB_443F
; =====================================================================
SUB_3EDD:
  3EDD  F6 62 15          LDB    >$6215
  3EE0  26 47             BNE    L_3F29
  3EE2  F6 62 16          LDB    >$6216
  3EE5  26 42             BNE    L_3F29
  3EE7  F6 63 98          LDB    >$6398
  3EEA  C1 01             CMPB   #$01
  3EEC  27 3B             BEQ    L_3F29
  3EEE  B6 62 03          LDA    >MarioX
  3EF1  80 03             SUBA   #$03
  3EF3  F6 62 05          LDB    >MarioY
  3EF6  CB 0C             ADDB   #$0C
  3EF8  1F 01             TFR    D,X
  3EFA  34 10             PSHS   X
  3EFC  BD 44 3F          JSR    >SUB_443F
  3EFF  35 20             PULS   Y
  3F01  E6 84             LDB    ,X
  3F03  C1 B0             CMPB   #$B0
  3F05  25 07             BCS    L_3F0E
  3F07  C4 0F             ANDB   #$0F
  3F09  C1 08             CMPB   #$08
  3F0B  24 01             BCC    L_3F0E
  3F0D  39                RTS
L_3F0E:
  3F0E  1F 20             TFR    Y,D
  3F10  84 07             ANDA   #$07
  3F12  27 10             BEQ    L_3F24
  3F14  30 88 E0          LEAX   <-32,X
  3F17  E6 84             LDB    ,X
  3F19  C1 B0             CMPB   #$B0
  3F1B  25 07             BCS    L_3F24
  3F1D  C4 0F             ANDB   #$0F
  3F1F  C1 08             CMPB   #$08
  3F21  24 01             BCC    L_3F24
  3F23  39                RTS
L_3F24:
  3F24  C6 01             LDB    #$01
  3F26  F7 62 21          STB    >$6221
L_3F29:
  3F29  39                RTS

; =====================================================================
; SUB_3F2A (36 instructions)
; Uses:  MarioX MarioY $63A3 $63A6 $63A5 $63A4 $694C
; Calls: SUB_3864
; =====================================================================
SUB_3F2A:
  3F2A  F6 62 03          LDB    >MarioX
  3F2D  D7 02             STB    <$02
  3F2F  F6 62 05          LDB    >MarioY
  3F32  C1 50             CMPB   #$50
  3F34  27 09             BEQ    L_3F3F
  3F36  C1 78             CMPB   #$78
  3F38  27 0F             BEQ    L_3F49
  3F3A  C1 C8             CMPB   #$C8
  3F3C  27 06             BEQ    L_3F44
  3F3E  39                RTS
L_3F3F:
  3F3F  F6 63 A3          LDB    >$63A3
  3F42  20 11             BRA    L_3F55
L_3F44:
  3F44  F6 63 A6          LDB    >$63A6
  3F47  20 0C             BRA    L_3F55
L_3F49:
  3F49  D6 02             LDB    <$02
  3F4B  C1 80             CMPB   #$80
  3F4D  F6 63 A5          LDB    >$63A5
  3F50  24 03             BCC    L_3F55
  3F52  F6 63 A4          LDB    >$63A4
L_3F55:
  3F55  DB 02             ADDB   <$02
  3F57  F7 62 03          STB    >MarioX
  3F5A  F7 69 4C          STB    >$694C
  3F5D  BD 38 64          JSR    >SUB_3864
  3F60  8E 62 03          LDX    #MarioX
  3F63  0A 05             DEC    <$05
  3F65  27 08             BEQ    L_3F6F
  3F67  0A 04             DEC    <$04
  3F69  27 0A             BEQ    L_3F75
  3F6B  10 9E 04          LDY    <$04
  3F6E  39                RTS
L_3F6F:
  3F6F  6A 84             DEC    ,X
  3F71  10 9E 04          LDY    <$04
  3F74  39                RTS
L_3F75:
  3F75  6C 84             INC    ,X
  3F77  10 9E 04          LDY    <$04
  3F7A  39                RTS

; =====================================================================
; SUB_3F7B (6 instructions)
; Uses:  MarioAlive
; Calls: SUB_3F87 SUB_3E05
; =====================================================================
SUB_3F7B:
  3F7B  CE 62 00          LDU    #MarioAlive
  3F7E  8D 07             BSR    SUB_3F87
  3F80  BD 3E 05          JSR    >SUB_3E05
  3F83  5F                CLRB
  3F84  D7 02             STB    <$02
  3F86  39                RTS

; =====================================================================
; SUB_3F87 (52 instructions)
; Uses:  ScreenNum MarioX MarioY $6210 $694C
; Calls: SUB_3FF4
; =====================================================================
SUB_3F87:
  3F87  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  3F8A  5A                DECB
  3F8B  26 24             BNE    L_3FB1
  3F8D  B6 62 03          LDA    >MarioX
  3F90  F6 62 05          LDB    >MarioY
  3F93  CB 07             ADDB   #$07
  3F95  1F 01             TFR    D,X
  3F97  8D 5B             BSR    SUB_3FF4
  3F99  5D                TSTB
  3F9A  27 13             BEQ    L_3FAF
  3F9C  1F 20             TFR    Y,D
  3F9E  D0 03             SUBB   <$03
  3FA0  C1 04             CMPB   #$04
  3FA2  24 2C             BCC    L_3FD0
  3FA4  D6 03             LDB    <$03
  3FA6  C0 07             SUBB   #$07
  3FA8  F7 62 05          STB    >MarioY
  3FAB  C6 01             LDB    #$01
  3FAD  D7 02             STB    <$02
L_3FAF:
  3FAF  35 90             PULS   X,PC
L_3FB1:
  3FB1  B6 62 03          LDA    >MarioX
  3FB4  80 03             SUBA   #$03
  3FB6  F6 62 05          LDB    >MarioY
  3FB9  CB 07             ADDB   #$07
  3FBB  1F 01             TFR    D,X
  3FBD  8D 35             BSR    SUB_3FF4
  3FBF  C1 02             CMPB   #$02
  3FC1  27 12             BEQ    L_3FD5
  3FC3  1F 20             TFR    Y,D
  3FC5  8B 07             ADDA   #$07
  3FC7  1F 01             TFR    D,X
  3FC9  8D 29             BSR    SUB_3FF4
  3FCB  5D                TSTB
  3FCC  27 25             BEQ    L_3FF3
  3FCE  20 05             BRA    L_3FD5
L_3FD0:
  3FD0  5F                CLRB
  3FD1  D7 02             STB    <$02
  3FD3  35 90             PULS   X,PC
L_3FD5:
  3FD5  F6 62 03          LDB    >MarioX
  3FD8  B6 62 10          LDA    >$6210
  3FDB  27 06             BEQ    L_3FE3
  3FDD  CA 07             ORB    #$07
  3FDF  C0 04             SUBB   #$04
  3FE1  20 06             BRA    L_3FE9
L_3FE3:
  3FE3  C0 08             SUBB   #$08
  3FE5  CA 07             ORB    #$07
  3FE7  CB 04             ADDB   #$04
L_3FE9:
  3FE9  F7 62 03          STB    >MarioX
  3FEC  F7 69 4C          STB    >$694C
  3FEF  C6 01             LDB    #$01
  3FF1  35 90             PULS   X,PC
L_3FF3:
  3FF3  39                RTS

; =====================================================================
; SUB_3FF4 (58 instructions)
; Uses:  $620C MarioY
; Calls: SUB_443F
; =====================================================================
SUB_3FF4:
  3FF4  34 10             PSHS   X
  3FF6  BD 44 3F          JSR    >SUB_443F
  3FF9  35 20             PULS   Y
  3FFB  E6 84             LDB    ,X
  3FFD  C1 B0             CMPB   #$B0
  3FFF  25 33             BCS    L_4034
  4001  C4 0F             ANDB   #$0F
  4003  C1 08             CMPB   #$08
  4005  24 2D             BCC    L_4034
  4007  E6 84             LDB    ,X
  4009  C1 C0             CMPB   #$C0
  400B  27 27             BEQ    L_4034
  400D  25 29             BCS    L_4038
  400F  C1 D0             CMPB   #$D0
  4011  25 0D             BCS    L_4020
  4013  C1 E0             CMPB   #$E0
  4015  25 04             BCS    L_401B
  4017  C1 F0             CMPB   #$F0
  4019  25 05             BCS    L_4020
L_401B:
  401B  C4 0F             ANDB   #$0F
  401D  5A                DECB
  401E  20 04             BRA    L_4024
L_4020:
  4020  C4 0F             ANDB   #$0F
  4022  C0 09             SUBB   #$09
L_4024:
  4024  D7 03             STB    <$03
  4026  1F 20             TFR    Y,D
  4028  D7 05             STB    <$05
  402A  C4 F8             ANDB   #$F8
  402C  DB 03             ADDB   <$03
  402E  D7 03             STB    <$03
  4030  D1 05             CMPB   <$05
  4032  25 0D             BCS    L_4041
L_4034:
  4034  5F                CLRB
  4035  D7 02             STB    <$02
  4037  39                RTS
L_4038:
  4038  1F 20             TFR    Y,D
  403A  D7 05             STB    <$05
  403C  C4 F8             ANDB   #$F8
  403E  5A                DECB
  403F  D7 03             STB    <$03
L_4041:
  4041  F6 62 0C          LDB    >$620C
  4044  E0 45             SUBB   5,U
  4046  DB 05             ADDB   <$05
  4048  D1 03             CMPB   <$03
  404A  27 02             BEQ    L_404E
  404C  24 09             BCC    L_4057
L_404E:
  404E  D6 03             LDB    <$03
  4050  C0 07             SUBB   #$07
  4052  F7 62 05          STB    >MarioY
  4055  20 05             BRA    L_405C
L_4057:
  4057  C6 02             LDB    #$02
  4059  0F 02             CLR    <$02
  405B  39                RTS
L_405C:
  405C  C6 01             LDB    #$01
  405E  D7 02             STB    <$02
  4060  32 62             LEAS   2,S
  4062  35 10             PULS   X
  4064  39                RTS

; =====================================================================
; SUB_4065 (68 instructions)
; Uses:  $6393 $62B1 $62B0 $6382 Difficulty FrameCounter RandTimer $638F $6392 $62B2 Fireballs
; Calls: RST_RetIfNotScreen RST_RetIfMarioDead UpdateRandom
; =====================================================================
SUB_4065:
  4065  C6 01             LDB    #$01
  4067  9D 64             JSR    <RST_RetIfNotScreen
  4069  9D 38             JSR    <RST_RetIfMarioDead
  406B  F6 63 93          LDB    >$6393
  406E  56                RORB
  406F  25 29             BCS    L_409A
  4071  F6 62 B1          LDB    >$62B1
  4074  27 24             BEQ    L_409A
  4076  D7 03             STB    <$03
  4078  F6 62 B0          LDB    >$62B0
  407B  C0 02             SUBB   #$02
  407D  D1 03             CMPB   <$03
  407F  25 64             BCS    L_40E5
  4081  F6 63 82          LDB    >$6382
  4084  C4 02             ANDB   #$02
  4086  26 67             BNE    L_40EF
  4088  F6 63 80          LDB    >Difficulty
  408B  D7 02             STB    <$02
  408D  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  4090  C4 1F             ANDB   #$1F
L_4092:
  4092  D1 02             CMPB   <$02
  4094  27 05             BEQ    L_409B
  4096  0A 02             DEC    <$02
  4098  26 F8             BNE    L_4092
L_409A:
  409A  39                RTS
L_409B:
  409B  F6 62 B0          LDB    >$62B0
  409E  54                LSRB
  409F  D1 03             CMPB   <$03
  40A1  25 06             BCS    L_40A9
  40A3  F6 60 19          LDB    >RandTimer
  40A6  56                RORB
  40A7  24 F1             BCC    L_409A
L_40A9:
  40A9  9D FC             JSR    <UpdateRandom
  40AB  C4 0F             ANDB   #$0F
  40AD  26 40             BNE    L_40EF
L_40AF:
  40AF  C6 01             LDB    #$01
L_40B1:
  40B1  F7 63 82          STB    >$6382
  40B4  5C                INCB
L_40B5:
  40B5  F7 63 8F          STB    >$638F
  40B8  C6 01             LDB    #$01
  40BA  F7 63 92          STB    >$6392
  40BD  F6 62 B2          LDB    >$62B2
  40C0  D1 03             CMPB   <$03
  40C2  26 D6             BNE    L_409A
  40C4  C0 08             SUBB   #$08
  40C6  F7 62 B2          STB    >$62B2
  40C9  8E 64 00          LDX    #Fireballs
  40CC  86 05             LDA    #$05
  40CE  97 02             STA    <$02
L_40D0:
  40D0  E6 84             LDB    ,X
  40D2  27 08             BEQ    L_40DC
  40D4  30 88 20          LEAX   <32,X
  40D7  0A 02             DEC    <$02
  40D9  26 F5             BNE    L_40D0
  40DB  39                RTS
L_40DC:
  40DC  F6 63 82          LDB    >$6382
  40DF  CA 80             ORB    #$80
  40E1  F7 63 82          STB    >$6382
  40E4  39                RTS
L_40E5:
  40E5  CB 02             ADDB   #$02
  40E7  D1 03             CMPB   <$03
  40E9  27 C4             BEQ    L_40AF
  40EB  C6 02             LDB    #$02
  40ED  20 C2             BRA    L_40B1
L_40EF:
  40EF  5F                CLRB
  40F0  F7 63 82          STB    >$6382
  40F3  C6 03             LDB    #$03
  40F5  20 BE             BRA    L_40B5

; =====================================================================
; SUB_40F7 (150 instructions)
; Uses:  $6393 $6392 Barrels $62AA $6980 $62AC $62B1 $6386 $69A8 $6382 $62AF $638F $62A8 $690B
; Calls: RST_RetIfNotScreen RST_RetIfMarioDead AddTask RST_CopySprites RST_AddToObjects
; =====================================================================
SUB_40F7:
  40F7  C6 01             LDB    #$01
  40F9  9D 64             JSR    <RST_RetIfNotScreen
  40FB  9D 38             JSR    <RST_RetIfMarioDead
  40FD  F6 63 93          LDB    >$6393
  4100  56                RORB
  4101  25 76             BCS    L_4179
  4103  F6 63 92          LDB    >$6392
  4106  56                RORB
  4107  24 1A             BCC    L_4123
  4109  CE 67 00          LDU    #Barrels
  410C  10 8E 00 20       LDY    #$0020
  4110  86 0A             LDA    #$0A
  4112  97 02             STA    <$02
L_4114:
  4114  E6 C4             LDB    ,U
  4116  56                RORB
  4117  25 03             BCS    L_411C
  4119  56                RORB
  411A  24 08             BCC    L_4124
L_411C:
  411C  33 C8 20          LEAU   <32,U
  411F  0A 02             DEC    <$02
  4121  26 F1             BNE    L_4114
L_4123:
  4123  39                RTS
L_4124:
  4124  FF 62 AA          STU    >$62AA
  4127  86 02             LDA    #$02
  4129  A7 C4             STA    ,U
  412B  C6 0A             LDB    #$0A
  412D  D0 02             SUBB   <$02
  412F  58                ASLB
  4130  58                ASLB
  4131  8E 69 80          LDX    #$6980
  4134  3A                ABX
  4135  BF 62 AC          STX    >$62AC
  4138  C6 01             LDB    #$01
  413A  F7 63 93          STB    >$6393
  413D  10 8E 05 01       LDY    #$0501                  ; queue BonusTimer(1)
  4141  BD 45 21          JSR    >AddTask
  4144  8E 62 B1          LDX    #$62B1
  4147  6A 84             DEC    ,X
  4149  26 05             BNE    L_4150
  414B  C6 01             LDB    #$01
  414D  F7 63 86          STB    >$6386
L_4150:
  4150  E6 84             LDB    ,X
  4152  C1 04             CMPB   #$04
  4154  24 08             BCC    L_415E
  4156  8E 69 A8          LDX    #$69A8
  4159  58                ASLB
  415A  58                ASLB
  415B  3A                ABX
  415C  6F 84             CLR    ,X
L_415E:
  415E  CC 15 0B          LDD    #$150B
  4161  ED 47             STD    7,U
  4163  6F C8 15          CLR    <21,U
  4166  F6 63 82          LDB    >$6382
  4169  59                ROLB
  416A  24 0D             BCC    L_4179
  416C  86 19             LDA    #$19
  416E  A7 47             STA    7,U
  4170  86 0C             LDA    #$0C
  4172  A7 48             STA    8,U
  4174  86 01             LDA    #$01
  4176  A7 C8 15          STA    <21,U
L_4179:
  4179  8E 62 AF          LDX    #$62AF
  417C  6A 84             DEC    ,X
  417E  26 A3             BNE    L_4123
  4180  86 18             LDA    #$18
  4182  A7 84             STA    ,X
  4184  F6 63 8F          LDB    >$638F
  4187  27 2D             BEQ    L_41B6
  4189  D7 03             STB    <$03
  418B  8E 4D 1A          LDX    #D_4D1A
  418E  F6 63 82          LDB    >$6382
  4191  56                RORB
  4192  25 02             BCS    L_4196
  4194  0A 03             DEC    <$03
L_4196:
  4196  D6 03             LDB    <$03
  4198  58                ASLB
  4199  58                ASLB
  419A  58                ASLB
  419B  D7 03             STB    <$03
  419D  58                ASLB
  419E  58                ASLB
  419F  DB 03             ADDB   <$03
  41A1  3A                ABX
  41A2  9D 77             JSR    <RST_CopySprites
  41A4  8E 63 8F          LDX    #$638F
  41A7  6A 84             DEC    ,X
  41A9  26 0B             BNE    L_41B6
  41AB  C6 01             LDB    #$01
  41AD  F7 62 AF          STB    >$62AF
  41B0  F6 63 82          LDB    >$6382
  41B3  56                RORB
  41B4  25 30             BCS    L_41E6
L_41B6:
  41B6  BE 62 A8          LDX    >$62A8
L_41B9:
  41B9  E6 84             LDB    ,X
  41BB  FE 62 AA          LDU    >$62AA
  41BE  10 BE 62 AC       LDY    >$62AC
  41C2  C1 7F             CMPB   #$7F
  41C4  27 28             BEQ    L_41EE
  41C6  D7 03             STB    <$03
  41C8  C4 7F             ANDB   #$7F
  41CA  E7 A0             STB    ,Y+
  41CC  E6 47             LDB    7,U
  41CE  96 03             LDA    <$03
  41D0  2A 02             BPL    L_41D4
  41D2  C8 03             EORB   #$03
L_41D4:
  41D4  E7 A0             STB    ,Y+
  41D6  E7 47             STB    7,U
  41D8  E6 48             LDB    8,U
  41DA  E7 A0             STB    ,Y+
  41DC  30 01             LEAX   1,X
  41DE  E6 80             LDB    ,X+
  41E0  E7 A4             STB    ,Y
  41E2  BF 62 A8          STX    >$62A8
  41E5  39                RTS
L_41E6:
  41E6  8E 4D B4          LDX    #D_4DB4
  41E9  BF 62 A8          STX    >$62A8
  41EC  20 CB             BRA    L_41B9
L_41EE:
  41EE  8E 4D AB          LDX    #D_4DAB
  41F1  BF 62 A8          STX    >$62A8
  41F4  86 01             LDA    #$01
  41F6  A7 41             STA    1,U
  41F8  F6 63 82          LDB    >$6382
  41FB  56                RORB
  41FC  25 06             BCS    L_4204
  41FE  6F 41             CLR    1,U
  4200  86 02             LDA    #$02
  4202  A7 42             STA    2,U
L_4204:
  4204  86 01             LDA    #$01
  4206  A7 C4             STA    ,U
  4208  A7 4F             STA    15,U
  420A  5F                CLRB
  420B  E7 C8 10          STB    <16,U
  420E  E7 C8 11          STB    <17,U
  4211  E7 C8 12          STB    <18,U
  4214  E7 C8 13          STB    <19,U
  4217  E7 C8 14          STB    <20,U
  421A  F7 63 93          STB    >$6393
  421D  F7 63 92          STB    >$6392
  4220  E6 A4             LDB    ,Y
  4222  E7 43             STB    3,U
  4224  31 23             LEAY   3,Y
  4226  E6 A4             LDB    ,Y
  4228  E7 45             STB    5,U
  422A  8E 4D B7          LDX    #D_4DB7
  422D  9D 77             JSR    <RST_CopySprites
  422F  8E 69 0B          LDX    #$690B
  4232  86 FC             LDA    #$FC
  4234  97 03             STA    <$03
  4236  9D 4F             JSR    <RST_AddToObjects
  4238  39                RTS

; =====================================================================
; SUB_4239 (25 instructions)
; Uses:  Difficulty ScreenNum FrameCounter $63A0 $639A
; Calls: RST_RetIfNotScreen RST_RetIfMarioDead
; =====================================================================
SUB_4239:
  4239  C6 0A             LDB    #$0A
  423B  9D 64             JSR    <RST_RetIfNotScreen
  423D  9D 38             JSR    <RST_RetIfMarioDead
  423F  F6 63 80          LDB    >Difficulty
  4242  5C                INCB
  4243  54                LSRB
  4244  D7 02             STB    <$02
  4246  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  4249  C1 02             CMPB   #$02
  424B  26 02             BNE    L_424F
  424D  0C 02             INC    <$02
L_424F:
  424F  C6 FE             LDB    #$FE
  4251  1A 01             ORCC   #$01
L_4253:
  4253  56                RORB
  4254  4F                CLRA
  4255  0A 02             DEC    <$02
  4257  26 FA             BNE    L_4253
  4259  D7 02             STB    <$02
  425B  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  425E  D4 02             ANDB   <$02
  4260  26 08             BNE    L_426A
  4262  C6 01             LDB    #$01
  4264  F7 63 A0          STB    >$63A0
  4267  F7 63 9A          STB    >$639A
L_426A:
  426A  39                RTS

; =====================================================================
; SUB_426B (87 instructions)
; Uses:  $6980 $6500 FrameCounter SndCoin SndFx4 $6396
; Calls: RST_RetIfNotScreen RST_RetIfMarioDead UpdateRandom
; =====================================================================
SUB_426B:
  426B  C6 04             LDB    #$04
  426D  9D 64             JSR    <RST_RetIfNotScreen
  426F  9D 38             JSR    <RST_RetIfMarioDead
  4271  10 8E 69 80       LDY    #$6980
  4275  CE 65 00          LDU    #$6500
  4278  86 0A             LDA    #$0A
  427A  97 02             STA    <$02
L_427C:
  427C  E6 C4             LDB    ,U
  427E  56                RORB
  427F  24 7C             BCC    L_42FD
  4281  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  4284  C4 0F             ANDB   #$0F
  4286  26 06             BNE    L_428E
  4288  E6 21             LDB    1,Y
  428A  C8 07             EORB   #$07
  428C  E7 21             STB    1,Y
L_428E:
  428E  E6 4D             LDB    13,U
  4290  C1 04             CMPB   #$04
  4292  27 4F             BEQ    L_42E3
  4294  6C 43             INC    3,U
  4296  6C 43             INC    3,U
  4298  E6 4E             LDB    14,U
  429A  A6 4F             LDA    15,U
  429C  1F 01             TFR    D,X
  429E  E6 84             LDB    ,X
  42A0  D7 03             STB    <$03
  42A2  C1 7F             CMPB   #$7F
  42A4  27 4D             BEQ    L_42F3
  42A6  30 01             LEAX   1,X
  42A8  EB 45             ADDB   5,U
  42AA  E7 45             STB    5,U
L_42AC:
  42AC  1F 10             TFR    X,D
  42AE  E7 4E             STB    14,U
  42B0  A7 4F             STA    15,U
  42B2  E6 43             LDB    3,U
  42B4  C1 B7             CMPB   #$B7
  42B6  25 12             BCS    L_42CA
  42B8  D6 03             LDB    <$03
  42BA  C1 7F             CMPB   #$7F
  42BC  26 0C             BNE    L_42CA
  42BE  86 04             LDA    #$04
  42C0  A7 4D             STA    13,U
  42C2  7F 60 83          CLR    >SndCoin
  42C5  C6 03             LDB    #$03
  42C7  F7 60 84          STB    >SndFx4
L_42CA:
  42CA  E6 43             LDB    3,U
  42CC  E7 A4             STB    ,Y
  42CE  E6 45             LDB    5,U
  42D0  E7 23             STB    3,Y
L_42D2:
  42D2  33 C8 10          LEAU   <16,U
  42D5  31 24             LEAY   4,Y
  42D7  0A 02             DEC    <$02
  42D9  26 A1             BNE    L_427C
  42DB  10 9F 0A          STY    <$0A
  42DE  10 8E 00 04       LDY    #$0004
  42E2  39                RTS
L_42E3:
  42E3  C6 03             LDB    #$03
  42E5  EB 45             ADDB   5,U
  42E7  E7 45             STB    5,U
  42E9  C1 F8             CMPB   #$F8
  42EB  25 DD             BCS    L_42CA
  42ED  6F 43             CLR    3,U
  42EF  6F C4             CLR    ,U
  42F1  20 D7             BRA    L_42CA
L_42F3:
  42F3  8E 4D 92          LDX    #D_4D92
  42F6  C6 03             LDB    #$03
  42F8  F7 60 83          STB    >SndCoin
  42FB  20 AF             BRA    L_42AC
L_42FD:
  42FD  F6 63 96          LDB    >$6396
  4300  56                RORB
  4301  24 CF             BCC    L_42D2
  4303  5F                CLRB
  4304  F7 63 96          STB    >$6396
  4307  CC 50 01          LDD    #$5001
  430A  A7 45             STA    5,U
  430C  E7 4D             STB    13,U
  430E  9D FC             JSR    <UpdateRandom
  4310  C4 0F             ANDB   #$0F
  4312  CB F8             ADDB   #$F8
  4314  E7 43             STB    3,U
  4316  86 01             LDA    #$01
  4318  A7 C4             STA    ,U
  431A  8E 4D 92          LDX    #D_4D92
  431D  1F 10             TFR    X,D
  431F  E7 4E             STB    14,U
  4321  A7 4F             STA    15,U
  4323  20 AD             BRA    L_42D2

; =====================================================================
; SUB_4325 (106 instructions)
; Uses:  $6A18 $6680 $6A1C $6690 $6217 $6218 MusicReq $6207 $6394 $694D $6395 MarioX $6389 MarioY ...
; Calls: RST_RetIfNotScreen RST_RetIfMarioDead
; =====================================================================
SUB_4325:
  4325  C6 0B             LDB    #$0B
  4327  9D 64             JSR    <RST_RetIfNotScreen
  4329  9D 38             JSR    <RST_RetIfMarioDead
  432B  10 8E 6A 18       LDY    #$6A18
  432F  CE 66 80          LDU    #$6680
  4332  E6 41             LDB    1,U
  4334  56                RORB
  4335  25 07             BCS    L_433E
  4337  10 8E 6A 1C       LDY    #$6A1C
  433B  CE 66 90          LDU    #$6690
L_433E:
  433E  CC 00 F0          LDD    #$00F0
  4341  ED 4E             STD    14,U
  4343  F6 62 17          LDB    >$6217
  4346  56                RORB
  4347  10 24 00 98       LBCC   L_43E3
  434B  5F                CLRB
  434C  F7 62 18          STB    >$6218
  434F  8E 60 89          LDX    #MusicReq
  4352  86 04             LDA    #$04
  4354  A7 84             STA    ,X
  4356  CC 06 03          LDD    #$0603
  4359  ED 49             STD    9,U
  435B  86 1E             LDA    #$1E
  435D  97 02             STA    <$02
  435F  F6 62 07          LDB    >$6207
  4362  58                ASLB
  4363  24 08             BCC    L_436D
  4365  CA 80             ORB    #$80
  4367  96 02             LDA    <$02
  4369  8A 80             ORA    #$80
  436B  97 02             STA    <$02
L_436D:
  436D  CA 08             ORB    #$08
  436F  D7 03             STB    <$03
  4371  F6 63 94          LDB    >$6394
  4374  C4 08             ANDB   #$08
  4376  27 1A             BEQ    L_4392
  4378  DC 02             LDD    <$02
  437A  8A 01             ORA    #$01
  437C  CA 01             ORB    #$01
  437E  DD 02             STD    <$02
  4380  CC 05 06          LDD    #$0506
  4383  ED 49             STD    9,U
  4385  CC F0 00          LDD    #$F000
  4388  ED 4E             STD    14,U
  438A  96 03             LDA    <$03
  438C  2A 04             BPL    L_4392
  438E  86 10             LDA    #$10
  4390  A7 4E             STA    14,U
L_4392:
  4392  D6 03             LDB    <$03
  4394  F7 69 4D          STB    >$694D
  4397  0F 03             CLR    <$03
  4399  8E 63 94          LDX    #$6394
  439C  6C 84             INC    ,X
  439E  26 61             BNE    L_4401
  43A0  8E 63 95          LDX    #$6395
  43A3  6C 84             INC    ,X
  43A5  E6 84             LDB    ,X
  43A7  C1 02             CMPB   #$02
  43A9  26 5B             BNE    L_4406
  43AB  5F                CLRB
  43AC  F7 63 95          STB    >$6395
  43AF  F7 62 17          STB    >$6217
  43B2  E7 41             STB    1,U
  43B4  F6 62 03          LDB    >MarioX
  43B7  50                NEGB
  43B8  E7 4E             STB    14,U
  43BA  F6 62 07          LDB    >$6207
  43BD  F7 69 4D          STB    >$694D
  43C0  6F C4             CLR    ,U
  43C2  F6 63 89          LDB    >$6389
  43C5  F7 60 89          STB    >MusicReq               ; music number request
L_43C8:
  43C8  1E 21             EXG    Y,X
  43CA  F6 62 03          LDB    >MarioX
  43CD  EB 4E             ADDB   14,U
  43CF  E7 80             STB    ,X+
  43D1  E7 43             STB    3,U
  43D3  96 02             LDA    <$02
  43D5  9B 03             ADDA   <$03
  43D7  A7 81             STA    ,X++
  43D9  F6 62 05          LDB    >MarioY
  43DC  EB 4F             ADDB   15,U
  43DE  E7 84             STB    ,X
  43E0  E7 45             STB    5,U
L_43E2:
  43E2  39                RTS
L_43E3:
  43E3  F6 62 18          LDB    >$6218
  43E6  56                RORB
  43E7  24 F9             BCC    L_43E2
  43E9  CC 06 03          LDD    #$0603
  43EC  ED 49             STD    9,U
  43EE  F6 62 07          LDB    >$6207
  43F1  59                ROLB
  43F2  C6 3C             LDB    #$3C
  43F4  56                RORB
  43F5  D7 02             STB    <$02
  43F7  0F 03             CLR    <$03
  43F9  F6 60 89          LDB    >MusicReq               ; music number request
  43FC  F7 63 89          STB    >$6389
  43FF  20 C7             BRA    L_43C8
L_4401:
  4401  F6 63 95          LDB    >$6395
  4404  27 C2             BEQ    L_43C8
L_4406:
  4406  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  4409  C4 08             ANDB   #$08
  440B  27 BB             BEQ    L_43C8
  440D  86 FE             LDA    #$FE
  440F  97 03             STA    <$03
  4411  20 B5             BRA    L_43C8

; =====================================================================
; SUB_4413 (18 instructions)
; Uses:  $62B4 $62B9 $6396 $62B3 $62B1 $6386
; Calls: RST_RetIfNotScreen AddTask
; =====================================================================
SUB_4413:
  4413  C6 0E             LDB    #$0E
  4415  9D 64             JSR    <RST_RetIfNotScreen
  4417  8E 62 B4          LDX    #$62B4
  441A  6A 84             DEC    ,X
  441C  26 20             BNE    L_443E
  441E  C6 03             LDB    #$03
  4420  F7 62 B9          STB    >$62B9
  4423  F7 63 96          STB    >$6396
  4426  10 8E 05 01       LDY    #$0501                  ; queue BonusTimer(1)
  442A  BD 45 21          JSR    >AddTask
  442D  F6 62 B3          LDB    >$62B3
  4430  E7 84             STB    ,X
  4432  8E 62 B1          LDX    #$62B1
  4435  6A 84             DEC    ,X
  4437  26 05             BNE    L_443E
  4439  C6 01             LDB    #$01
  443B  F7 63 86          STB    >$6386
L_443E:
  443E  39                RTS

; =====================================================================
; SUB_443F (18 instructions)
; =====================================================================
SUB_443F:
  443F  1F 10             TFR    X,D
  4441  54                LSRB
  4442  54                LSRB
  4443  54                LSRB
  4444  43                COMA
  4445  84 F8             ANDA   #$F8
  4447  97 05             STA    <$05
  4449  4F                CLRA
  444A  1F 01             TFR    D,X
  444C  D6 05             LDB    <$05
  444E  59                ROLB
  444F  49                ROLA
  4450  59                ROLB
  4451  49                ROLA
  4452  8B 74             ADDA   #$74
  4454  1F 02             TFR    D,Y
  4456  30 8B             LEAX   D,X
  4458  39                RTS

; =====================================================================
; SUB_4459 (51 instructions)
; =====================================================================
SUB_4459:
  4459  D7 04             STB    <$04
  445B  56                RORB
  445C  25 17             BCS    L_4475
  445E  86 93             LDA    #$93
  4460  97 03             STA    <$03
  4462  56                RORB
  4463  56                RORB
  4464  24 04             BCC    L_446A
  4466  86 6C             LDA    #$6C
  4468  97 03             STA    <$03
L_446A:
  446A  59                ROLB
  446B  25 1C             BCS    L_4489
  446D  D6 03             LDB    <$03
  446F  C4 F0             ANDB   #$F0
  4471  D7 03             STB    <$03
  4473  20 14             BRA    L_4489
L_4475:
  4475  86 B4             LDA    #$B4
  4477  97 03             STA    <$03
  4479  56                RORB
  447A  56                RORB
  447B  24 04             BCC    L_4481
  447D  86 1E             LDA    #$1E
  447F  97 03             STA    <$03
L_4481:
  4481  96 02             LDA    <$02
  4483  84 04             ANDA   #$04
  4485  27 02             BEQ    L_4489
  4487  0A 02             DEC    <$02
L_4489:
  4489  D6 03             LDB    <$03
  448B  1F 98             TFR    B,A
  448D  46                RORA
  448E  56                RORB
  448F  46                RORA
  4490  56                RORB
  4491  D7 03             STB    <$03
  4493  C4 03             ANDB   #$03
  4495  D1 02             CMPB   <$02
  4497  26 F0             BNE    L_4489
  4499  D6 03             LDB    <$03
  449B  56                RORB
  449C  56                RORB
  449D  C4 03             ANDB   #$03
  449F  C1 03             CMPB   #$03
  44A1  26 09             BNE    L_44AC
  44A3  96 04             LDA    <$04
  44A5  84 FB             ANDA   #$FB
  44A7  4A                DECA
  44A8  26 03             BNE    L_44AD
  44AA  C6 04             LDB    #$04
L_44AC:
  44AC  39                RTS
L_44AD:
  44AD  C6 03             LDB    #$03
  44AF  39                RTS

; =====================================================================
; SUB_44B0 (12 instructions)
; Uses:  $638E $7600 $75C0
; Calls: SUB_44CC
; =====================================================================
SUB_44B0:
  44B0  10 8E FF E0       LDY    #$FFE0
  44B4  F6 63 8E          LDB    >$638E
  44B7  4F                CLRA
  44B8  DD 02             STD    <$02
  44BA  8E 76 00          LDX    #$7600
  44BD  8D 0D             BSR    SUB_44CC
  44BF  D6 03             LDB    <$03
  44C1  8E 75 C0          LDX    #$75C0
  44C4  8D 06             BSR    SUB_44CC
  44C6  8E 63 8E          LDX    #$638E
  44C9  6A 84             DEC    ,X
  44CB  39                RTS

; =====================================================================
; SUB_44CC (8 instructions)
; Uses:  $63C0
; Calls: RST_WaitTimer
; =====================================================================
SUB_44CC:
  44CC  30 8B             LEAX   D,X
  44CE  E6 84             LDB    ,X
  44D0  E7 88 E0          STB    <-32,X
  44D3  39                RTS
L_44D4:
  44D4  9D 3F             JSR    <RST_WaitTimer
  44D6  BE 63 C0          LDX    >$63C0
  44D9  6C 84             INC    ,X
  44DB  39                RTS

; =====================================================================
; SUB_44DC (21 instructions)
; Uses:  $62AF $690B $6909 $691D $692D
; Calls: RST_AddToObjects SUB_450A UpdateRandom
; =====================================================================
SUB_44DC:
  44DC  8E 62 AF          LDX    #$62AF
  44DF  6C 84             INC    ,X
  44E1  E6 84             LDB    ,X
  44E3  C4 07             ANDB   #$07
  44E5  26 22             BNE    L_4509
  44E7  8E 69 0B          LDX    #$690B
  44EA  86 FC             LDA    #$FC
  44EC  97 03             STA    <$03
  44EE  9D 4F             JSR    <RST_AddToObjects
  44F0  86 81             LDA    #$81
  44F2  97 03             STA    <$03
  44F4  8E 69 09          LDX    #$6909
  44F7  8D 11             BSR    SUB_450A
  44F9  8E 69 1D          LDX    #$691D
  44FC  8D 0C             BSR    SUB_450A
  44FE  9D FC             JSR    <UpdateRandom
  4500  C4 80             ANDB   #$80
  4502  8E 69 2D          LDX    #$692D
  4505  E8 84             EORB   ,X
  4507  E7 84             STB    ,X
L_4509:
  4509  39                RTS

; =====================================================================
; SUB_450A (12 instructions)
; =====================================================================
SUB_450A:
  450A  86 02             LDA    #$02
  450C  97 02             STA    <$02
L_450E:
  450E  D6 03             LDB    <$03
  4510  E8 84             EORB   ,X
  4512  E7 84             STB    ,X
  4514  D7 01             STB    <$01
  4516  1F 20             TFR    Y,D
  4518  30 8B             LEAX   D,X
  451A  D6 01             LDB    <$01
  451C  0A 02             DEC    <$02
  451E  26 EE             BNE    L_450E
  4520  39                RTS

; =====================================================================
; AddTask: Y = task number : parameter.  Writes it into the task
; ring buffer $60C0-$60FF at $60B0 when the slot is free ($FF).
; =====================================================================
AddTask:
  4521  34 10             PSHS   X
  4523  86 60             LDA    #$60
  4525  F6 60 B0          LDB    >TaskWrPtr              ; task queue write ptr (low byte)
  4528  1F 01             TFR    D,X
  452A  A6 84             LDA    ,X
  452C  2A 0E             BPL    L_453C
  452E  10 AF 81          STY    ,X++
  4531  1F 10             TFR    X,D
  4533  C1 C0             CMPB   #$C0
  4535  24 02             BCC    L_4539
  4537  C6 C0             LDB    #$C0
L_4539:
  4539  F7 60 B0          STB    >TaskWrPtr              ; task queue write ptr (low byte)
L_453C:
  453C  35 90             PULS   X,PC

; =====================================================================
; SUB_453E (12 instructions)
; Uses:  $6950 $6980 $69B8 $6A0C
; Calls: SUB_4564
; =====================================================================
SUB_453E:
  453E  8E 69 50          LDX    #$6950
  4541  86 02             LDA    #$02
  4543  8D 1F             BSR    SUB_4564
  4545  8E 69 80          LDX    #$6980
  4548  86 0A             LDA    #$0A
  454A  8D 18             BSR    SUB_4564
  454C  8E 69 B8          LDX    #$69B8
  454F  86 0B             LDA    #$0B
  4551  8D 11             BSR    SUB_4564
  4553  8E 6A 0C          LDX    #$6A0C
  4556  86 05             LDA    #$05
  4558  20 0A             BRA    SUB_4564

; =====================================================================
; SUB_455A (4 instructions)
; Uses:  $694C $6958
; =====================================================================
SUB_455A:
  455A  8E 69 4C          LDX    #$694C
  455D  6F 84             CLR    ,X
  455F  8E 69 58          LDX    #$6958
  4562  86 06             LDA    #$06

; =====================================================================
; SUB_4564 (5 instructions)
; =====================================================================
SUB_4564:
  4564  6F 84             CLR    ,X
  4566  30 04             LEAX   4,X
  4568  4A                DECA
  4569  26 F9             BNE    SUB_4564
  456B  39                RTS

; =====================================================================
; SUB_456C (5 instructions)
; Calls: SUB_4577 SUB_45BE SUB_4640 SUB_4921
; =====================================================================
SUB_456C:
  456C  8D 09             BSR    SUB_4577
  456E  8D 4E             BSR    SUB_45BE
  4570  BD 46 40          JSR    >SUB_4640
  4573  BD 49 21          JSR    >SUB_4921
  4576  39                RTS

; =====================================================================
; SUB_4577 (29 instructions)
; Uses:  Difficulty FrameCounter
; Calls: RST_JumpTable
; =====================================================================
SUB_4577:
  4577  F6 63 80          LDB    >Difficulty
  457A  C1 06             CMPB   #$06
  457C  25 02             BCS    L_4580
  457E  C6 05             LDB    #$05
L_4580:
  4580  9D 47             JSR    <RST_JumpTable
TBL_4582:
  4582  45 8E             FDB    L_458E
  4584  45 8E             FDB    L_458E
  4586  45 9A             FDB    L_459A
  4588  45 A6             FDB    L_45A6
  458A  45 A6             FDB    L_45A6
  458C  45 B2             FDB    L_45B2
L_458E:
  458E  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  4591  C4 01             ANDB   #$01
  4593  C1 01             CMPB   #$01
  4595  27 02             BEQ    L_4599
  4597  32 62             LEAS   2,S
L_4599:
  4599  39                RTS
L_459A:
  459A  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  459D  C4 07             ANDB   #$07
  459F  C1 05             CMPB   #$05
  45A1  2B 02             BMI    L_45A5
  45A3  32 62             LEAS   2,S
L_45A5:
  45A5  39                RTS
L_45A6:
  45A6  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  45A9  C4 03             ANDB   #$03
  45AB  C1 03             CMPB   #$03
  45AD  2B 02             BMI    L_45B1
  45AF  32 62             LEAS   2,S
L_45B1:
  45B1  39                RTS
L_45B2:
  45B2  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  45B5  C4 07             ANDB   #$07
  45B7  C1 07             CMPB   #$07
  45B9  2B 02             BMI    L_45BD
  45BB  32 62             LEAS   2,S
L_45BD:
  45BD  39                RTS

; =====================================================================
; SUB_45BE (59 instructions)
; Uses:  Fireballs $63A1 $6217 $63A0 ScreenNum Difficulty
; =====================================================================
SUB_45BE:
  45BE  CE 64 00          LDU    #Fireballs
  45C1  5F                CLRB
  45C2  F7 63 A1          STB    >$63A1
  45C5  86 05             LDA    #$05
  45C7  97 02             STA    <$02
L_45C9:
  45C9  E6 C4             LDB    ,U
  45CB  27 40             BEQ    L_460D
  45CD  F6 63 A1          LDB    >$63A1
  45D0  5C                INCB
  45D1  F7 63 A1          STB    >$63A1
  45D4  F6 62 17          LDB    >$6217
  45D7  C1 01             CMPB   #$01
  45D9  26 10             BNE    L_45EB
  45DB  E6 47             LDB    7,U
  45DD  C4 70             ANDB   #$70
  45DF  C1 40             CMPB   #$40
  45E1  22 16             BHI    L_45F9
  45E3  E6 47             LDB    7,U
  45E5  CB 20             ADDB   #$20
  45E7  E7 47             STB    7,U
  45E9  20 0E             BRA    L_45F9
L_45EB:
  45EB  E6 47             LDB    7,U
  45ED  C4 70             ANDB   #$70
  45EF  C1 50             CMPB   #$50
  45F1  25 06             BCS    L_45F9
  45F3  E6 47             LDB    7,U
  45F5  C0 20             SUBB   #$20
  45F7  E7 47             STB    7,U
L_45F9:
  45F9  33 C8 20          LEAU   <32,U
  45FC  0A 02             DEC    <$02
  45FE  26 C9             BNE    L_45C9
  4600  8E 63 A0          LDX    #$63A0
  4603  6F 84             CLR    ,X
  4605  F6 63 A1          LDB    >$63A1
  4608  26 02             BNE    L_460C
  460A  32 62             LEAS   2,S
L_460C:
  460C  39                RTS
L_460D:
  460D  F6 63 A1          LDB    >$63A1
  4610  C1 05             CMPB   #$05
  4612  27 E5             BEQ    L_45F9
  4614  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  4617  C1 02             CMPB   #$02
  4619  26 0C             BNE    L_4627
  461B  F6 63 A1          LDB    >$63A1
  461E  D7 03             STB    <$03
  4620  F6 63 80          LDB    >Difficulty
  4623  D1 03             CMPB   <$03
  4625  27 E5             BEQ    L_460C
L_4627:
  4627  F6 63 A0          LDB    >$63A0
  462A  C1 01             CMPB   #$01
  462C  26 CB             BNE    L_45F9
  462E  E7 C4             STB    ,U
  4630  E7 C8 18          STB    <24,U
  4633  5F                CLRB
  4634  F7 63 A0          STB    >$63A0
  4637  F6 63 A1          LDB    >$63A1
  463A  5C                INCB
  463B  F7 63 A1          STB    >$63A1
  463E  20 B9             BRA    L_45F9

; =====================================================================
; SUB_4640 (17 instructions)
; Uses:  $63A2 $63E0 $63C8
; Calls: SUB_4667 SUB_4690
; =====================================================================
SUB_4640:
  4640  8D 25             BSR    SUB_4667
  4642  5F                CLRB
  4643  F7 63 A2          STB    >$63A2
  4646  8E 63 E0          LDX    #$63E0
  4649  BF 63 C8          STX    >$63C8
L_464C:
  464C  BE 63 C8          LDX    >$63C8
  464F  30 88 20          LEAX   <32,X
  4652  BF 63 C8          STX    >$63C8
  4655  E6 84             LDB    ,X
  4657  27 02             BEQ    L_465B
  4659  8D 35             BSR    SUB_4690
L_465B:
  465B  F6 63 A2          LDB    >$63A2
  465E  5C                INCB
  465F  F7 63 A2          STB    >$63A2
  4662  C1 05             CMPB   #$05
  4664  26 E6             BNE    L_464C
  4666  39                RTS

; =====================================================================
; SUB_4667 (13 instructions)
; Uses:  Difficulty $6439 $6479
; Calls: SUB_4683
; =====================================================================
SUB_4667:
  4667  F6 63 80          LDB    >Difficulty
  466A  C1 03             CMPB   #$03
  466C  2B 14             BMI    L_4682
  466E  8D 13             BSR    SUB_4683
  4670  C1 01             CMPB   #$01
  4672  26 0E             BNE    L_4682
  4674  8E 64 39          LDX    #$6439
  4677  C6 02             LDB    #$02
  4679  E7 84             STB    ,X
  467B  8E 64 79          LDX    #$6479
  467E  C6 02             LDB    #$02
  4680  E7 84             STB    ,X
L_4682:
  4682  39                RTS

; =====================================================================
; SUB_4683 (6 instructions)
; Uses:  RandNum FrameCounter
; =====================================================================
SUB_4683:
  4683  F6 60 18          LDB    >RandNum                ; random number
  4686  C4 03             ANDB   #$03
  4688  C1 01             CMPB   #$01
  468A  26 F6             BNE    L_4682
  468C  F6 60 1A          LDB    >FrameCounter           ; decremented every frame
  468F  39                RTS

; =====================================================================
; SUB_4690 (70 instructions)
; Uses:  $63C8 RandNum
; Calls: SUB_476E SUB_4794 SUB_480E SUB_3DE0 SUB_4727 SUB_473E SUB_483D SUB_481E
; =====================================================================
SUB_4690:
  4690  FE 63 C8          LDU    >$63C8
  4693  E6 C8 18          LDB    <24,U
  4696  C1 01             CMPB   #$01
  4698  27 5A             BEQ    L_46F4
  469A  E6 4D             LDB    13,U
  469C  C1 04             CMPB   #$04
  469E  2A 15             BPL    L_46B5
  46A0  E6 C8 19          LDB    <25,U
  46A3  C1 02             CMPB   #$02
  46A5  27 50             BEQ    L_46F7
  46A7  BD 47 6E          JSR    >SUB_476E
  46AA  F6 60 18          LDB    >RandNum                ; random number
  46AD  C4 03             ANDB   #$03
  46AF  26 07             BNE    L_46B8
L_46B1:
  46B1  E6 4D             LDB    13,U
  46B3  27 20             BEQ    L_46D5
L_46B5:
  46B5  BD 47 94          JSR    >SUB_4794
L_46B8:
  46B8  E6 4D             LDB    13,U
  46BA  C1 04             CMPB   #$04
  46BC  2A 47             BPL    L_4705
  46BE  BD 48 0E          JSR    >SUB_480E
  46C1  BD 3D E0          JSR    >SUB_3DE0
  46C4  C1 01             CMPB   #$01
  46C6  27 42             BEQ    L_470A
  46C8  FE 63 C8          LDU    >$63C8
  46CB  E6 4E             LDB    14,U
  46CD  C1 10             CMPB   #$10
  46CF  25 30             BCS    L_4701
  46D1  C1 F0             CMPB   #$F0
  46D3  24 26             BCC    L_46FB
L_46D5:
  46D5  E6 C8 13          LDB    <19,U
  46D8  26 4A             BNE    L_4724
  46DA  C6 11             LDB    #$11
L_46DC:
  46DC  E7 C8 13          STB    <19,U
  46DF  8E 4E A7          LDX    #D_4EA7
  46E2  3A                ABX
  46E3  E6 84             LDB    ,X
  46E5  A6 4E             LDA    14,U
  46E7  97 02             STA    <$02
  46E9  A7 43             STA    3,U
  46EB  A6 4F             LDA    15,U
  46ED  97 03             STA    <$03
  46EF  DB 03             ADDB   <$03
  46F1  E7 45             STB    5,U
  46F3  39                RTS
L_46F4:
  46F4  8D 31             BSR    SUB_4727
  46F6  39                RTS
L_46F7:
  46F7  8D 45             BSR    SUB_473E
  46F9  20 B6             BRA    L_46B1
L_46FB:
  46FB  C6 02             LDB    #$02
L_46FD:
  46FD  E7 4D             STB    13,U
  46FF  20 D4             BRA    L_46D5
L_4701:
  4701  C6 01             LDB    #$01
  4703  20 F8             BRA    L_46FD
L_4705:
  4705  BD 48 3D          JSR    >SUB_483D
  4708  20 CB             BRA    L_46D5
L_470A:
  470A  FE 63 C8          LDU    >$63C8
  470D  E6 4D             LDB    13,U
  470F  C1 01             CMPB   #$01
  4711  26 0B             BNE    L_471E
  4713  C6 02             LDB    #$02
  4715  6A 4E             DEC    14,U
L_4717:
  4717  E7 4D             STB    13,U
  4719  BD 48 1E          JSR    >SUB_481E
  471C  20 B7             BRA    L_46D5
L_471E:
  471E  C6 01             LDB    #$01
  4720  6C 4E             INC    14,U
  4722  20 F3             BRA    L_4717
L_4724:
  4724  5A                DECB
  4725  20 B5             BRA    L_46DC

; =====================================================================
; SUB_4727 (11 instructions)
; Uses:  ScreenNum
; Calls: SUB_48EF SUB_4878 SUB_48BC
; =====================================================================
SUB_4727:
  4727  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  472A  C1 01             CMPB   #$01
  472C  27 08             BEQ    L_4736
  472E  C1 02             CMPB   #$02
  4730  27 08             BEQ    L_473A
  4732  BD 48 EF          JSR    >SUB_48EF
  4735  39                RTS
L_4736:
  4736  BD 48 78          JSR    >SUB_4878
  4739  39                RTS
L_473A:
  473A  BD 48 BC          JSR    >SUB_48BC
  473D  39                RTS

; =====================================================================
; SUB_473E (21 instructions)
; Uses:  MarioY
; Calls: SUB_476E
; =====================================================================
SUB_473E:
  473E  E6 C8 1C          LDB    <28,U
  4741  26 1D             BNE    L_4760
  4743  E6 C8 1D          LDB    <29,U
  4746  C1 01             CMPB   #$01
  4748  26 21             BNE    L_476B
  474A  6F C8 1D          CLR    <29,U
  474D  F6 62 05          LDB    >MarioY
  4750  A6 4F             LDA    15,U
  4752  97 02             STA    <$02
  4754  D0 02             SUBB   <$02
  4756  25 0D             BCS    L_4765
  4758  86 FF             LDA    #$FF
  475A  A7 C8 1C          STA    <28,U
L_475D:
  475D  6F 4D             CLR    13,U
  475F  39                RTS
L_4760:
  4760  6A C8 1C          DEC    <28,U
  4763  26 F8             BNE    L_475D
L_4765:
  4765  6F C8 19          CLR    <25,U
  4768  6F C8 1C          CLR    <28,U
L_476B:
  476B  8D 01             BSR    SUB_476E
  476D  39                RTS

; =====================================================================
; SUB_476E (18 instructions)
; Uses:  RandNum
; =====================================================================
SUB_476E:
  476E  E6 C8 16          LDB    <22,U
  4771  26 17             BNE    L_478A
  4773  86 2B             LDA    #$2B
  4775  A7 C8 16          STA    <22,U
  4778  6F 4D             CLR    13,U
  477A  F6 60 18          LDB    >RandNum                ; random number
  477D  56                RORB
  477E  24 0A             BCC    L_478A
  4780  E6 4D             LDB    13,U
  4782  C1 01             CMPB   #$01
  4784  27 08             BEQ    L_478E
  4786  86 01             LDA    #$01
  4788  A7 4D             STA    13,U
L_478A:
  478A  6A C8 16          DEC    <22,U
  478D  39                RTS
L_478E:
  478E  86 02             LDA    #$02
  4790  A7 4D             STA    13,U
  4792  20 F6             BRA    L_478A

; =====================================================================
; SUB_4794 (52 instructions)
; Uses:  MarioY
; Calls: SUB_4801 SUB_37B6
; =====================================================================
SUB_4794:
  4794  E6 4D             LDB    13,U
  4796  C1 08             CMPB   #$08
  4798  27 31             BEQ    L_47CB
  479A  C1 04             CMPB   #$04
  479C  27 49             BEQ    L_47E7
  479E  8D 61             BSR    SUB_4801
  47A0  E6 4F             LDB    15,U
  47A2  CB 08             ADDB   #$08
  47A4  10 9F 04          STY    <$04
  47A7  D7 04             STB    <$04
  47A9  E6 4E             LDB    14,U
  47AB  8E 00 15          LDX    #$0015
  47AE  9F 02             STX    <$02
  47B0  BD 37 B6          JSR    >SUB_37B6
  47B3  5D                TSTB
  47B4  27 41             BEQ    L_47F7
  47B6  96 02             LDA    <$02
  47B8  A7 C8 1F          STA    <31,U
  47BB  F6 62 05          LDB    >MarioY
  47BE  D7 02             STB    <$02
  47C0  E6 4F             LDB    15,U
  47C2  D0 02             SUBB   <$02
  47C4  24 3A             BCC    L_4800
  47C6  86 04             LDA    #$04
  47C8  A7 4D             STA    13,U
  47CA  39                RTS
L_47CB:
  47CB  E6 4F             LDB    15,U
  47CD  CB 08             ADDB   #$08
  47CF  A6 C8 1F          LDA    <31,U
  47D2  97 02             STA    <$02
  47D4  D1 02             CMPB   <$02
  47D6  26 28             BNE    L_4800
  47D8  6F 4D             CLR    13,U
  47DA  E6 C8 19          LDB    <25,U
  47DD  C1 02             CMPB   #$02
  47DF  26 1F             BNE    L_4800
  47E1  86 01             LDA    #$01
  47E3  A7 C8 1D          STA    <29,U
  47E6  39                RTS
L_47E7:
  47E7  E6 4F             LDB    15,U
  47E9  CB 08             ADDB   #$08
  47EB  A6 C8 1F          LDA    <31,U
  47EE  97 02             STA    <$02
  47F0  D1 02             CMPB   <$02
  47F2  26 0C             BNE    L_4800
  47F4  6F 4D             CLR    13,U
  47F6  39                RTS
L_47F7:
  47F7  96 02             LDA    <$02
  47F9  A7 C8 1F          STA    <31,U
  47FC  86 08             LDA    #$08
  47FE  A7 4D             STA    13,U
L_4800:
  4800  39                RTS

; =====================================================================
; SUB_4801 (7 instructions)
; Calls: RST_RetIfNotScreen
; =====================================================================
SUB_4801:
  4801  C6 07             LDB    #$07
  4803  9D 64             JSR    <RST_RetIfNotScreen
  4805  E6 4F             LDB    15,U
  4807  C1 59             CMPB   #$59
  4809  24 F5             BCC    L_4800
  480B  32 62             LEAS   2,S
  480D  39                RTS

; =====================================================================
; SUB_480E (8 instructions)
; Calls: SUB_4859
; =====================================================================
SUB_480E:
  480E  E6 4D             LDB    13,U
  4810  C1 01             CMPB   #$01
  4812  27 1F             BEQ    L_4833
  4814  E6 47             LDB    7,U
  4816  C4 7F             ANDB   #$7F
  4818  E7 47             STB    7,U
  481A  6A 4E             DEC    14,U
L_481C:
  481C  8D 3B             BSR    SUB_4859

; =====================================================================
; SUB_481E (15 instructions)
; Uses:  ScreenNum
; Calls: SUB_376C
; =====================================================================
SUB_481E:
  481E  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  4821  C1 01             CMPB   #$01
  4823  26 0D             BNE    L_4832
  4825  AE 4E             LDX    14,U
  4827  A6 4D             LDA    13,U
  4829  97 02             STA    <$02
  482B  BD 37 6C          JSR    >SUB_376C
  482E  96 07             LDA    <$07
  4830  A7 4F             STA    15,U
L_4832:
  4832  39                RTS
L_4833:
  4833  E6 47             LDB    7,U
  4835  CA 80             ORB    #$80
  4837  E7 47             STB    7,U
  4839  6C 4E             INC    14,U
  483B  20 DF             BRA    L_481C

; =====================================================================
; SUB_483D (14 instructions)
; Calls: SUB_4859
; =====================================================================
SUB_483D:
  483D  8D 1A             BSR    SUB_4859
  483F  E6 4D             LDB    13,U
  4841  C1 08             CMPB   #$08
  4843  26 11             BNE    L_4856
  4845  E6 C8 14          LDB    <20,U
  4848  26 08             BNE    L_4852
  484A  86 02             LDA    #$02
  484C  A7 C8 14          STA    <20,U
  484F  6A 4F             DEC    15,U
  4851  39                RTS
L_4852:
  4852  6A C8 14          DEC    <20,U
  4855  39                RTS
L_4856:
  4856  6C 4F             INC    15,U
  4858  39                RTS

; =====================================================================
; SUB_4859 (15 instructions)
; =====================================================================
SUB_4859:
  4859  E6 C8 15          LDB    <21,U
  485C  26 16             BNE    L_4874
  485E  86 02             LDA    #$02
  4860  A7 C8 15          STA    <21,U
  4863  6C 47             INC    7,U
  4865  E6 47             LDB    7,U
  4867  C4 0F             ANDB   #$0F
  4869  C1 0F             CMPB   #$0F
  486B  26 0A             BNE    L_4877
  486D  E6 47             LDB    7,U
  486F  C8 02             EORB   #$02
  4871  E7 47             STB    7,U
  4873  39                RTS
L_4874:
  4874  6A C8 15          DEC    <21,U
L_4877:
  4877  39                RTS

; =====================================================================
; SUB_4878 (30 instructions)
; =====================================================================
SUB_4878:
  4878  E6 C8 1A          LDB    <26,U
  487B  A6 C8 1B          LDA    <27,U
  487E  1F 01             TFR    D,X
  4880  8C 00 00          CMPX   #$0000
  4883  26 07             BNE    L_488C
  4885  8E 4E B9          LDX    #D_4EB9
  4888  86 26             LDA    #$26
  488A  A7 43             STA    3,U
L_488C:
  488C  6C 43             INC    3,U
L_488E:
  488E  E6 84             LDB    ,X
  4890  C1 AA             CMPB   #$AA
  4892  27 0D             BEQ    L_48A1
  4894  E7 45             STB    5,U
  4896  30 01             LEAX   1,X
  4898  1F 10             TFR    X,D
  489A  E7 C8 1A          STB    <26,U
  489D  A7 C8 1B          STA    <27,U
  48A0  39                RTS
L_48A1:
  48A1  5F                CLRB
  48A2  E7 C8 13          STB    <19,U
  48A5  E7 C8 18          STB    <24,U
  48A8  E7 4D             STB    13,U
  48AA  E7 C8 1C          STB    <28,U
  48AD  E6 43             LDB    3,U
  48AF  E7 4E             STB    14,U
  48B1  E6 45             LDB    5,U
  48B3  E7 4F             STB    15,U
  48B5  6F C8 1A          CLR    <26,U
  48B8  6F C8 1B          CLR    <27,U
  48BB  39                RTS

; =====================================================================
; SUB_48BC (22 instructions)
; Uses:  MarioX
; =====================================================================
SUB_48BC:
  48BC  E6 C8 1A          LDB    <26,U
  48BF  A6 C8 1B          LDA    <27,U
  48C2  1F 01             TFR    D,X
  48C4  8C 00 00          CMPX   #$0000
  48C7  26 0F             BNE    L_48D8
  48C9  8E 4E D9          LDX    #D_4ED9
  48CC  F6 62 03          LDB    >MarioX
  48CF  2A 11             BPL    L_48E2
  48D1  CC 01 7E          LDD    #$017E
  48D4  A7 4D             STA    13,U
  48D6  E7 43             STB    3,U
L_48D8:
  48D8  E6 4D             LDB    13,U
  48DA  C1 01             CMPB   #$01
  48DC  26 0D             BNE    L_48EB
  48DE  6C 43             INC    3,U
  48E0  20 AC             BRA    L_488E
L_48E2:
  48E2  CC 02 80          LDD    #$0280
  48E5  A7 4D             STA    13,U
  48E7  E7 43             STB    3,U
  48E9  20 ED             BRA    L_48D8
L_48EB:
  48EB  6A 43             DEC    3,U
  48ED  20 9F             BRA    L_488E

; =====================================================================
; SUB_48EF (23 instructions)
; Uses:  ScreenNum MarioX RandTimer
; =====================================================================
SUB_48EF:
  48EF  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  48F2  C1 03             CMPB   #$03
  48F4  27 25             BEQ    L_491B
  48F6  F6 62 03          LDB    >MarioX
  48F9  2B 21             BMI    L_491C
  48FB  8E 4E F1          LDX    #D_4EF1
L_48FE:
  48FE  0F 02             CLR    <$02
  4900  F6 60 19          LDB    >RandTimer
  4903  C4 06             ANDB   #$06
  4905  3A                ABX
  4906  E6 80             LDB    ,X+
  4908  E7 43             STB    3,U
  490A  E7 4E             STB    14,U
  490C  E6 84             LDB    ,X
  490E  E7 45             STB    5,U
  4910  E7 4F             STB    15,U
  4912  5F                CLRB
  4913  E7 4D             STB    13,U
  4915  E7 C8 18          STB    <24,U
  4918  E7 C8 1C          STB    <28,U
L_491B:
  491B  39                RTS
L_491C:
  491C  8E 4F 01          LDX    #D_4F01
  491F  20 DD             BRA    L_48FE

; =====================================================================
; SUB_4921 (17 instructions)
; Uses:  Fireballs $69D0
; =====================================================================
SUB_4921:
  4921  8E 64 00          LDX    #Fireballs
  4924  10 8E 69 D0       LDY    #$69D0
  4928  86 05             LDA    #$05
L_492A:
  492A  E6 84             LDB    ,X
  492C  27 0E             BEQ    L_493C
  492E  E6 03             LDB    3,X
  4930  C4 FE             ANDB   #$FE
  4932  E7 A4             STB    ,Y
  4934  E6 07             LDB    7,X
  4936  E7 21             STB    1,Y
  4938  E6 05             LDB    5,X
  493A  E7 23             STB    3,Y
L_493C:
  493C  31 24             LEAY   4,Y
  493E  30 88 20          LEAX   <32,X
  4941  4A                DECA
  4942  26 E6             BNE    L_492A
  4944  39                RTS

; =====================================================================
; Arcade data tables (translated from the Z80 ROM): score values,
; default high scores, strings, stage layouts, animation tables.
; =====================================================================
TBL_ScoreValues:
  4945  00 00 00 00 01    FCB    $00,$00,$00,$00,$01,$00,$00,$02
  494D  00 00 03 00 00    FCB    $00,$00,$03,$00,$00,$04,$00,$00
  4955  05 00 00 06 00    FCB    $05,$00,$00,$06,$00,$00,$07,$00
  495D  00 08 00 00 09    FCB    $00,$08,$00,$00,$09,$00,$00,$00
  4965  00 00 10 00 00    FCB    $00,$00,$10,$00,$00,$20,$00,$00
  496D  30 00 00 40 00    FCB    $30,$00,$00,$40,$00,$00,$50,$00
  4975  00 60 00 00 70    FCB    $00,$60,$00,$00,$70,$00,$00,$80
  497D  00 00 90 00       FCB    $00,$00,$90,$00
DefaultHiScores:
  4981  77 94 01 23 24    FCB    $77,$94,$01,$23,$24,$10,$10,$00
  4989  00 07 06 05 00    FCB    $00,$07,$06,$05,$00
  498E  10 x14            FILL   $10,14
  499C  3F 00 50 76 00    FCB    $3F,$00,$50,$76,$00,$76,$F4,$77
  49A4  96 02 1E 14 10    FCB    $96,$02,$1E,$14,$10,$10,$00,$00
  49AC  06 01 00 00       FCB    $06,$01,$00,$00
  49B0  10 x14            FILL   $10,14
  49BE  3F 00 00 61 00    FCB    $3F,$00,$00,$61,$00,$76,$F6,$77
  49C6  98 03 22 14 10    FCB    $98,$03,$22,$14,$10,$10,$00,$00
  49CE  05 09 05 00       FCB    $05,$09,$05,$00
  49D2  10 x14            FILL   $10,14
  49E0  3F 00 50 59 00    FCB    $3F,$00,$50,$59,$00,$76,$F8,$77
  49E8  9A 04 24 18 10    FCB    $9A,$04,$24,$18,$10,$10,$00,$00
  49F0  05 00 05 00       FCB    $05,$00,$05,$00
  49F4  10 x14            FILL   $10,14
  4A02  3F 00 50 50 00    FCB    $3F,$00,$50,$50,$00,$76,$FA,$77
  4A0A  9C 05 24 18 10    FCB    $9C,$05,$24,$18,$10,$10,$00,$00
  4A12  04 03 00 00       FCB    $04,$03,$00,$00
  4A16  10 x14            FILL   $10,14
  4A24  3F 00 00 43 00    FCB    $3F,$00,$00,$43,$00,$76,$FC
D_4A2B:
  4A2B  3B 5D 4B 5D 5B    FCB    $3B,$5D,$4B,$5D,$5B,$5D,$6B,$5D
  4A33  7B 5D 8B 5D 9B    FCB    $7B,$5D,$8B,$5D,$9B,$5D,$AB,$5D
  4A3B  BB 5D CB 5D 3B    FCB    $BB,$5D,$CB,$5D,$3B,$6D,$4B,$6D
  4A43  5B 6D 6B 6D 7B    FCB    $5B,$6D,$6B,$6D,$7B,$6D,$8B,$6D
  4A4B  9B 6D AB 6D BB    FCB    $9B,$6D,$AB,$6D,$BB,$6D,$CB,$6D
  4A53  3B 7D 4B 7D 5B    FCB    $3B,$7D,$4B,$7D,$5B,$7D,$6B,$7D
  4A5B  7B 7D 8B 7D 9B    FCB    $7B,$7D,$8B,$7D,$9B,$7D,$AB,$7D
  4A63  BB 7D CB 7D       FCB    $BB,$7D,$CB,$7D

; =====================================================================
; String pointer table for Task3_ShowString.  Entries $14-$18 point
; to the high-score lines in RAM ($6100-$61A8).
; =====================================================================
TBL_Strings:
  4A67  4A A7             FDB    D_4AA7                  ; #00 "GAME  OVER"
  4A69  00 01             FDB    $0001                   ; #01 (unused)
  4A6B  4A B4             FDB    D_4AB4                  ; #02 "PLAYER ~~~"
  4A6D  4A C1             FDB    D_4AC1                  ; #03 "PLAYER ~~~"
  4A6F  4A CE             FDB    D_4ACE                  ; #04 "HIGH SCORE"
  4A71  4A DB             FDB    D_4ADB                  ; #05 "CREDIT    "
  4A73  00 06             FDB    $0006                   ; #06 (unused)
  4A75  4A E8             FDB    D_4AE8                  ; #07 "HOW HIGH CAN YOU GET ~ "
  4A77  00 08             FDB    $0008                   ; #08 (unused)
  4A79  4B 02             FDB    D_4B02                  ; #09 "ONLY 1 PLAYER BUTTON"
  4A7B  4B 19             FDB    D_4B19                  ; #0A "1 OR 2 PLAYERS BUTTON"
  4A7D  00 0B             FDB    $000B                   ; #0B (unused)
  4A7F  4B 31             FDB    D_4B31                  ; #0C "PUSH"
  4A81  4B 38             FDB    D_4B38                  ; #0D "NAME REGISTRATION"
  4A83  4B 4C             FDB    D_4B4C                  ; #0E "NAME:"
  4A85  4B 54             FDB    D_4B54                  ; #0F """"         "
  4A87  4B 63             FDB    D_4B63                  ; #10 "A B C D E F G H I J"
  4A89  4B 79             FDB    D_4B79                  ; #11 "K L M N O P Q R S T"
  4A8B  4B 8F             FDB    D_4B8F                  ; #12 "U V W X Y Z . -~~~~~ "
  4A8D  4B A7             FDB    D_4BA7                  ; #13 "REGI TIME  ~30~ "
  4A8F  61 00             FDB    HiScoreTable            ; #14 (RAM high-score line)
  4A91  61 22             FDB    $6122                   ; #15 (RAM high-score line)
  4A93  61 44             FDB    $6144                   ; #16 (RAM high-score line)
  4A95  61 66             FDB    $6166                   ; #17 (RAM high-score line)
  4A97  61 88             FDB    $6188                   ; #18 (RAM high-score line)
  4A99  4B BA             FDB    D_4BBA                  ; #19 "RANK  SCORE  NAME    "
  4A9B  4B D2             FDB    D_4BD2                  ; #1A "YOUR NAME WAS REGISTERED~"
  4A9D  4B EE             FDB    D_4BEE                  ; #1B "INSERT COIN "
  4A9F  4B FD             FDB    D_4BFD                  ; #1C "  PLAYER    COIN"
  4AA1  00 1D             FDB    $001D                   ; #1D (unused)
  4AA3  4C 10             FDB    D_4C10                  ; #1E "~~ NINTENDO"
  4AA5  4C 1E             FDB    D_4C1E                  ; #1F "1981"
D_4AA7:
  4AA7  76 96             FDB    $7696                   ; string #00 at tile RAM $7696
  4AA9  17 11 1D 15 10    FCB    $17,$11,$1D,$15,$10,$10,$1F,$26,$15,$22,$3F ; "GAME  OVER" +end
D_4AB4:
  4AB4  76 94             FDB    $7694                   ; string #02 at tile RAM $7694
  4AB6  20 1C 11 29 15    FCB    $20,$1C,$11,$29,$15,$22,$10,$30,$32,$31,$3F ; "PLAYER ~~~" +end
D_4AC1:
  4AC1  76 94             FDB    $7694                   ; string #03 at tile RAM $7694
  4AC3  20 1C 11 29 15    FCB    $20,$1C,$11,$29,$15,$22,$10,$30,$33,$31,$3F ; "PLAYER ~~~" +end
D_4ACE:
  4ACE  76 80             FDB    $7680                   ; string #04 at tile RAM $7680
  4AD0  18 19 17 18 10    FCB    $18,$19,$17,$18,$10,$23,$13,$1F,$22,$15,$3F ; "HIGH SCORE" +end
D_4ADB:
  4ADB  75 9F             FDB    $759F                   ; string #05 at tile RAM $759F
  4ADD  13 22 15 14 19    FCB    $13,$22,$15,$14,$19,$24,$10,$10,$10,$10,$3F ; "CREDIT    " +end
D_4AE8:
  4AE8  77 5E             FDB    $775E                   ; string #07 at tile RAM $775E
  4AEA  18 1F 27 10 18    FCB    $18,$1F,$27,$10,$18,$19,$17,$18,$10,$13,$11,$1E ; "HOW HIGH CAN"
  4AF6  10 29 1F 25 10    FCB    $10,$29,$1F,$25,$10,$17,$15,$24,$10,$FB,$10,$3F ; " YOU GET ~ " +end
D_4B02:
  4B02  77 29             FDB    $7729                   ; string #09 at tile RAM $7729
  4B04  1F 1E 1C 29 10    FCB    $1F,$1E,$1C,$29,$10,$01,$10,$20,$1C,$11,$29,$15 ; "ONLY 1 PLAYE"
  4B10  22 10 12 25 24    FCB    $22,$10,$12,$25,$24,$24,$1F,$1E,$3F ; "R BUTTON" +end
D_4B19:
  4B19  77 29             FDB    $7729                   ; string #0A at tile RAM $7729
  4B1B  01 10 1F 22 10    FCB    $01,$10,$1F,$22,$10,$02,$10,$20,$1C,$11,$29,$15 ; "1 OR 2 PLAYE"
  4B27  22 23 10 12 25    FCB    $22,$23,$10,$12,$25,$24,$24,$1F,$1E,$3F ; "RS BUTTON" +end
D_4B31:
  4B31  76 27             FDB    $7627                   ; string #0C at tile RAM $7627
  4B33  20 25 23 18 3F    FCB    $20,$25,$23,$18,$3F     ; "PUSH" +end
D_4B38:
  4B38  77 06             FDB    $7706                   ; string #0D at tile RAM $7706
  4B3A  1E 11 1D 15 10    FCB    $1E,$11,$1D,$15,$10,$22,$15,$17,$19,$23,$24,$22 ; "NAME REGISTR"
  4B46  11 24 19 1F 1E    FCB    $11,$24,$19,$1F,$1E,$3F ; "ATION" +end
D_4B4C:
  4B4C  76 88             FDB    $7688                   ; string #0E at tile RAM $7688
  4B4E  1E 11 1D 15 2E    FCB    $1E,$11,$1D,$15,$2E,$3F ; "NAME:" +end
D_4B54:
  4B54  75 E9             FDB    $75E9                   ; string #0F at tile RAM $75E9
  4B56  2D 2D 2D 10 10    FCB    $2D,$2D,$2D,$10,$10,$10,$10,$10,$10,$10,$10,$10 ; """"         "
  4B62  3F                FCB    $3F                     ; "" +end
D_4B63:
  4B63  77 0B             FDB    $770B                   ; string #10 at tile RAM $770B
  4B65  11 10 12 10 13    FCB    $11,$10,$12,$10,$13,$10,$14,$10,$15,$10,$16,$10 ; "A B C D E F "
  4B71  17 10 18 10 19    FCB    $17,$10,$18,$10,$19,$10,$1A,$3F ; "G H I J" +end
D_4B79:
  4B79  77 0D             FDB    $770D                   ; string #11 at tile RAM $770D
  4B7B  1B 10 1C 10 1D    FCB    $1B,$10,$1C,$10,$1D,$10,$1E,$10,$1F,$10,$20,$10 ; "K L M N O P "
  4B87  21 10 22 10 23    FCB    $21,$10,$22,$10,$23,$10,$24,$3F ; "Q R S T" +end
D_4B8F:
  4B8F  77 0F             FDB    $770F                   ; string #12 at tile RAM $770F
  4B91  25 10 26 10 27    FCB    $25,$10,$26,$10,$27,$10,$28,$10,$29,$10,$2A,$10 ; "U V W X Y Z "
  4B9D  2B 10 2C 44 45    FCB    $2B,$10,$2C,$44,$45,$46,$47,$48,$10,$3F ; ". -~~~~~ " +end
D_4BA7:
  4BA7  76 F2             FDB    $76F2                   ; string #13 at tile RAM $76F2
  4BA9  22 15 17 19 10    FCB    $22,$15,$17,$19,$10,$24,$19,$1D,$15,$10,$10,$30 ; "REGI TIME  ~"
  4BB5  03 00 31 10 3F    FCB    $03,$00,$31,$10,$3F     ; "30~ " +end
D_4BBA:
  4BBA  77 92             FDB    $7792                   ; string #19 at tile RAM $7792
  4BBC  22 11 1E 1B 10    FCB    $22,$11,$1E,$1B,$10,$10,$23,$13,$1F,$22,$15,$10 ; "RANK  SCORE "
  4BC8  10 1E 11 1D 15    FCB    $10,$1E,$11,$1D,$15,$10,$10,$10,$10,$3F ; " NAME    " +end
D_4BD2:
  4BD2  77 72             FDB    $7772                   ; string #1A at tile RAM $7772
  4BD4  29 1F 25 22 10    FCB    $29,$1F,$25,$22,$10,$1E,$11,$1D,$15,$10,$27,$11 ; "YOUR NAME WA"
  4BE0  23 10 22 15 17    FCB    $23,$10,$22,$15,$17,$19,$23,$24,$15,$22,$15,$14 ; "S REGISTERED"
  4BEC  42 3F             FCB    $42,$3F                 ; "~" +end
D_4BEE:
  4BEE  76 A7             FDB    $76A7                   ; string #1B at tile RAM $76A7
  4BF0  19 1E 23 15 22    FCB    $19,$1E,$23,$15,$22,$24,$10,$13,$1F,$19,$1E,$10 ; "INSERT COIN "
  4BFC  3F                FCB    $3F                     ; "" +end
D_4BFD:
  4BFD  77 0A             FDB    $770A                   ; string #1C at tile RAM $770A
  4BFF  10 10 20 1C 11    FCB    $10,$10,$20,$1C,$11,$29,$15,$22,$10,$10,$10,$10 ; "  PLAYER    "
  4C0B  13 1F 19 1E 3F    FCB    $13,$1F,$19,$1E,$3F     ; "COIN" +end
D_4C10:
  4C10  76 FC             FDB    $76FC                   ; string #1E at tile RAM $76FC
  4C12  49 4A 10 1E 19    FCB    $49,$4A,$10,$1E,$19,$1E,$24,$15,$1E,$14,$1F,$3F ; "~~ NINTENDO" +end
D_4C1E:
  4C1E  75 7C             FDB    $757C                   ; string #1F at tile RAM $757C
  4C20  01 09 08 01 3F    FCB    $01,$09,$08,$01,$3F     ; "1981" +end
D_4C25:
  4C25  02 97 38 68 38    FCB    $02,$97,$38,$68,$38,$02,$DF,$54
  4C2D  10 54 02 EF 6D    FCB    $10,$54,$02,$EF,$6D,$20,$6D,$02
  4C35  DF 8E 10 8E 02    FCB    $DF,$8E,$10,$8E,$02,$EF,$AF,$20
  4C3D  AF 02 DF D0 10    FCB    $AF,$02,$DF,$D0,$10,$D0,$02,$EF
  4C45  F1 10 F1 00 53    FCB    $F1,$10,$F1,$00,$53,$18,$53,$54
  4C4D  00 63 18 63 54    FCB    $00,$63,$18,$63,$54,$00,$93,$38
  4C55  93 54 00 83 54    FCB    $93,$54,$00,$83,$54,$83,$F1,$00
  4C5D  93 54 93 F1 AA    FCB    $93,$54,$93,$F1,$AA
D_4C62:
  4C62  8D 7D 8C 6F 00    FCB    $8D,$7D,$8C,$6F,$00,$7C,$6E,$00
  4C6A  7C 6D 00 7C 6C    FCB    $7C,$6D,$00,$7C,$6C,$00,$7C,$8F
  4C72  7F 8E             FCB    $7F,$8E
D_4C74:
  4C74  50 34 08 3C 00    FCB    $50,$34,$08,$3C,$00,$35,$08,$3C
  4C7C  53 32 08 40 63    FCB    $53,$32,$08,$40,$63,$33,$08,$40
  4C84  00 70 08 48 53    FCB    $00,$70,$08,$48,$53,$36,$08,$50
  4C8C  63 37 08 50 6B    FCB    $63,$37,$08,$50,$6B,$31,$08,$41
  4C94  00 70 08 48 6A    FCB    $00,$70,$08,$48,$6A,$14,$0A,$48
D_4C9C:
  4C9C  FD FD FD FD FD    FCB    $FD,$FD,$FD,$FD,$FD,$FD,$FD,$FE
  4CA4  FE FE FE FE FE    FCB    $FE,$FE,$FE,$FE,$FE,$FF,$FF,$FF
  4CAC  FF 00 00 01 01    FCB    $FF,$00,$00,$01,$01,$01,$7F
D_4CB3:
  4CB3  FF FF FF FF FF    FCB    $FF,$FF,$FF,$FF,$FF,$00,$FF,$00
  4CBB  00 01 00 01 01    FCB    $00,$01,$00,$01,$01,$01,$01,$01
  4CC3  7F                FCB    $7F
D_4CC4:
  4CC4  04 7F F0 10 F0    FCB    $04,$7F,$F0,$10,$F0,$02,$DF,$F2
  4CCC  70 F8 02 6F F8    FCB    $70,$F8,$02,$6F,$F8,$10,$F8,$AA
  4CD4  04 DF D0 90 D0    FCB    $04,$DF,$D0,$90,$D0,$02,$DF,$DC
  4CDC  20 D1 AA FF FF    FCB    $20,$D1,$AA,$FF,$FF,$FF,$FF,$FF
  4CE4  04 DF A8 20 A8    FCB    $04,$DF,$A8,$20,$A8,$04,$5F,$B0
  4CEC  20 B0 02 DF B0    FCB    $20,$B0,$02,$DF,$B0,$20,$BB,$AA
  4CF4  04 DF 88 30 88    FCB    $04,$DF,$88,$30,$88,$04,$DF,$90
  4CFC  B0 90 02 DF 9A    FCB    $B0,$90,$02,$DF,$9A,$20,$8F,$AA
  4D04  04 BF 68 20 68    FCB    $04,$BF,$68,$20,$68,$04,$3F,$70
  4D0C  20 70 02 DF 6E    FCB    $20,$70,$02,$DF,$6E,$20,$79,$AA
D_4D14:
  4D14  02 DF 58 A0 55    FCB    $02,$DF,$58,$A0,$55,$AA
D_4D1A:
  4D1A  00 70 08 44 2B    FCB    $00,$70,$08,$44,$2B,$AC,$08,$4C
  4D22  3B AE 08 4C 3B    FCB    $3B,$AE,$08,$4C,$3B,$AF,$08,$3C
  4D2A  4B B0 07 3C 4B    FCB    $4B,$B0,$07,$3C,$4B,$AD,$08,$4C
  4D32  00 70 08 44 00    FCB    $00,$70,$08,$44,$00,$70,$08,$44
  4D3A  00 70 08 44 00    FCB    $00,$70,$08,$44,$00,$70,$0A,$44
  4D42  47 27 08 4C 2F    FCB    $47,$27,$08,$4C,$2F,$A7,$08,$4C
  4D4A  3B 25 08 4C 00    FCB    $3B,$25,$08,$4C,$00,$70,$08,$44
  4D52  3B 23 07 3C 4B    FCB    $3B,$23,$07,$3C,$4B,$2A,$08,$3C
  4D5A  4B 2B 08 4C 2B    FCB    $4B,$2B,$08,$4C,$2B,$AA,$08,$3C
  4D62  2B AB 08 4C 00    FCB    $2B,$AB,$08,$4C,$00,$70,$0A,$44
  4D6A  00 70 08 44 4B    FCB    $00,$70,$08,$44,$4B,$2C,$08,$4C
  4D72  3B 2E 08 4C 3B    FCB    $3B,$2E,$08,$4C,$3B,$2F,$08,$3C
  4D7A  2B 30 07 3C 2B    FCB    $2B,$30,$07,$3C,$2B,$2D,$08,$4C
  4D82  00 70 08 44 00    FCB    $00,$70,$08,$44,$00,$70,$08,$44
  4D8A  00 70 08 44 00    FCB    $00,$70,$08,$44,$00,$70,$0A,$44
D_4D92:
  4D92  FD FD FD FE FE    FCB    $FD,$FD,$FD,$FE,$FE,$FE,$FE,$FF
  4D9A  FF 00 FF 00 00    FCB    $FF,$00,$FF,$00,$00,$01,$00,$01
  4DA2  01 02 02 02 02    FCB    $01,$02,$02,$02,$02,$03,$03,$03
  4DAA  7F                FCB    $7F
D_4DAB:
  4DAB  1E 4E BB 4C D8    FCB    $1E,$4E,$BB,$4C,$D8,$4E,$59,$4E
  4DB3  7F                FCB    $7F
D_4DB4:
  4DB4  BB 4D 7F          FCB    $BB,$4D,$7F
D_4DB7:
  4DB7  47 27 08 50 2F    FCB    $47,$27,$08,$50,$2F,$A7,$08,$50
  4DBF  3B 25 08 50 00    FCB    $3B,$25,$08,$50,$00,$70,$08,$48
  4DC7  3B 23 07 40 47    FCB    $3B,$23,$07,$40,$47,$A9,$08,$44
  4DCF  00 70 08 48 2F    FCB    $00,$70,$08,$48,$2F,$29,$08,$44
  4DD7  00 70 08 48 00    FCB    $00,$70,$08,$48,$00,$70,$0A,$48
  4DDF  6F 10 09 23 6F    FCB    $6F,$10,$09,$23,$6F,$11,$0A,$33
D_4DE7:
  4DE7  47 27 08 50 2D    FCB    $47,$27,$08,$50,$2D,$26,$08,$50
  4DEF  3B 25 08 50 00    FCB    $3B,$25,$08,$50,$00,$70,$08,$48
  4DF7  3B 24 07 40 4B    FCB    $3B,$24,$07,$40,$4B,$28,$08,$40
  4DFF  00 70 08 48 2F    FCB    $00,$70,$08,$48,$2F,$29,$08,$44
  4E07  00 70 08 48 00    FCB    $00,$70,$08,$48,$00,$70,$0A,$48
D_4E0F:
  4E0F  49 A6 08 50 2F    FCB    $49,$A6,$08,$50,$2F,$A7,$08,$50
  4E17  3B 25 08 50 00    FCB    $3B,$25,$08,$50,$00,$70,$08,$48
  4E1F  3B 24 07 40 47    FCB    $3B,$24,$07,$40,$47,$A9,$08,$44
  4E27  00 70 08 48 2B    FCB    $00,$70,$08,$48,$2B,$A8,$08,$40
  4E2F  00 70 08 48 00    FCB    $00,$70,$08,$48,$00,$70,$0A,$48
D_4E37:
  4E37  73 E7 08 60 8B    FCB    $73,$E7,$08,$60,$8B,$67,$08,$60
  4E3F  7F 65 08 60 00    FCB    $7F,$65,$08,$60,$00,$70,$08,$68
  4E47  7F 64 07 70 75    FCB    $7F,$64,$07,$70,$75,$69,$08,$6C
  4E4F  00 70 08 68 89    FCB    $00,$70,$08,$68,$89,$E9,$08,$6C
  4E57  00 70 08 68 00    FCB    $00,$70,$08,$68,$00,$70,$0A,$68
D_4E5F:
  4E5F  05 AF F0 50 F0    FCB    $05,$AF,$F0,$50,$F0,$AA
D_4E65:
  4E65  05 AF E8 50 E8    FCB    $05,$AF,$E8,$50,$E8,$AA
D_4E6B:
  4E6B  05 AF E0 50 E0    FCB    $05,$AF,$E0,$50,$E0,$AA
D_4E71:
  4E71  05 AF D8 50 D8    FCB    $05,$AF,$D8,$50,$D8,$AA
D_4E77:
  4E77  05 B7 58 48 58    FCB    $05,$B7,$58,$48,$58,$AA

; =====================================================================
; TBL_StageOrder: screen sequence per level (1 girders, 2 conveyors,
; 3 elevators, 4 rivets); Setup copies the Japanese order over it.
; =====================================================================
TBL_StageOrder:
  4E7D  01 04 01 03 04    FCB    $01,$04,$01,$03,$04,$01,$02,$03
  4E85  04 01 02 01 03    FCB    $04,$01,$02,$01,$03,$04
D_4E8B:
  4E8B  01 02 01 03 01    FCB    $01,$02,$01,$03,$01,$04,$7F,$01
  4E93  02 03 04 01 02    FCB    $02,$03,$04,$01,$02,$03,$04,$01
  4E9B  02 03 04 7F 7F    FCB    $02,$03,$04,$7F,$7F,$01,$02,$03
  4EA3  04 7F 7F 7F       FCB    $04,$7F,$7F,$7F
D_4EA7:
  4EA7  FF 00 FF FF       FCB    $FF,$00,$FF,$FF
  4EAB  FE x11            FILL   $FE,11
  4EB6  FF FF 00          FCB    $FF,$FF,$00
D_4EB9:
  4EB9  E8 E5 E3 E2 E1    FCB    $E8,$E5,$E3,$E2,$E1,$E0,$DF,$DE
  4EC1  DD DD DC DC DC    FCB    $DD,$DD,$DC,$DC,$DC,$DC,$DC,$DC
  4EC9  DD DD DE DF E0    FCB    $DD,$DD,$DE,$DF,$E0,$E1,$E2,$E3
  4ED1  E4 E5 E7 E9 EB    FCB    $E4,$E5,$E7,$E9,$EB,$ED,$F0,$AA
D_4ED9:
  4ED9  80 7B 78 76 74    FCB    $80,$7B,$78,$76,$74,$73,$72,$71
  4EE1  70 70 6F 6F 6F    FCB    $70,$70,$6F,$6F,$6F,$70,$70,$71
  4EE9  72 73 74 75 76    FCB    $72,$73,$74,$75,$76,$77,$78,$AA
D_4EF1:
  4EF1  EE F0 DB A0 E6    FCB    $EE,$F0,$DB,$A0,$E6,$C8,$D6,$78
  4EF9  EB F0 DB A0 E6    FCB    $EB,$F0,$DB,$A0,$E6,$C8,$E6,$C8
D_4F01:
  4F01  1B C8 23 A0 2B    FCB    $1B,$C8,$23,$A0,$2B,$78,$12,$F0
  4F09  1B C8 23 A0 12    FCB    $1B,$C8,$23,$A0,$12,$F0,$1B,$C8
D_4F11:
  4F11  02 97 38 68 38    FCB    $02,$97,$38,$68,$38,$02,$9F,$54
  4F19  10 54 02 DF 58    FCB    $10,$54,$02,$DF,$58,$A0,$55,$02
  4F21  EF 6D 20 79 02    FCB    $EF,$6D,$20,$79,$02,$DF,$9A,$10
  4F29  8E 02 EF AF 20    FCB    $8E,$02,$EF,$AF,$20,$BB,$02,$DF
  4F31  DC 10 D0 02 FF    FCB    $DC,$10,$D0,$02,$FF,$F0,$80,$F7
  4F39  02 7F F8 00 F8    FCB    $02,$7F,$F8,$00,$F8,$00,$CB,$57
  4F41  CB 6F 00 CB 99    FCB    $CB,$6F,$00,$CB,$99,$CB,$B1,$00
  4F49  CB DB CB F3 00    FCB    $CB,$DB,$CB,$F3,$00,$63,$18,$63
  4F51  54 01 63 D5 63    FCB    $54,$01,$63,$D5,$63,$F8,$00,$33
  4F59  78 33 90 00 33    FCB    $78,$33,$90,$00,$33,$BA,$33,$D2
  4F61  00 53 18 53 54    FCB    $00,$53,$18,$53,$54,$01,$53,$92
  4F69  53 B8 00 5B 76    FCB    $53,$B8,$00,$5B,$76,$5B,$92,$00
  4F71  73 B6 73 D6 00    FCB    $73,$B6,$73,$D6,$00,$83,$95,$83
  4F79  B5 00 93 38 93    FCB    $B5,$00,$93,$38,$93,$54,$01,$BB
  4F81  70 BB 98 01 6B    FCB    $70,$BB,$98,$01,$6B,$54,$6B,$75
  4F89  AA                FCB    $AA
D_4F8A:
  4F8A  06 8F 90 70 90    FCB    $06,$8F,$90,$70,$90,$06,$8F,$98
  4F92  70 98 06 8F A0    FCB    $70,$98,$06,$8F,$A0,$70,$A0,$00
  4F9A  63 18 63 58 00    FCB    $63,$18,$63,$58,$00,$63,$80,$63
  4FA2  A8 00 63 D0 63    FCB    $A8,$00,$63,$D0,$63,$F8,$00,$53
  4FAA  18 53 58 00 53    FCB    $18,$53,$58,$00,$53,$A8,$53,$D0
  4FB2  00 9B 80 9B A8    FCB    $00,$9B,$80,$9B,$A8,$00,$9B,$D0
  4FBA  9B F8 01 23 58    FCB    $9B,$F8,$01,$23,$58,$23,$80,$01
  4FC2  DB 58 DB 80 00    FCB    $DB,$58,$DB,$80,$00,$2B,$80,$2B
  4FCA  A8 00 D3 80 D3    FCB    $A8,$00,$D3,$80,$D3,$A8,$00,$A3
  4FD2  A8 A3 D0 00 2B    FCB    $A8,$A3,$D0,$00,$2B,$D0,$2B,$F8
  4FDA  00 D3 D0 D3 F8    FCB    $00,$D3,$D0,$D3,$F8,$00,$93,$38
  4FE2  93 58 02 97 38    FCB    $93,$58,$02,$97,$38,$68,$38,$03
  4FEA  EF 58 10 58 03    FCB    $EF,$58,$10,$58,$03,$F7,$80,$88
  4FF2  80 03 77 80 08    FCB    $80,$03,$77,$80,$08,$80,$02,$A7
  4FFA  A8 50 A8 02 E7    FCB    $A8,$50,$A8,$02,$E7,$A8,$B8,$A8
  5002  02 3F A8 18 A8    FCB    $02,$3F,$A8,$18,$A8,$03,$EF,$D0
  500A  10 D0 02 EF F8    FCB    $10,$D0,$02,$EF,$F8,$10,$F8,$AA
D_5012:
  5012  00 63 18 63 58    FCB    $00,$63,$18,$63,$58,$00,$63,$88
  501A  63 D0 00 53 18    FCB    $63,$D0,$00,$53,$18,$53,$58,$00
  5022  53 88 53 D0 00    FCB    $53,$88,$53,$D0,$00,$E3,$68,$E3
  502A  90 00 E3 B8 E3    FCB    $90,$00,$E3,$B8,$E3,$D0,$00,$CB
  5032  90 CB B0 00 B3    FCB    $90,$CB,$B0,$00,$B3,$58,$B3,$78
  503A  00 9B 80 9B A0    FCB    $00,$9B,$80,$9B,$A0,$00,$93,$38
  5042  93 58 00 23 88    FCB    $93,$58,$00,$23,$88,$23,$C0,$00
  504A  1B C0 1B E8 02    FCB    $1B,$C0,$1B,$E8,$02,$97,$38,$68
  5052  38 02 B7 58 10    FCB    $38,$02,$B7,$58,$10,$58,$02,$EF
  505A  68 E0 68 02 D7    FCB    $68,$E0,$68,$02,$D7,$70,$C8,$70
  5062  02 BF 78 B0 78    FCB    $02,$BF,$78,$B0,$78,$02,$A7,$80
  506A  90 80 02 67 88    FCB    $90,$80,$02,$67,$88,$48,$88,$02
  5072  27 88 10 88 02    FCB    $27,$88,$10,$88,$02,$EF,$90,$C8
  507A  90 02 A7 A0 98    FCB    $90,$02,$A7,$A0,$98,$A0,$02,$BF
  5082  A8 B0 A8 02 D7    FCB    $A8,$B0,$A8,$02,$D7,$B0,$C8,$B0
  508A  02 EF B8 E0 B8    FCB    $02,$EF,$B8,$E0,$B8,$02,$27,$C0
  5092  10 C0 02 EF D0    FCB    $10,$C0,$02,$EF,$D0,$D8,$D0,$02
  509A  67 D0 50 D0 02    FCB    $67,$D0,$50,$D0,$02,$CF,$D8,$C0
  50A2  D8 02 B7 E0 A8    FCB    $D8,$02,$B7,$E0,$A8,$E0,$02,$9F
  50AA  E8 88 E8 02 27    FCB    $E8,$88,$E8,$02,$27,$E8,$10,$E8
  50B2  02 EF F8 10 F8    FCB    $02,$EF,$F8,$10,$F8,$AA
D_50B8:
  50B8  00 7B 80 7B A8    FCB    $00,$7B,$80,$7B,$A8,$00,$7B,$D0
  50C0  7B F8 00 33 58    FCB    $7B,$F8,$00,$33,$58,$33,$80,$00
  50C8  53 58 53 80 00    FCB    $53,$58,$53,$80,$00,$AB,$58,$AB
  50D0  80 00 CB 58 CB    FCB    $80,$00,$CB,$58,$CB,$80,$00,$2B
  50D8  80 2B A8 00 D3    FCB    $80,$2B,$A8,$00,$D3,$80,$D3,$A8
  50E0  00 23 A8 23 D0    FCB    $00,$23,$A8,$23,$D0,$00,$5B,$A8
  50E8  5B D0 00 A3 A8    FCB    $5B,$D0,$00,$A3,$A8,$A3,$D0,$00
  50F0  DB A8 DB D0 00    FCB    $DB,$A8,$DB,$D0,$00,$1B,$D0,$1B
  50F8  F8 00 E3 D0 E3    FCB    $F8,$00,$E3,$D0,$E3,$F8,$05,$B7
  5100  30 48 30 05 CF    FCB    $30,$48,$30,$05,$CF,$58,$30,$58
  5108  05 D7 80 28 80    FCB    $05,$D7,$80,$28,$80,$05,$DF,$A8
  5110  20 A8 05 E7 D0    FCB    $20,$A8,$05,$E7,$D0,$18,$D0,$05
  5118  EF F8 10 F8 AA    FCB    $EF,$F8,$10,$F8,$AA
D_511D:
  511D  10 82 85 8B 10    FCB    $10,$82,$85,$8B,$10,$85,$80,$8B
  5125  10 87 85 8B 81    FCB    $10,$87,$85,$8B,$81,$80,$80,$8B
  512D  81 82 85 8B 81    FCB    $81,$82,$85,$8B,$81,$85,$80,$8B
D_5135:
  5135  05 77 88 01 77    FCB    $05,$77,$88,$01,$77,$68,$01,$77
  513D  6C 03 77 49 05    FCB    $6C,$03,$77,$49,$05,$77,$08,$01
  5145  76 E8 01 76 EC    FCB    $76,$E8,$01,$76,$EC,$05,$76,$C8
  514D  05 76 88 02 76    FCB    $05,$76,$88,$02,$76,$69,$02,$76
  5155  4A 05 76 28 05    FCB    $4A,$05,$76,$28,$05,$75,$E8,$01
  515D  75 CA 03 75 A9    FCB    $75,$CA,$03,$75,$A9,$01,$75,$88
  5165  01 75 8C 05 75    FCB    $01,$75,$8C,$05,$75,$48,$01,$75
  516D  28 01 75 2A 01    FCB    $28,$01,$75,$2A,$01,$75,$2C,$01
  5175  75 08 01 75 0A    FCB    $75,$08,$01,$75,$0A,$01,$75,$0C
  517D  03 74 C8 03 74    FCB    $03,$74,$C8,$03,$74,$AA,$03,$74
  5185  88 05 77 2F 05    FCB    $88,$05,$77,$2F,$05,$77,$0F,$02
  518D  76 F0 02 76 CF    FCB    $76,$F0,$02,$76,$CF,$02,$76,$D2
  5195  05 76 8F 05 76    FCB    $05,$76,$8F,$05,$76,$6F,$01,$76
  519D  4F 01 76 53 05    FCB    $4F,$01,$76,$53,$05,$76,$2F,$05
  51A5  75 EF 02 75 D0    FCB    $75,$EF,$02,$75,$D0,$02,$75,$B1
  51AD  05 75 8F 03 75    FCB    $05,$75,$8F,$03,$75,$50,$05,$75
  51B5  2F 01 75 0F 01    FCB    $2F,$01,$75,$0F,$01,$75,$13,$01
  51BD  74 EF 01 74 F1    FCB    $74,$EF,$01,$74,$F1,$01,$74,$F3
  51C5  02 74 D1 00       FCB    $02,$74,$D1,$00
D_51C9:
  51C9  00 00 23 68 01    FCB    $00,$00,$23,$68,$01,$11,$00,$00
  51D1  00 10 DB 68 01    FCB    $00,$10,$DB,$68,$01,$40,$00,$00
  51D9  08                FCB    $08
  51DA  01 x9             FILL   $01,9
  51E3  00 00 00 00 00    FCB    $00,$00,$00,$00,$00,$00,$80,$01
  51EB  C0 FF 01 FF FF    FCB    $C0,$FF,$01,$FF,$FF,$34,$4D,$AB
  51F3  67 00 69 80 1A    FCB    $67,$00,$69,$80,$1A,$01
  51F9  00 x8             FILL   $00,8
  5201  04 00 10 00 00    FCB    $04,$00,$10,$00,$00,$00,$00,$00
D_5209:
  5209  1E 18 0B 4B 14    FCB    $1E,$18,$0B,$4B,$14,$18,$0B,$4B
  5211  1E 18 0B 3B 14    FCB    $1E,$18,$0B,$3B,$14,$18,$0B,$3B
D_5219:
  5219  3D 01 03 02       FCB    $3D,$01,$03,$02
D_521D:
  521D  4D 01 04 01       FCB    $4D,$01,$04,$01
D_5221:
  5221  27 70 01 E0 00    FCB    $27,$70,$01,$E0,$00,$00
D_5227:
  5227  7F 40 01 78 02    FCB    $7F,$40,$01,$78,$02,$00
D_522D:
  522D  27 49 0C F0       FCB    $27,$49,$0C,$F0
D_5231:
  5231  7F 49 0C 88       FCB    $7F,$49,$0C,$88
D_5235:
  5235  1E 07 03 09       FCB    $1E,$07,$03,$09
D_5239:
  5239  24 64 BB C0       FCB    $24,$64,$BB,$C0
D_523D:
  523D  23 8D 7B B4       FCB    $23,$8D,$7B,$B4
D_5241:
  5241  1B 8C 7C 64       FCB    $1B,$8C,$7C,$64
D_5245:
  5245  4B 0E 04 02       FCB    $4B,$0E,$04,$02
D_5249:
  5249  23 46 03 68 DB    FCB    $23,$46,$03,$68,$DB,$46,$03,$68
D_5251:
  5251  17 50 00 5C E7    FCB    $17,$50,$00,$5C,$E7,$D0,$00,$5C
  5259  8C 50 00 84 71    FCB    $8C,$50,$00,$84,$71,$D0,$00,$84
  5261  17 50 00 D4 E7    FCB    $17,$50,$00,$D4,$E7,$D0,$00,$D4
D_5269:
  5269  53 73 0A A0 8B    FCB    $53,$73,$0A,$A0,$8B,$74,$0A,$F0
  5271  DB 75 0A A0       FCB    $DB,$75,$0A,$A0
D_5275:
  5275  5B 73 0A C8 E3    FCB    $5B,$73,$0A,$C8,$E3,$74,$0A,$60
  527D  1B 75 0A 80       FCB    $1B,$75,$0A,$80
D_5281:
  5281  DB 73 0A C8 93    FCB    $DB,$73,$0A,$C8,$93,$74,$0A,$F0
  5289  33 75 0A 50       FCB    $33,$75,$0A,$50
D_528D:
  528D  44 03 08 04       FCB    $44,$03,$08,$04
D_5291:
  5291  37 F4 37 C0 37    FCB    $37,$F4,$37,$C0,$37,$8C,$77,$70
  5299  77 A4 77 D8       FCB    $77,$A4,$77,$D8

; =====================================================================
; JumpOverCheck: while Mario jumps, count barrels ($6700) and
; fireballs ($6400) inside the box under him (HitboxScan) -> $6060.
; Returns B = score index (0 none, 3 one, 7 several) for Task0_AddScore.
; Per-screen variants through TBL_JumpOverStage.
; =====================================================================
JumpOverCheck:
  529D  F6 62 27          LDB    >ScreenNum              ; 1 girders, 2 conveyors, 3 elevators, 4 rivets
  52A0  34 10             PSHS   X
  52A2  9D 47             JSR    <RST_JumpTable
TBL_JumpOverStage:
  52A4  11 14             FDB    ColdStart
  52A6  52 B0             FDB    L_52B0
  52A8  3C F3             FDB    L_3CF3
  52AA  3D 23             FDB    L_3D23
  52AC  3D 44             FDB    L_3D44
  52AE  11 14             FDB    ColdStart
L_52B0:
  52B0  35 10             PULS   X
  52B2  5F                CLRB
  52B3  F7 60 60          STB    >$6060
  52B6  86 0A             LDA    #$0A
  52B8  97 02             STA    <$02
  52BA  10 8E 00 20       LDY    #$0020
  52BE  CE 67 00          LDU    #Barrels
  52C1  8D 1B             BSR    HitboxScan
  52C3  86 05             LDA    #$05
  52C5  97 02             STA    <$02
  52C7  CE 64 00          LDU    #Fireballs
  52CA  8D 12             BSR    HitboxScan
  52CC  F6 60 60          LDB    >$6060
  52CF  27 0C             BEQ    L_52DD
  52D1  C1 01             CMPB   #$01
  52D3  27 08             BEQ    L_52DD
  52D5  C1 03             CMPB   #$03
  52D7  C6 03             LDB    #$03
  52D9  25 02             BCS    L_52DD
  52DB  C6 07             LDB    #$07
L_52DD:
  52DD  39                RTS

; =====================================================================
; HitboxScan: count objects (stride 32 at U) overlapping the box
; around (IX+3, <$03) into $6060.
; =====================================================================
HitboxScan:
  52DE  9F 06             STX    <$06
  52E0  9E 0A             LDX    <$0A
L_52E2:
  52E2  A6 C4             LDA    ,U
  52E4  84 01             ANDA   #$01
  52E6  27 22             BEQ    L_530A
  52E8  D6 03             LDB    <$03
  52EA  E0 45             SUBB   5,U
  52EC  24 01             BCC    L_52EF
  52EE  50                NEGB
L_52EF:
  52EF  5C                INCB
  52F0  D0 07             SUBB   <$07
  52F2  25 04             BCS    L_52F8
  52F4  E0 4A             SUBB   10,U
  52F6  24 12             BCC    L_530A
L_52F8:
  52F8  E6 03             LDB    3,X
  52FA  E0 43             SUBB   3,U
  52FC  24 01             BCC    L_52FF
  52FE  50                NEGB
L_52FF:
  52FF  D0 06             SUBB   <$06
  5301  25 04             BCS    L_5307
  5303  E0 49             SUBB   9,U
  5305  24 03             BCC    L_530A
L_5307:
  5307  7C 60 60          INC    >$6060
L_530A:
  530A  33 C8 20          LEAU   <32,U
  530D  0A 02             DEC    <$02
  530F  26 D1             BNE    L_52E2
  5311  9E 06             LDX    <$06
  5313  39                RTS
L_5314:
  5314  8D 03             BSR    SUB_5319
  5316  7E 1F 7E          JMP    >L_1F7E

; =====================================================================
; SUB_5319 (13 instructions)
; Uses:  $776C $748C
; Calls: RST_RetIfNotScreen
; =====================================================================
SUB_5319:
  5319  C6 02             LDB    #$02
  531B  9D 64             JSR    <RST_RetIfNotScreen
  531D  86 02             LDA    #$02
  531F  97 02             STA    <$02
  5321  8E 77 6C          LDX    #$776C
L_5324:
  5324  86 10             LDA    #$10
  5326  A7 81             STA    ,X++
  5328  86 C0             LDA    #$C0
  532A  A7 84             STA    ,X
  532C  8E 74 8C          LDX    #$748C
  532F  0A 02             DEC    <$02
  5331  26 F1             BNE    L_5324
  5333  39                RTS

; =====================================================================
; SUB_5334 (4 instructions)
; Uses:  $694D
; =====================================================================
SUB_5334:
  5334  8E 69 4D          LDX    #$694D
  5337  86 03             LDA    #$03
  5339  A7 81             STA    ,X++
  533B  39                RTS

; =====================================================================
; Z80_EXX: swap BC/HL/DE (<$02, X, Y) with the alternate set kept in
; the direct page; <$0C toggles which set is active.
; =====================================================================
Z80_EXX:
  533C  03 0C             COM    <$0C
  533E  2B 13             BMI    L_5353
  5340  9F 17             STX    <$17
  5342  9E 02             LDX    <$02
  5344  9F 13             STX    <$13
  5346  9E 0D             LDX    <$0D
  5348  9F 02             STX    <$02
  534A  9E 11             LDX    <$11
  534C  10 9F 15          STY    <$15
  534F  10 9E 0F          LDY    <$0F
  5352  39                RTS
L_5353:
  5353  9F 11             STX    <$11
  5355  9E 02             LDX    <$02
  5357  9F 0D             STX    <$0D
  5359  9E 13             LDX    <$13
  535B  9F 02             STX    <$02
  535D  9E 17             LDX    <$17
  535F  10 9F 0F          STY    <$0F
  5362  10 9E 15          LDY    <$15
  5365  39                RTS

; =====================================================================
; PaletteBankUpdate: arcade palette bank $7D86/$7D87 -> copy the
; matching colour tables from page $29 to $0F00 and select the tile
; colour table used by DrawDirtyTiles (patches LDY at L_54C6).
; =====================================================================
PaletteBankUpdate:
  5366  34 36             PSHS   A,B,X,Y
  5368  86 29             LDA    #$29
  536A  B7 FF A1          STA    >MMU_T0_P1              ; MMU_T0_P1 - Task0 page1 ($2000-$3FFF)
  536D  FC 7D 86          LDD    >PaletteBank0           ; palette bank bit 0
  5370  54                LSRB
  5371  49                ROLA
  5372  84 03             ANDA   #$03
  5374  B7 53 8B          STA    >L_538A+1
  5377  27 11             BEQ    L_538A
  5379  8B 27             ADDA   #$27
  537B  5F                CLRB
  537C  1F 02             TFR    D,Y
  537E  8E 0F 00          LDX    #$0F00
L_5381:
  5381  EC A1             LDD    ,Y++
  5383  ED 81             STD    ,X++
  5385  8C 10 00          CMPX   #$1000
  5388  25 F7             BCS    L_5381
L_538A:
  538A  CC 00 00          LDD    #$0000                  ; SMC: operand patched by $5374
  538D  46                RORA
  538E  56                RORB
  538F  46                RORA
  5390  56                RORB
  5391  8E 53 9F          LDX    #TBL_TilePalette
  5394  3A                ABX
  5395  BF 54 C8          STX    >L_54C6+2
  5398  86 39             LDA    #$39
  539A  B7 FF A1          STA    >MMU_T0_P1              ; MMU_T0_P1 - Task0 page1 ($2000-$3FFF)
  539D  35 B6             PULS   A,B,X,Y,PC
TBL_TilePalette:
  539F  20 50 20 10 20    FCB    $20,$50,$20,$10,$20,$00,$20,$00
  53A7  20 40 20 20 20    FCB    $20,$40,$20,$20,$20,$20,$20,$10
  53AF  20 x9             FILL   $20,9
  53B8  50 20 20 20 50    FCB    $50,$20,$20,$20,$50,$20,$10,$20
  53C0  50                FCB    $50
  53C1  20 x9             FILL   $20,9
  53CA  10 20 50 20 10    FCB    $10,$20,$50,$20,$10,$20,$30,$20
  53D2  10 20 20 20 30    FCB    $10,$20,$20,$20,$30,$20,$50,$20
  53DA  30 20 50 20 20    FCB    $30,$20,$50,$20,$20,$20,$20,$20
  53E2  10 20 00 20 00    FCB    $10,$20,$00,$20,$00,$20,$40
  53E9  20 x55            FILL   $20,55
  5420  00 20 10 20 00    FCB    $00,$20,$10,$20,$00,$20,$00,$20
  5428  40 20 00 20 00    FCB    $40,$20,$00,$20,$00,$20,$00,$20
  5430  00 20 00 20 00    FCB    $00,$20,$00,$20,$00,$20,$00,$20
  5438  00 20 00 20 00    FCB    $00,$20,$00,$20,$00,$20,$00,$20
  5440  00 20 00 20 00    FCB    $00,$20,$00,$20,$00,$20,$00,$20
  5448  00 20 00 20 00    FCB    $00,$20,$00,$20,$00,$20,$00,$20
  5450  00 20 00 20 00    FCB    $00,$20,$00,$20,$00,$20,$00,$20
  5458  00 20 00 20 00    FCB    $00,$20,$00,$20,$00,$20,$00
D_545F:
  545F  20 30 20 10 20    FCB    $20,$30,$20,$10,$20,$00,$20,$00
  5467  20 40 20 30 20    FCB    $20,$40,$20,$30,$20,$30,$20,$30
  546F  20 30 20 30 20    FCB    $20,$30,$20,$30,$20,$30,$20,$30
  5477  20 30 20 30 20    FCB    $20,$30,$20,$30,$20,$30,$20,$30
  547F  20 30 20 30 20    FCB    $20,$30,$20,$30,$20,$30,$20,$30
  5487  20 30 20 30 20    FCB    $20,$30,$20,$30,$20,$30,$20,$30
  548F  20 30 20 30 20    FCB    $20,$30,$20,$30,$20,$30,$20,$30
  5497  20 30 20 30 20    FCB    $20,$30,$20,$30,$20,$30,$20,$30

; =====================================================================
; DrawDirtyTiles - tile RAM emulation.  Compares arcade tile RAM
; $7400-$77FF with the copy kept in each video buffer ($F89C...).  For
; every changed tile: tile $10 = blank -> fast clear with STU; other tiles
; -> compiled tile routine (page:address from the table at $0C00 + 4*tile)
; called with JSR ,U while that page is mapped at $2000.
; =====================================================================
DrawDirtyTiles:
  549F  10 8E 74 20       LDY    #$7420
  54A3  8E F8 9C          LDX    #$F89C
  54A6  7E 55 60          JMP    >L_5560
L_54A9:
  54A9  34 30             PSHS   X,Y
  54AB  86 03             LDA    #$03
  54AD  58                ASLB
  54AE  49                ROLA
  54AF  58                ASLB
  54B0  49                ROLA
  54B1  1F 03             TFR    D,U
  54B3  A6 C4             LDA    ,U
  54B5  EE 41             LDU    1,U
  54B7  B7 FF A1          STA    >MMU_T0_P1              ; MMU_T0_P1 - Task0 page1 ($2000-$3FFF)
  54BA  1F 20             TFR    Y,D
  54BC  84 03             ANDA   #$03
  54BE  58                ASLB
  54BF  49                ROLA
  54C0  1F 01             TFR    D,X
  54C2  AE 84             LDX    ,X
  54C4  C4 3E             ANDB   #$3E
L_54C6:
  54C6  10 8E 53 9F       LDY    #TBL_TilePalette        ; SMC: operand patched by $1740,$197B,$5395
  54CA  10 AE A5          LDY    B,Y
  54CD  C6 FF             LDB    #$FF
  54CF  AD C4             JSR    ,U
  54D1  35 30             PULS   X,Y
  54D3  E6 A0             LDB    ,Y+
  54D5  E1 80             CMPB   ,X+
  54D7  26 40             BNE    L_5519
L_54D9:
  54D9  EC A1             LDD    ,Y++
  54DB  10 A3 81          CMPD   ,X++
  54DE  27 F9             BEQ    L_54D9
  54E0  A1 1E             CMPA   -2,X
  54E2  27 35             BEQ    L_5519
  54E4  31 3F             LEAY   -1,Y
  54E6  30 1F             LEAX   -1,X
  54E8  E6 3F             LDB    -1,Y
  54EA  20 2D             BRA    L_5519
L_54EC:
  54EC  C1 4B             CMPB   #$4B
  54EE  25 B9             BCS    L_54A9
  54F0  BF 55 11          STX    >L_5510+1
  54F3  86 03             LDA    #$03
  54F5  58                ASLB
  54F6  49                ROLA
  54F7  58                ASLB
  54F8  49                ROLA
  54F9  1F 03             TFR    D,U
  54FB  A6 C4             LDA    ,U
  54FD  EE 41             LDU    1,U
  54FF  B7 FF A1          STA    >MMU_T0_P1              ; MMU_T0_P1 - Task0 page1 ($2000-$3FFF)
  5502  1F 20             TFR    Y,D
  5504  84 03             ANDA   #$03
  5506  58                ASLB
  5507  49                ROLA
  5508  1F 01             TFR    D,X
  550A  AE 84             LDX    ,X
  550C  C6 FF             LDB    #$FF
  550E  AD C4             JSR    ,U
L_5510:
  5510  8E 00 00          LDX    #$0000                  ; SMC: operand patched by $54F0
  5513  E6 A0             LDB    ,Y+
  5515  E1 80             CMPB   ,X+
  5517  27 4D             BEQ    L_5566
L_5519:
  5519  8C FC 5C          CMPX   #$FC5C
  551C  22 5B             BHI    L_5579
  551E  E7 1F             STB    -1,X
  5520  C1 10             CMPB   #$10
  5522  26 C8             BNE    L_54EC
  5524  BF 55 5E          STX    >L_555D+1
  5527  1F 20             TFR    Y,D
  5529  84 03             ANDA   #$03
  552B  58                ASLB
  552C  49                ROLA
  552D  1F 01             TFR    D,X
  552F  AE 84             LDX    ,X
  5531  C6 FF             LDB    #$FF
  5533  CE 00 00          LDU    #$0000
  5536  EF 88 80          STU    <-128,X
  5539  EF 88 82          STU    <-126,X
  553C  EF 84             STU    ,X
  553E  EF 02             STU    2,X
  5540  3A                ABX
  5541  EF 88 81          STU    <-127,X
  5544  EF 88 83          STU    <-125,X
  5547  EF 01             STU    1,X
  5549  EF 03             STU    3,X
  554B  3A                ABX
  554C  EF 88 82          STU    <-126,X
  554F  EF 88 84          STU    <-124,X
  5552  EF 02             STU    2,X
  5554  EF 04             STU    4,X
  5556  3A                ABX
  5557  EF 88 83          STU    <-125,X
  555A  EF 88 85          STU    <-123,X
L_555D:
  555D  8E 00 00          LDX    #$0000                  ; SMC: operand patched by $5524
L_5560:
  5560  E6 A0             LDB    ,Y+
  5562  E1 80             CMPB   ,X+
  5564  26 B3             BNE    L_5519
L_5566:
  5566  EC A1             LDD    ,Y++
  5568  10 A3 81          CMPD   ,X++
  556B  27 F9             BEQ    L_5566
  556D  A1 1E             CMPA   -2,X
  556F  27 A8             BEQ    L_5519
  5571  31 3F             LEAY   -1,Y
  5573  30 1F             LEAX   -1,X
  5575  E6 3F             LDB    -1,Y
  5577  20 A0             BRA    L_5519
L_5579:
  5579  86 39             LDA    #$39
  557B  B7 FF A1          STA    >MMU_T0_P1              ; MMU_T0_P1 - Task0 page1 ($2000-$3FFF)
  557E  39                RTS

; =====================================================================
; EraseMovedSprites: compare the arcade sprite list ($6900, 4 bytes:
; X, code, attr, Y) with the copy from the last frame; mark the tiles
; under moved sprites dirty ($4F) so DrawDirtyTiles repaints them.
; =====================================================================
EraseMovedSprites:
  557F  8E 68 FC          LDX    #$68FC
  5582  10 8E FC 82       LDY    #$FC82
  5586  20 2E             BRA    L_55B6
L_5588:
  5588  A6 A4             LDA    ,Y
  558A  27 49             BEQ    L_55D5
  558C  CB 07             ADDB   #$07
  558E  43                COMA
  558F  44                LSRA
  5590  44                LSRA
  5591  44                LSRA
  5592  44                LSRA
  5593  56                RORB
  5594  44                LSRA
  5595  56                RORB
  5596  44                LSRA
  5597  56                RORB
  5598  EF A4             STU    ,Y
  559A  C3 F8 7A          ADDD   #$F87A
  559D  1F 03             TFR    D,U
  559F  A6 03             LDA    3,X
  55A1  A7 23             STA    3,Y
  55A3  CC 4F 4F          LDD    #$4F4F
  55A6  ED C4             STD    ,U
  55A8  A7 42             STA    2,U
  55AA  ED C8 E0          STD    <-32,U
  55AD  A7 C8 E2          STA    <-30,U
  55B0  ED C8 20          STD    <32,U
  55B3  A7 C8 22          STA    <34,U
L_55B6:
  55B6  31 24             LEAY   4,Y
  55B8  30 04             LEAX   4,X
  55BA  EE 84             LDU    ,X
  55BC  11 A3 A4          CMPU   ,Y
  55BF  27 08             BEQ    L_55C9
  55C1  E6 23             LDB    3,Y
  55C3  8C 6A 34          CMPX   #$6A34
  55C6  25 07             BCS    L_55CF
  55C8  39                RTS
L_55C9:
  55C9  E6 23             LDB    3,Y
  55CB  E1 03             CMPB   3,X
  55CD  27 E7             BEQ    L_55B6
L_55CF:
  55CF  A6 21             LDA    1,Y
  55D1  81 70             CMPA   #$70
  55D3  26 B3             BNE    L_5588
L_55D5:
  55D5  EF A4             STU    ,Y
  55D7  A6 03             LDA    3,X
  55D9  A7 23             STA    3,Y
  55DB  20 D9             BRA    L_55B6

; =====================================================================
; DrawSprites: for each active sprite compute the screen address
; (Y*$70 + X, buffer at $8000) and call its compiled sprite routine
; (page:address from the table at $0800 + 4*code, mapped at $2000).
; =====================================================================
DrawSprites:
  55DD  10 8E 68 FC       LDY    #$68FC
  55E1  CC FF 00          LDD    #$FF00
  55E4  FD 6A 34          STD    >$6A34
  55E7  20 2B             BRA    L_5614
L_55E9:
  55E9  E6 23             LDB    3,Y
  55EB  86 70             LDA    #$70
  55ED  3D                MUL
  55EE  C3 7D 30          ADDD   #$7D30
  55F1  C4 80             ANDB   #$80
  55F3  1F 01             TFR    D,X
  55F5  E6 A4             LDB    ,Y
  55F7  CB 10             ADDB   #$10
  55F9  C1 1E             CMPB   #$1E
  55FB  25 17             BCS    L_5614
  55FD  C0 16             SUBB   #$16
  55FF  54                LSRB
  5600  3A                ABX
  5601  E6 21             LDB    1,Y
  5603  86 02             LDA    #$02
  5605  58                ASLB
  5606  49                ROLA
  5607  58                ASLB
  5608  49                ROLA
  5609  1F 03             TFR    D,U
  560B  A6 C4             LDA    ,U
  560D  EE 41             LDU    1,U
  560F  B7 FF A1          STA    >MMU_T0_P1              ; MMU_T0_P1 - Task0 page1 ($2000-$3FFF)
  5612  AD C4             JSR    ,U
L_5614:
  5614  31 24             LEAY   4,Y
  5616  A6 A4             LDA    ,Y
  5618  27 FA             BEQ    L_5614
  561A  81 FF             CMPA   #$FF
  561C  26 CB             BNE    L_55E9
  561E  E6 21             LDB    1,Y
  5620  26 C7             BNE    L_55E9
  5622  86 39             LDA    #$39
  5624  B7 FF A1          STA    >MMU_T0_P1              ; MMU_T0_P1 - Task0 page1 ($2000-$3FFF)
  5627  39                RTS

; =====================================================================
; ReadJoystick: read the CoCo joystick through the PIA: the DAC
; ($FF20) is set to thresholds and the comparator ($FF00 bit7) is read
; with the analog mux (CA2/CB2) on each axis -> 4 direction bits + fire
; in JoyNow (previous value in JoyPrev).  Start / coin come from the
; button bits via CoinStartBits.  DAC value is restored afterwards.
; =====================================================================
ReadJoystick:
  5628  1A 40             ORCC   #$40
  562A  B6 FF 20          LDA    >PIA1_DA                ; PIA1_DA
  562D  B7 56 7E          STA    >L_567D+1
  5630  86 36             LDA    #$36
  5632  B7 FF 23          STA    >PIA1_CB                ; PIA1_CB
  5635  CC D8 BC          LDD    #$D8BC
  5638  F7 FF 01          STB    >PIA0_CA                ; PIA0_CA
  563B  B7 FF 20          STA    >PIA1_DA                ; PIA1_DA
  563E  C6 35             LDB    #$35
  5640  F7 FF 03          STB    >PIA0_CB                ; PIA0_CB
  5643  12                NOP
  5644  B6 FF 00          LDA    >PIA0_DA                ; PIA0_DA
  5647  84 01             ANDA   #$01
  5649  F6 FF 00          LDB    >PIA0_DA                ; PIA0_DA
  564C  59                ROLB
  564D  C6 24             LDB    #$24
  564F  F7 FF 20          STB    >PIA1_DA                ; PIA1_DA
  5652  49                ROLA
  5653  30 84             LEAX   ,X
  5655  F6 FF 00          LDB    >PIA0_DA                ; PIA0_DA
  5658  59                ROLB
  5659  C6 B4             LDB    #$B4
  565B  F7 FF 01          STB    >PIA0_CA                ; PIA0_CA
  565E  49                ROLA
  565F  30 0A             LEAX   10,X
  5661  30 16             LEAX   -10,X
  5663  30 84             LEAX   ,X
  5665  0F 1E             CLR    <CoinStartBits
  5667  D6 1C             LDB    <JoyNow
  5669  D7 1B             STB    <JoyPrev
  566B  0A 20             DEC    <VsyncCount
  566D  F6 FF 00          LDB    >PIA0_DA                ; PIA0_DA
  5670  59                ROLB
  5671  C6 D8             LDB    #$D8
  5673  F7 FF 20          STB    >PIA1_DA                ; PIA1_DA
  5676  49                ROLA
  5677  88 0B             EORA   #$0B
  5679  F6 FF 00          LDB    >PIA0_DA                ; PIA0_DA
  567C  59                ROLB
L_567D:
  567D  C6 00             LDB    #$00                    ; SMC: operand patched by $562D
  567F  F7 FF 20          STB    >PIA1_DA                ; PIA1_DA
  5682  49                ROLA
  5683  97 1C             STA    <JoyNow
  5685  C6 3E             LDB    #$3E
  5687  F7 FF 23          STB    >PIA1_CB                ; PIA1_CB
  568A  1C BF             ANDCC  #$BF
  568C  F6 60 01          LDB    >NumCredits             ; credits (BCD)
  568F  26 18             BNE    L_56A9
  5691  F6 60 07          LDB    >AttractFlag            ; 1 = attract / no game
  5694  27 21             BEQ    L_56B7
  5696  96 1B             LDA    <JoyPrev
  5698  84 10             ANDA   #$10
  569A  88 10             EORA   #$10
  569C  27 04             BEQ    L_56A2
  569E  96 1C             LDA    <JoyNow
  56A0  84 10             ANDA   #$10
L_56A2:
  56A2  48                ASLA
  56A3  48                ASLA
  56A4  48                ASLA
  56A5  97 1E             STA    <CoinStartBits
  56A7  20 0E             BRA    L_56B7
L_56A9:
  56A9  D6 1B             LDB    <JoyPrev
  56AB  C4 10             ANDB   #$10
  56AD  26 08             BNE    L_56B7
  56AF  96 1C             LDA    <JoyNow
  56B1  84 10             ANDA   #$10
  56B3  44                LSRA
  56B4  44                LSRA
  56B5  97 1E             STA    <CoinStartBits
L_56B7:
  56B7  39                RTS

; =====================================================================
; FlipDrawPage: show the buffer just drawn (GIME vertical offset)
; and map the next one of pages $30/$34/$3C at $8000-$FEFF.
; =====================================================================
FlipDrawPage:
  56B8  96 23             LDA    <DrawPage
  56BA  48                ASLA
  56BB  48                ASLA
  56BC  B7 FF 9D          STA    >GIME_VOFFLO            ; GIME_VOFFLO - Video offset LSB
  56BF  96 23             LDA    <DrawPage
  56C1  8B 04             ADDA   #$04
  56C3  81 38             CMPA   #$38
  56C5  26 02             BNE    L_56C9
  56C7  8B 04             ADDA   #$04
L_56C9:
  56C9  81 40             CMPA   #$40
  56CB  25 02             BCS    L_56CF
  56CD  86 30             LDA    #$30
L_56CF:
  56CF  97 23             STA    <DrawPage
  56D1  B7 FF A4          STA    >MMU_T0_P4              ; MMU_T0_P4 - Task0 page4 ($8000-$9FFF)
  56D4  4C                INCA
  56D5  B7 FF A5          STA    >MMU_T0_P5              ; MMU_T0_P5 - Task0 page5 ($A000-$BFFF)
  56D8  4C                INCA
  56D9  B7 FF A6          STA    >MMU_T0_P6              ; MMU_T0_P6 - Task0 page6 ($C000-$DFFF)
  56DC  4C                INCA
  56DD  B7 FF A7          STA    >MMU_T0_P7              ; MMU_T0_P7 - Task0 page7 ($E000-$FEFF)
  56E0  39                RTS

; =====================================================================
; SoundDriver: arcade music latch $7C00 -> TBL_MusicSamples (16
; tunes x 8 bytes: page, start, loop); effect latches $7D80 (death),
; $7D04, $7D06, $7D05, $7D01 (jump), $7D02 (boom), $7D00 (walk, 4 random
; variants) -> TBL_SfxSamples (8 bytes: page, start, ..., priority).
; Patches FIRQ_SampleMixer's operands with interrupts masked.
; =====================================================================
SoundDriver:
  56E1  B6 7D 03          LDA    >SfxCoin
  56E4  27 04             BEQ    L_56EA
  56E6  C6 1A             LDB    #$1A
  56E8  20 1D             BRA    L_5707
L_56EA:
  56EA  F6 7C 00          LDB    >MusicLatch             ; music latch (arcade sound CPU)
  56ED  C1 06             CMPB   #$06
  56EF  26 05             BNE    L_56F6
  56F1  F7 7D 06          STB    >Sfx6
  56F4  20 3F             BRA    L_5735
L_56F6:
  56F6  C1 0D             CMPB   #$0D
  56F8  26 05             BNE    L_56FF
  56FA  F7 7D 05          STB    >Sfx5
  56FD  20 36             BRA    L_5735
L_56FF:
  56FF  C1 0A             CMPB   #$0A
  5701  26 04             BNE    L_5707
  5703  D7 2A             STB    <LastMusic
  5705  20 2E             BRA    L_5735
L_5707:
  5707  D1 2A             CMPB   <LastMusic
  5709  27 2A             BEQ    L_5735
  570B  D7 2A             STB    <LastMusic
  570D  8E 58 0F          LDX    #TBL_MusicSamples
  5710  1A 40             ORCC   #$40
  5712  C4 0F             ANDB   #$0F
  5714  27 13             BEQ    L_5729
  5716  58                ASLB
  5717  58                ASLB
  5718  58                ASLB
  5719  3A                ABX
  571A  A6 84             LDA    ,X
  571C  97 2D             STA    <MusicPage
  571E  B7 FF AB          STA    >MMU_T1_P3              ; MMU_T1_P3 - Task1 page3 ($6000-$7FFF)
  5721  EC 01             LDD    1,X
  5723  DD 94             STD    <L_1093+1
  5725  A6 06             LDA    6,X
  5727  97 E2             STA    <L_10E1+1
L_5729:
  5729  EC 03             LDD    3,X
  572B  97 EE             STA    <L_10ED+1
  572D  D7 EA             STB    <L_10E9+1
  572F  A6 05             LDA    5,X
  5731  97 E6             STA    <L_10E5+1
  5733  1C BF             ANDCC  #$BF
L_5735:
  5735  96 2C             LDA    <SfxPriority
  5737  27 03             BEQ    L_573C
  5739  4A                DECA
  573A  97 2C             STA    <SfxPriority
L_573C:
  573C  8E 57 BF          LDX    #TBL_SfxSamples
  573F  B6 7D 80          LDA    >SfxDeath               ; death sound / sound IRQ latch
  5742  27 03             BEQ    L_5747
  5744  5F                CLRB
  5745  20 3E             BRA    L_5785
L_5747:
  5747  B6 7D 04          LDA    >Sfx4
  574A  27 04             BEQ    L_5750
  574C  C6 20             LDB    #$20
  574E  20 35             BRA    L_5785
L_5750:
  5750  B6 7D 06          LDA    >Sfx6
  5753  27 04             BEQ    L_5759
  5755  C6 30             LDB    #$30
  5757  20 2C             BRA    L_5785
L_5759:
  5759  B6 7D 05          LDA    >Sfx5
  575C  27 04             BEQ    L_5762
  575E  C6 28             LDB    #$28
  5760  20 23             BRA    L_5785
L_5762:
  5762  B6 7D 01          LDA    >SfxJump                ; jump sound latch
  5765  27 04             BEQ    L_576B
  5767  C6 08             LDB    #$08
  5769  20 1A             BRA    L_5785
L_576B:
  576B  B6 7D 02          LDA    >SfxBoom                ; boom sound latch
  576E  27 04             BEQ    L_5774
  5770  C6 10             LDB    #$10
  5772  20 11             BRA    L_5785
L_5774:
  5774  B6 7D 00          LDA    >SfxWalk                ; walk sound latch
  5777  27 41             BEQ    L_57BA
  5779  F6 60 18          LDB    >RandNum                ; random number
  577C  86 18             LDA    #$18
  577E  3D                MUL
  577F  84 18             ANDA   #$18
  5781  30 86             LEAX   A,X
  5783  C6 38             LDB    #$38
L_5785:
  5785  D1 2B             CMPB   <LastSfx
  5787  27 30             BEQ    L_57B9
  5789  D7 2B             STB    <LastSfx
  578B  3A                ABX
  578C  A6 07             LDA    7,X
  578E  91 2C             CMPA   <SfxPriority
  5790  25 27             BCS    L_57B9
  5792  97 2C             STA    <SfxPriority
  5794  1A 40             ORCC   #$40
  5796  A6 84             LDA    ,X
  5798  97 2E             STA    <SfxPage
  579A  B7 FF AC          STA    >MMU_T1_P4              ; MMU_T1_P4 - Task1 page4 ($8000-$9FFF)
  579D  EC 01             LDD    1,X
  579F  DD 97             STD    <L_1096+1
  57A1  E6 06             LDB    6,X
  57A3  D7 AE             STB    <L_10AD+1
  57A5  86 BB             LDA    #$BB
  57A7  97 96             STA    <L_1096
  57A9  CC B7 FF          LDD    #$B7FF
  57AC  DD 99             STD    <L_1099
  57AE  CC 20 0A          LDD    #$200A
  57B1  DD 9B             STD    <L_1099+2
  57B3  1C BF             ANDCC  #$BF
  57B5  A6 07             LDA    7,X
  57B7  97 2C             STA    <SfxPriority
L_57B9:
  57B9  39                RTS
L_57BA:
  57BA  C6 FF             LDB    #$FF
  57BC  D7 2B             STB    <LastSfx
  57BE  39                RTS

; =====================================================================
; Effect sample table: page, start address, length/end, ..., priority.
; =====================================================================
TBL_SfxSamples:
  57BF  08 9D A1 06 80    FCB    $08,$9D,$A1,$06,$80,$FF,$06,$AA
  57C7  18 9B D2 18 85    FCB    $18,$9B,$D2,$18,$85,$FF,$18,$1D
  57CF  1A 91 C5 1A 80    FCB    $1A,$91,$C5,$1A,$80,$FF,$1A,$0A
  57D7  26 87 B9 26 80    FCB    $26,$87,$B9,$26,$80,$FF,$26,$06
  57DF  02 8F 43 01 81    FCB    $02,$8F,$43,$01,$81,$FF,$01,$3C
  57E7  1B 97 D2 1B 83    FCB    $1B,$97,$D2,$1B,$83,$FF,$1B,$25
  57EF  23 82 9A 22 80    FCB    $23,$82,$9A,$22,$80,$FF,$22,$3C
  57F7  0F 85 26 0F 80    FCB    $0F,$85,$26,$0F,$80,$FF,$0F,$01
  57FF  0E 8F E3 0E 89    FCB    $0E,$8F,$E3,$0E,$89,$FF,$0E,$01
  5807  00 8F FF 00 89    FCB    $00,$8F,$FF,$00,$89,$FF,$00,$01

; =====================================================================
; Music sample table, 16 tunes x 8 bytes.
; =====================================================================
TBL_MusicSamples:
  580F  2F 7F 00 2F 7F    FCB    $2F,$7F,$00,$2F,$7F,$00,$37,$00
  5817  08 7D AE 0D 7F    FCB    $08,$7D,$AE,$0D,$7F,$00,$0D,$00
  581F  26 68 24 28 78    FCB    $26,$68,$24,$28,$78,$00,$28,$00
  5827  0E 70 E4 0E 70    FCB    $0E,$70,$E4,$0E,$70,$E4,$0E,$00
  582F  0F 65 A7 0F 65    FCB    $0F,$65,$A7,$0F,$65,$A7,$11,$00
  5837  12 60 00 17 7F    FCB    $12,$60,$00,$17,$7F,$00,$17,$00
  583F  28 78 00 28 78    FCB    $28,$78,$00,$28,$78,$00,$28,$00
  5847  02 6F 74 05 7E    FCB    $02,$6F,$74,$05,$7E,$00,$05,$00
  584F  18 7C D3 18 7C    FCB    $18,$7C,$D3,$18,$7C,$D3,$19,$00
  5857  1A 72 2B 1A 72    FCB    $1A,$72,$2B,$1A,$72,$2B,$1A,$00
  585F  2F 78 47 2F 7F    FCB    $2F,$78,$47,$2F,$7F,$00,$2F,$00
  5867  00 70 E3 00 70    FCB    $00,$70,$E3,$00,$70,$E3,$00,$00
  586F  1B 78 D3 21 7D    FCB    $1B,$78,$D3,$21,$7D,$00,$21,$00
  5877  28 78 00 28 78    FCB    $28,$78,$00,$28,$78,$00,$28,$00
  587F  23 62 9B 25 7F    FCB    $23,$62,$9B,$25,$7F,$00,$25,$00
  5887  04 65 8B 05 7E    FCB    $04,$65,$8B,$05,$7E,$00,$05,$00

; =====================================================================
; Setup: CPU to 1.79 MHz (SAM R1), HD6309 detect (CLRD leaves B=$FF on a
; 6809) -> native mode, palette (RGB or CMP per $80EB), disk motor off,
; PIA sound on, level order patch ($80EA), difficulty ($80E9), sound on/off ($80EC:
; unpack samples or silence the mixer), MMU tasks 0/1, GIME timer FIRQ
; (timer $01C8), video 256x225x16, clear the three video buffers,
; build the tile -> screen address table at $0000-$07FF, copy the
; compiled-routine pointer tables from page $29 to $0800-$0FFF.
; =====================================================================
Setup:
  588F  B7 FF D9          STA    >SAM_R1SET              ; SAM R1=1: 1.79 MHz CPU
  5892  C6 FF             LDB    #$FF                    ; 6309 test: CLRD clears B only on an HD6309
  5894  10 4F             FCB    $10,$4F                 ; HD6309: CLRD
  5896  5D                TSTB
  5897  26 03             BNE    L_589C
  5899  11 3D 01          FCB    $11,$3D,$01             ; HD6309: LDMD   #$01 ; 6309 found -> native mode
L_589C:
  589C  CE 5A 98          LDU    #PaletteRGB
  589F  1F 32             TFR    U,Y
  58A1  7A 80 EB          DEC    >CfgPalette             ; CMP monitor? use the second palette set  [BASIC POKE 33003]
  58A4  26 03             BNE    L_58A9
  58A6  33 C8 10          LEAU   <16,U
L_58A9:
  58A9  8E FF B0          LDX    #$FFB0
  58AC  4F                CLRA
L_58AD:
  58AD  E6 C0             LDB    ,U+
  58AF  E7 A0             STB    ,Y+
  58B1  30 01             LEAX   1,X
  58B3  8C FF C0          CMPX   #$FFC0
  58B6  25 F5             BCS    L_58AD
  58B8  B7 FF 9A          STA    >GIME_BORDER            ; border black  [GIME_BORDER - Border color (6-bit palette index)]
  58BB  B7 FF 40          STA    >DSKREG                 ; drive motors off  [disk drive control latch]
  58BE  CC 3F 7F          LDD    #$3F7F                  ; PIA1 CB2 = sound enable, DAC mid-level
  58C1  F7 FF 20          STB    >PIA1_DA                ; PIA1_DA
  58C4  B7 FF 23          STA    >PIA1_CB                ; PIA1_CB
  58C7  7A 80 EA          DEC    >CfgLevelOrder          ; Japan order: copy alt. stage order over TBL_StageOrder  [BASIC POKE 33002]
  58CA  26 0D             BNE    L_58D9
  58CC  8E 4E 7D          LDX    #TBL_StageOrder
  58CF  C6 15             LDB    #$15
L_58D1:
  58D1  A6 88 15          LDA    <21,X
  58D4  A7 80             STA    ,X+
  58D6  5A                DECB
  58D7  26 F8             BNE    L_58D1
L_58D9:
  58D9  7A 80 E9          DEC    >CfgDifficulty          ; hard: patch RNG step and a game-speed operand  [BASIC POKE 33001]
  58DC  26 09             BNE    L_58E7
  58DE  CC 04 05          LDD    #$0405                  ; #4 -> $3581 operand, #5 -> RNG ADDB
  58E1  B7 35 82          STA    >L_3581+1
  58E4  F7 11 06          STB    >L_1105+1
L_58E7:
  58E7  B6 80 E8          LDA    >CfgLivesBonus          ; BASIC POKE 33000
  58EA  84 F0             ANDA   #$F0
  58EC  26 03             BNE    L_58F1
  58EE  B6 80 E8          LDA    >CfgLivesBonus          ; BASIC POKE 33000
L_58F1:
  58F1  84 0F             ANDA   #$0F
  58F3  97 1F             STA    <DipConfig
  58F5  7A 80 EC          DEC    >CfgSound               ; sound off: timer reload 0 = no sample FIRQ  [BASIC POKE 33004]
  58F8  26 07             BNE    L_5901
  58FA  4F                CLRA
  58FB  5F                CLRB
  58FC  FD 59 21          STD    >L_5920+1
  58FF  20 03             BRA    L_5904
L_5901:
  5901  BD 59 EA          JSR    >UnpackSamples
L_5904:
  5904  8E FF B0          LDX    #$FFB0                  ; all 16 palettes black while setting up
  5907  CC 00 10          LDD    #$0010
L_590A:
  590A  A7 80             STA    ,X+
  590C  5A                DECB
  590D  26 FB             BNE    L_590A
  590F  86 08             LDA    #$08                    ; copy MMU task 0 map to task 1
  5911  8E FF A0          LDX    #$FFA0
L_5914:
  5914  E6 80             LDB    ,X+
  5916  E7 07             STB    7,X
  5918  4A                DECA
  5919  26 F9             BNE    L_5914
  591B  DC 2D             LDD    <MusicPage
  591D  FD FF AB          STD    >MMU_T1_P3              ; MMU_T1_P3 - Task1 page3 ($6000-$7FFF)
L_5920:
  5920  CC 01 C8          LDD    #$01C8                  ; GIME timer reload (279 ns ticks: ~7.8 kHz)  [SMC: operand patched by $58FC]
  5923  FD FF 94          STD    >GIME_TMRHI             ; GIME_TMRHI - Timer MSB (12-bit countdown)
  5926  CC 0E 89          LDD    #$0E89                  ; FIRQ vector $FEF4 = JMP <$89 (FIRQ_SampleMixer)
  5929  FD FE F4          STD    >$FEF4
  592C  CC 20 20          LDD    #$2020
  592F  B7 FF 91          STA    >GIME_INIT1             ; GIME_INIT1 - Init 1: timer input, task select
  5932  F7 FF 93          STB    >GIME_FIRQEN            ; GIME_FIRQEN - FIRQ enable: TMR|HBORD|VBORD|EI2-0
  5935  86 5C             LDA    #$5C                    ; MMU on, GIME FIRQ on, constant RAM at $FExx
  5937  B7 FF 90          STA    >GIME_INIT0             ; GIME_INIT0 - Init 0: COCO|MMUEN|IEN|FEN|MC3-0
  593A  CC 80 7A          LDD    #$807A                  ; graphics, 225 lines x 128 bytes = 256x225, 16 colours
  593D  FD FF 98          STD    >GIME_VMODE             ; GIME_VMODE - Video mode: BP|BPI|MOCH|H50|LPR
  5940  CC 00 00          LDD    #$0000
  5943  FD FF 9E          STD    >GIME_HOFFHI            ; GIME_HOFFHI - Horizontal offset MSB
  5946  CC C0 30          LDD    #$C030
  5949  B7 FF 9D          STA    >GIME_VOFFLO            ; GIME_VOFFLO - Video offset LSB
  594C  D7 23             STB    <DrawPage
L_594E:
  594E  BD 56 B8          JSR    >FlipDrawPage
  5951  8E 80 00          LDX    #$8000
  5954  CE 00 00          LDU    #$0000
  5957  CC 39 40          LDD    #$3940
L_595A:
  595A  EF 81             STU    ,X++
  595C  5A                DECB
  595D  26 FB             BNE    L_595A
  595F  4A                DECA
  5960  26 F8             BNE    L_595A
  5962  CE F8 7C          LDU    #$F87C
  5965  CC 10 10          LDD    #$1010
L_5968:
  5968  ED C1             STD    ,U++
  596A  11 83 FC 7C       CMPU   #$FC7C
  596E  25 F8             BCS    L_5968
  5970  CC 95 95          LDD    #$9595
  5973  ED C4             STD    ,U
  5975  CE FC 86          LDU    #$FC86
  5978  CC 00 00          LDD    #$0000
L_597B:
  597B  ED C1             STD    ,U++
  597D  11 83 FD FE       CMPU   #$FDFE
  5981  25 F8             BCS    L_597B
  5983  CC 95 95          LDD    #$9595
  5986  ED C4             STD    ,U
  5988  96 23             LDA    <DrawPage
  598A  81 30             CMPA   #$30
  598C  26 C0             BNE    L_594E
  598E  CE 5A 98          LDU    #PaletteRGB
  5991  8E FF B0          LDX    #$FFB0
L_5994:
  5994  EC C1             LDD    ,U++
  5996  ED 81             STD    ,X++
  5998  8C FF C0          CMPX   #$FFC0
  599B  25 F7             BCS    L_5994
  599D  8E 74 00          LDX    #TileRAM
  59A0  10 8E 00 00       LDY    #$0000
L_59A4:
  59A4  1F 10             TFR    X,D
  59A6  83 00 01          SUBD   #$0001
  59A9  F7 59 B4          STB    >L_59B3+1
  59AC  44                LSRA
  59AD  56                RORB
  59AE  44                LSRA
  59AF  56                RORB
  59B0  53                COMB
  59B1  C4 F8             ANDB   #$F8
L_59B3:
  59B3  86 00             LDA    #$00                    ; SMC: operand patched by $59A9
  59B5  84 1F             ANDA   #$1F
  59B7  B7 59 BE          STA    >L_59BD+1
  59BA  48                ASLA
  59BB  48                ASLA
  59BC  48                ASLA
L_59BD:
  59BD  80 00             SUBA   #$00                    ; SMC: operand patched by $59B7
  59BF  44                LSRA
  59C0  56                RORB
  59C1  8A 80             ORA    #$80
  59C3  C3 00 80          ADDD   #$0080
  59C6  ED A1             STD    ,Y++
  59C8  30 01             LEAX   1,X
  59CA  8C 78 00          CMPX   #$7800
  59CD  26 D5             BNE    L_59A4
  59CF  86 29             LDA    #$29
  59D1  B7 FF A1          STA    >MMU_T0_P1              ; MMU_T0_P1 - Task0 page1 ($2000-$3FFF)
  59D4  8E 08 00          LDX    #$0800
  59D7  10 8E 20 00       LDY    #$2000
L_59DB:
  59DB  EC A1             LDD    ,Y++
  59DD  ED 81             STD    ,X++
  59DF  8C 10 00          CMPX   #$1000
  59E2  25 F7             BCS    L_59DB
  59E4  86 39             LDA    #$39
  59E6  B7 FF A1          STA    >MMU_T0_P1              ; MMU_T0_P1 - Task0 page1 ($2000-$3FFF)
  59E9  39                RTS

; =====================================================================
; UnpackSamples: 1-bit delta-modulation decoder.  Each input bit
; moves the output up/down by a step that grows on repeats and shrinks on
; reversals (CVSD-like); 4 samples per byte, output clipped to 7 bits.
; Source $B800-$BFFF/$A000-$BFFF in pages $1E.., output 8K pages at
; $8000.  The border flashes while it runs ('DECOMPRESSING DATA').
; =====================================================================
UnpackSamples:
  59EA  CE B8 00          LDU    #$B800
L_59ED:
  59ED  8E 80 00          LDX    #$8000
  59F0  DC 27             LDD    <SndSrcPage
  59F2  FD FF A4          STD    >MMU_T0_P4              ; MMU_T0_P4 - Task0 page4 ($8000-$9FFF)
L_59F5:
  59F5  86 04             LDA    #$04
  59F7  97 29             STA    <BitCount
  59F9  A6 C0             LDA    ,U+
L_59FB:
  59FB  C6 80             LDB    #$80                    ; SMC: operand patched by L_5A46
  59FD  49                ROLA
  59FE  24 10             BCC    L_5A10
  5A00  DB 26             ADDB   <DeltaStep
  5A02  0F 25             CLR    <DeltaLo
  5A04  0D 24             TST    <DeltaHi
  5A06  26 16             BNE    L_5A1E
  5A08  D7 24             STB    <DeltaHi
  5A0A  0A 26             DEC    <DeltaStep
  5A0C  26 12             BNE    L_5A20
  5A0E  20 0E             BRA    L_5A1E
L_5A10:
  5A10  D0 26             SUBB   <DeltaStep
  5A12  0F 24             CLR    <DeltaHi
  5A14  0D 25             TST    <DeltaLo
  5A16  26 06             BNE    L_5A1E
  5A18  D7 25             STB    <DeltaLo
  5A1A  0A 26             DEC    <DeltaStep
  5A1C  26 02             BNE    L_5A20
L_5A1E:
  5A1E  0C 26             INC    <DeltaStep
L_5A20:
  5A20  F7 5A 4C          STB    >L_5A4B+1
  5A23  49                ROLA
  5A24  24 10             BCC    L_5A36
  5A26  DB 26             ADDB   <DeltaStep
  5A28  0F 25             CLR    <DeltaLo
  5A2A  0D 24             TST    <DeltaHi
  5A2C  26 16             BNE    L_5A44
  5A2E  D7 24             STB    <DeltaHi
  5A30  0A 26             DEC    <DeltaStep
  5A32  26 12             BNE    L_5A46
  5A34  20 0E             BRA    L_5A44
L_5A36:
  5A36  D0 26             SUBB   <DeltaStep
  5A38  0F 24             CLR    <DeltaHi
  5A3A  0D 25             TST    <DeltaLo
  5A3C  26 06             BNE    L_5A44
  5A3E  D7 25             STB    <DeltaLo
  5A40  0A 26             DEC    <DeltaStep
  5A42  26 02             BNE    L_5A46
L_5A44:
  5A44  0C 26             INC    <DeltaStep
L_5A46:
  5A46  F7 59 FC          STB    >L_59FB+1
  5A49  54                LSRB
  5A4A  54                LSRB
L_5A4B:
  5A4B  CB 80             ADDB   #$80                    ; SMC: operand patched by L_5A20
  5A4D  56                RORB
  5A4E  C0 2E             SUBB   #$2E
  5A50  24 01             BCC    L_5A53
  5A52  5F                CLRB
L_5A53:
  5A53  58                ASLB
  5A54  2A 02             BPL    L_5A58
  5A56  C6 7F             LDB    #$7F
L_5A58:
  5A58  E7 80             STB    ,X+
  5A5A  F7 FF 9A          STB    >GIME_BORDER            ; GIME_BORDER - Border color (6-bit palette index)
  5A5D  0A 29             DEC    <BitCount
  5A5F  26 9A             BNE    L_59FB
  5A61  8C A0 00          CMPX   #$A000
  5A64  25 8F             BCS    L_59F5
  5A66  0C 27             INC    <SndSrcPage
  5A68  96 27             LDA    <SndSrcPage
  5A6A  81 29             CMPA   #$29
  5A6C  27 10             BEQ    L_5A7E
  5A6E  11 83 C0 00       CMPU   #$C000
  5A72  10 25 FF 77       LBCS   L_59ED
  5A76  CE A0 00          LDU    #$A000
  5A79  0C 28             INC    <SndSrcPage2
  5A7B  7E 59 ED          JMP    >L_59ED
L_5A7E:
  5A7E  7F FF 9A          CLR    >GIME_BORDER            ; GIME_BORDER - Border color (6-bit palette index)
  5A81  CC 26 2F          LDD    #$262F
  5A84  FD FF A4          STD    >MMU_T0_P4              ; MMU_T0_P4 - Task0 page4 ($8000-$9FFF)
  5A87  8E 80 00          LDX    #$8000
  5A8A  10 8E C0 00       LDY    #$C000
L_5A8E:
  5A8E  A6 80             LDA    ,X+
  5A90  A7 A2             STA    ,-Y
  5A92  8C 87 BA          CMPX   #$87BA
  5A95  25 F7             BCS    L_5A8E
  5A97  39                RTS

; =====================================================================
; Palettes: 16 GIME colours for RGB monitors, then 16 for composite.
; =====================================================================
PaletteRGB:
  5A98  00 00 08          FCB    $00,$00,$08
D_5A9B:
  5A9B  09 12             FCB    $09,$12
D_5A9D:
  5A9D  1B                FCB    $1B
D_5A9E:
  5A9E  20 22 39 24       FCB    $20,$22,$39,$24
D_5AA2:
  5AA2  25 26 2E 34 35    FCB    $25,$26,$2E,$34,$35,$3F,$00,$00
  5AAA  10 1B 21 3D 16    FCB    $10,$1B,$21,$3D,$16,$14,$3B,$17
  5AB2  27 26 28 34 35    FCB    $27,$26,$28,$34,$35,$3F

        END    ColdStart
