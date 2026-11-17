    .area CODE1 (ABS)
    .org 0xffc0

    mem_0052 = 0x52         
    mem_0056 = 0x56         
    mem_0060 = 0x60         
    P2 = 0xf0               ;Port P2
    P1 = 0xf3               ;Port P1
    P0 = 0xf6               ;Port P0


reset:
    seb 0,P1                ;ffc0  0f f3     EE_CS = 1 (asserted)
    clb 0,P1                ;ffc2  1f f3     EE_CS = 0 (not asserted)
    bbc 6,P0,lab_ffca       ;ffc4  d7 f6 03  PE: branch if paper present
    bbs 6,P0,lab_ffca       ;ffc7  c7 f6 00  PE: branch if paper end

lab_ffca:
    seb 4,P0                ;ffca  8f f6     STB = 1 (not asserted)
    clb 4,P0                ;ffcc  9f f6     STB = 0 (asserted)
    seb 2,P2                ;ffce  4f f0     CR_PHASE[2] = 1
    bbs 7,mem_0052,lab_ffd3 ;ffd0  e7 52 00  asf_installed: branch if set

lab_ffd3:
    seb 5,mem_0056          ;ffd3  af 56     pe_detect_off? = 1
    seb 3,mem_0060          ;ffd5  6f 60    
    bbs 1,a,lab_ffd9        ;ffd7  23 00    

lab_ffd9:
    seb 1,a                 ;ffd9  2b       
    rts                     ;ffda  60       

    .byte 0x00              ;ffdb  00          UNKNOWN 0x00 
    .byte 0x00              ;ffdc  00          UNKNOWN 0x00 
    .byte 0x00              ;ffdd  00          UNKNOWN 0x00 
    .byte 0x00              ;ffde  00          UNKNOWN 0x00 
    .byte 0x00              ;ffdf  00          UNKNOWN 0x00 
    .byte 0x00              ;ffe0  00          UNKNOWN 0x00 
    .byte 0x00              ;ffe1  00          UNKNOWN 0x00 
    .byte 0x00              ;ffe2  00          UNKNOWN 0x00 
    .byte 0x00              ;ffe3  00          UNKNOWN 0x00 
    .byte 0x00              ;ffe4  00          UNKNOWN 0x00 
    .byte 0x00              ;ffe5  00          UNKNOWN 0x00 
    .byte 0x00              ;ffe6  00          UNKNOWN 0x00 
    .byte 0x00              ;ffe7  00          UNKNOWN 0x00 
    .byte 0x00              ;ffe8  00          UNKNOWN 0x00 
    .byte 0x00              ;ffe9  00          UNKNOWN 0x00 
    .byte 0x00              ;ffea  00          UNKNOWN 0x00 
    .byte 0x00              ;ffeb  00          UNKNOWN 0x00 
    .byte 0x00              ;ffec  00          UNKNOWN 0x00 
    .byte 0x00              ;ffed  00          UNKNOWN 0x00 
    .byte 0x00              ;ffee  00          UNKNOWN 0x00 
    .byte 0x00              ;ffef  00          UNKNOWN 0x00 
    .byte 0x00              ;fff0  00          UNKNOWN 0x00 
    .byte 0x00              ;fff1  00          UNKNOWN 0x00 
    .byte 0x00              ;fff2  00          UNKNOWN 0x00 
    .byte 0x00              ;fff3  00          UNKNOWN 0x00 

INT_FFF4_TXCNTRBRK:
    .word 0x0000            ;fff4  00 00       VECTOR TX, CNTR, or BRK

INT_FFF6_HEVE:
    .word 0x0000            ;fff6  00 00       VECTOR HE or VE

INT_FFF8_T1T2T3:
    .word 0x0000            ;fff8  00 00       VECTOR Timer1, Timer2, or Timer3

INT_FFFA_RI_INT1:
    .word 0x0000            ;fffa  00 00       VECTOR RI or INT1

INT_FFFC_INT2:
    .word 0x0000            ;fffc  00 00       VECTOR INT2 (External interrupt 2)

RESET:
    .word reset             ;fffe  c0 ff       VECTOR Reset vector
