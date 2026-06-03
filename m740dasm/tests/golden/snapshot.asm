    .area CODE1 (ABS)
    .org 0xffe0

    mem_0010 = 0x10         
    mem_0011 = 0x11         


lab_ffe0:
    lda mem_0010            ;ffe0  a5 10    
    sta mem_0011            ;ffe2  85 11    
    jsr sub_ffec            ;ffe4  20 ec ff 
    rts                     ;ffe7  60       

    .byte 0xde              ;ffe8  de          UNKNOWN 0xde 
    .byte 0xad              ;ffe9  ad          UNKNOWN 0xad 
    .byte 0xbe              ;ffea  be          UNKNOWN 0xbe 
    .byte 0xef              ;ffeb  ef          UNKNOWN 0xef 

sub_ffec:
    lda #0xaa               ;ffec  a9 aa    
    rts                     ;ffee  60       

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
    .word lab_ffe0          ;fffe  e0 ff       VECTOR Reset vector
