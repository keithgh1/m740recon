    .area CODE1 (ABS)
    .org 0xffd0

    scratch_a = 0x10        ;working byte seeded at reset
    scratch_b = 0x11        

    ;power-on reset: seed scratch, call helper, return

reset:
    lda scratch_a           ;ffd0  a5 10    
    sta scratch_b           ;ffd2  85 11    
    jsr helper              ;ffd4  20 d8 ff 
    rts                     ;ffd7  60       
    ;load the standby pattern (0xAA)

helper:
    lda #0xaa               ;ffd8  a9 aa    
    rts                     ;ffda  60       
    ;carriage-motor step ISR; reached only via computed jump

stepper_isr:
    lda #0xbb               ;ffdb  a9 bb    
    rts                     ;ffdd  60       

    .ascii "Hi"             ;ffde  TEXT "Hi"
    .byte 0x00              ;ffe0  00          DATA 0x00 
    .ascii "!"              ;ffe1  TEXT "!"

    .word 0x1234            ;ffe2  34 12       WORD

    .word helper            ;ffe4  d8 ff       VECTOR

cmd_A:
    lda #0x01               ;ffe6  a9 01    
    rts                     ;ffe8  60       

cmd_B:
    lda #0x02               ;ffe9  a9 02    
    rts                     ;ffeb  60       

    ;host-command dispatch table: command byte -> handler
    .byte 0x41              ;ffec  41          DATA 0x41 'A' 

    .word cmd_A             ;ffed  e6 ff       VECTOR

    .byte 0x42              ;ffef  42          DATA 0x42 'B' 

    .word cmd_B             ;fff0  e9 ff       VECTOR

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
    .word reset             ;fffe  d0 ff       VECTOR Reset vector
