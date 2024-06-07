/* SPDX-License-Identifier: BSD-3-Clause */

/****************************************************************************
*  Copyright (c) 2006 by Michael Fischer. All rights reserved.
****************************************************************************
*
*  History:
*
*  18.12.06  mifi   First Version
*                   The hardware initialization is based on the startup file
*                   crtat91sam7x256_rom.S from NutOS 4.2.1.
*                   Therefore partial copyright by egnite Software GmbH.
****************************************************************************/

/*
 * Some defines for the program status registers
 */
   ARM_MODE_USER  = 0x10      /* Normal User Mode                             */
   ARM_MODE_FIQ   = 0x11      /* FIQ Fast Interrupts Mode                     */
   ARM_MODE_IRQ   = 0x12      /* IRQ Standard Interrupts Mode                 */
   ARM_MODE_SVC   = 0x13      /* Supervisor Interrupts Mode                   */
   ARM_MODE_ABORT = 0x17      /* Abort Processing memory Faults Mode          */
   ARM_MODE_UNDEF = 0x1B      /* Undefined Instructions Mode                  */
   ARM_MODE_SYS   = 0x1F      /* System Running in Privileged Operating Mode  */
   ARM_MODE_MASK  = 0x1F

   I_BIT          = 0x80      /* disable IRQ when I bit is set */
   F_BIT          = 0x40      /* disable IRQ when I bit is set */

   /*
   .section .vectors,"ax"
   .code 32
   */

/****************************************************************************/
/*               Vector table and reset entry                               */
/****************************************************************************/

   .section .init, "ax"
   .code 32

_vectors:
   b ResetHandler    /* Reset                 */
   b UndefHandler    /* Undefined instruction */
   b SWIHandler      /* Software interrupt    */
   b PAbortHandler   /* Prefetch abort        */
   b DAbortHandler   /* Data abort            */
   b 0               /* Reserved              */
   b IRQHandler      /* IRQ interrupt         */
   b FIQHandler      /* FIQ interrupt         */

   .ltorg

   .global ResetHandler
   .global ExitFunction
   .global NorStartAddress
   .extern main
   .extern __stack_und_end

NorStartAddress:  .word 0x12345678
/****************************************************************************/
/*                           Reset handler                                  */
/****************************************************************************/
ResetHandler:
   /*
    * Setup a stack for each mode
    */
   mov   r0, #0
   adr   r0, _vectors

   msr   CPSR_c, #ARM_MODE_UNDEF | I_BIT | F_BIT   /* Undefined Instruction Mode */
   ldr   sp, =__stack_und_end
   add   sp, r0

   msr   CPSR_c, #ARM_MODE_ABORT | I_BIT | F_BIT   /* Abort Mode */
   ldr   sp, =__stack_abt_end
   add   sp, r0

   msr   CPSR_c, #ARM_MODE_FIQ | I_BIT | F_BIT     /* FIQ Mode */
   ldr   sp, =__stack_fiq_end
   add   sp, r0

   msr   CPSR_c, #ARM_MODE_IRQ | I_BIT | F_BIT     /* IRQ Mode */
   ldr   sp, =__stack_irq_end
   add   sp, r0

   msr   CPSR_c, #ARM_MODE_SVC | I_BIT | F_BIT     /* Supervisor Mode */
   ldr   sp, =__stack_svc_end
   add   sp, r0

   /*
    * Clear .bss section
    */
   ldr   r1, =__bss_start   
   ldr   r2, =__bss_end   
   mov   r3, #0
   
   add   r1, r0
   add   r2, r0
bss_clear_loop:
   cmp   r1, r2
   strne r3, [r1], #+4
   bne   bss_clear_loop


   /*
    * Jump to main
    */
   mrs   r0, cpsr
   bic   r0, r0, #I_BIT | F_BIT     /* Enable FIQ and IRQ interrupt */
   msr   cpsr, r0
   
   mov   r1, #0 /* No arguments */
   mov   r2, #0 /* No arguments */
   mov   r3, #0 /* No arguments */

   mov   r0, #0
   adr   r0, NorStartAddress
   ldr   r0, [r0]
   
   b main

ExitFunction:
   nop
   nop
   nop
   b ExitFunction


/****************************************************************************/
/*                         Default interrupt handler                        */
/****************************************************************************/

UndefHandler:
   b UndefHandler

SWIHandler:
   b SWIHandler

PAbortHandler:
   b PAbortHandler

DAbortHandler:
   b DAbortHandler

IRQHandler:
   b IRQHandler

FIQHandler:
   b FIQHandler

   .weak ExitFunction
   .weak UndefHandler, PAbortHandler, DAbortHandler
   .weak IRQHandler, FIQHandler

   .ltorg
/*** EOF ***/
