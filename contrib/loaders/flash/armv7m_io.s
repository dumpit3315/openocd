/* SPDX-License-Identifier: GPL-2.0-or-later */

/***************************************************************************
 *   Copyright (C) 2013 by Henrik Nilsson                                  *
 *   henrik.nilsson@bytequest.se                                           *
 ***************************************************************************/

.text
.syntax unified
//.arch armv7-m
//.thumb
//.thumb_func

.align 4

/* Inputs:
 *  r0	buffer address
 *  r1	NAND data address (byte wide)
 *  r2	buffer length
 *  r3  width size 
 *  r4  data write size
 *
 */
read_prelude:
 .ascii "GETS"
read:
	cmp r4,#16
	beq read16

	cmp r4,#8
	beq read8

/* read0 */
read0:
	cmp r3,#32
	beq read0_32

	cmp r3,#16
	beq read0_16

read0_8:
	ldrb	r10, [r1]
	strb	r10, [r0], #1
	subs	r2, r2, #1
	bne		read0_8

done_read0_8:
	bkpt #0

read0_16:
	ldrh	r10, [r1]
	strh	r10, [r0], #2
	subs	r2, r2, #2	
	bne		read0_16

done_read0_16:
	bkpt #0

read0_32:
	ldr		r10, [r1]
	str		r10, [r0], #4
	subs	r2, r2, #4	
	bne		read0_32

done_read0_32:
	bkpt #0

/* read8 */
read8:
	cmp r3,#32
	beq read8_32

	cmp r3,#16
	beq read8_16

read8_8:
	b read0_8

read8_16:
	ldrh	r10, [r1]
	and 	r10, #0xff
	strb	r10, [r0], #1
	subs	r2, r2, #1	
	bne		read8_16

done_read8_16:
	bkpt #0

read8_32:
	ldr		r10, [r1]
	and 	r10, #0xff
	strb	r10, [r0], #1
	subs	r2, r2, #1	
	bne		read8_32

done_read8_32:
	bkpt #0

/* read16 */
read16:
	cmp r3,#32
	beq read16_32

	cmp r3,#16
	beq read16_16

read16_8:
	b read0_8

read16_16:
	b read0_16

read16_32:
	mov 	r11, #0xff00	
	orr 	r11, #0xff
read16_32_loop:
	ldr		r10, [r1]	
	and 	r10, r11
	strh	r10, [r0], #2
	subs	r2, r2, #2	
	bne		read16_32_loop

done_read16_32:
	bkpt #0

	.align 4

/* Inputs:
 *  r0	NAND data address (byte wide)
 *  r1	buffer address
 *  r2	buffer length
 *  r3  width size
 *  r4  data read size
 *
 */
write_prelude:
 .ascii "PUTS"
write:
	cmp r4,#16
	beq write16

	cmp r4,#8
	beq write8	

/* write0 */
write0:
	cmp r3,#32
	beq write0_32

	cmp r3,#16
	beq write0_16

write0_8:
	ldrb	r10, [r1], #1
	strb	r10, [r0]
	subs	r2, r2, #1
	bne		write0_8

done_write0_8:
	bkpt #0

write0_16:
	ldrh	r10, [r1], #2
	strh	r10, [r0]
	subs	r2, r2, #2
	bne		write0_16

done_write0_16:
	bkpt #0

write0_32:
	ldr		r10, [r1], #4
	str		r10, [r0]
	subs	r2, r2, #4
	bne		write0_32

done_write0_32:
	bkpt #0

/* write8 */
write8:
	cmp r3,#32
	beq write8_32

	cmp r3,#16
	beq write8_16

write8_8:
	b write0_8

write8_16:
	ldrb	r10, [r1], #1
	and 	r10, #0xff
	strh	r10, [r0]
	subs	r2, r2, #1
	bne		write8_16

done_write8_16:
	bkpt #0

write8_32:
	ldrb	r10, [r1], #1
	and 	r10, #0xff
	str		r10, [r0]
	subs	r2, r2, #1
	bne		write8_32

done_write8_32:
	bkpt #0

/* write16 */
write16:
	cmp r3,#32
	beq write16_32

	cmp r3,#16
	beq write16_16

write16_8:
	b write0_8

write16_16:
	b write0_16

write16_32:
	mov		r11, #0xff00	
	orr		r11, #0xff
write16_32_loop:
	ldrh	r10, [r1], #2
	and		r10, r11
	str		r10, [r0]
	subs	r2, r2, #2
	bne		write16_32_loop

done_write16_32:
	bkpt #0

.end
