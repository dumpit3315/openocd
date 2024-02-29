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
 *
 */
read:
	cmp r3,#32
	beq read32

	cmp r3,#16
	beq read16

read8:
	ldrb	r4, [r1]
	strb	r4, [r0], #1
	subs	r2, r2, #1
	bne		read8

done_read8:
	bkpt #0

read16:
	ldrh	r4, [r1]
	strh	r4, [r0], #1
	subs	r2, r2, #2	
	bne		read16

done_read16:
	bkpt #0

read32:
	ldr		r4, [r1]
	str		r4, [r0], #1
	subs	r2, r2, #4	
	bne		read32

done_read32:
	bkpt #0

	.align 4

/* Inputs:
 *  r0	NAND data address (byte wide)
 *  r1	buffer address
 *  r2	buffer length
 *  r3  width size
 *
 */
write:
	cmp r3,#32
	beq write32

	cmp r3,#16
	beq write16

write8:
	ldrb	r4, [r1], #1
	strb	r4, [r0]
	subs	r2, r2, #1
	bne		write8

done_write8:
	bkpt #0

write16:
	ldrh	r4, [r1], #1
	strh	r4, [r0]
	subs	r2, r2, #2
	bne		write16

done_write16:
	bkpt #0

write32:
	ldr		r4, [r1], #1
	str		r4, [r0]
	subs	r2, r2, #4
	bne		write32

done_write32:
	bkpt #0

	.end
