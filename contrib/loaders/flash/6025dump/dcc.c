// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2007 by Pavel Chromy                                    *
 *   chromy@asix.cz                                                        *
 ***************************************************************************/
#include "dcc.h"


/* debug channel read (debugger->MCU) */
uint32 dcc_rd(void)
{
	volatile uint32 dcc_reg;

	do {
		asm volatile ("mrc p14, 0, %0, C0, C0" : "=r" (dcc_reg) :);
	} while ((dcc_reg&1) == 0); // When debugger sends the data to the DCC, the R bit was set to high.

	asm volatile ("mrc p14, 0, %0, C1, C0" : "=r" (dcc_reg) :); // Then, the host reads the RB data, setting the R bit to low.
	return dcc_reg;
}


/* debug channel write (MCU->debugger) */
int dcc_wr(uint32 data)
{
	volatile uint32 dcc_reg;

	do {
		asm volatile ("mrc p14, 0, %0, C0, C0" : "=r" (dcc_reg) :);
		/* operation controlled by master, cancel operation
			 upon reception of data for immediate response */
		if (dcc_reg&1) return -1; // Cancel if the debugger sends any data to the DCC buffer.
	} while (dcc_reg&2); // Wait until the debugger reads the WB data, which sets the W bit to low.

	asm volatile ("mcr p14, 0, %0, C1, C0" : : "r" (data)); // Then, the host writes the data to the WB bit, setting the W bit to high.
	return 0;
}
