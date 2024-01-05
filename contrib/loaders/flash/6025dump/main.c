// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2007 by Pavel Chromy                                    *
 *   chromy@asix.cz                                                        *
 ***************************************************************************/
#include "platform.h"

#include "ocl.h"
#include "dcc.h"


#define BUFSIZE 1024 /* words, i.e. 4 KiB */
uint32 buffer[1024];

#define READ_WIDTH 2
#define READ_CMD inw

int main (void)
{
	uint32 cmd;
	uint32 addr;
	uint32 count;
	uint32 chksum;

	uint32 read_offset;
	uint32 i;
	uint32 j;

	int readattempts;

	for (;;) {		
		cmd = dcc_rd();

		#ifdef EMULATION
		cmd = OCL_READ | 8; // 8 Blocks
		#endif

		switch (cmd&OCL_CMD_MASK) {
			case OCL_PROBE:
				dcc_wr(OCL_CMD_DONE);
				#ifdef READ_AT_0x12000000
				dcc_wr(0x12000000); /* base */
				#else
				dcc_wr(0x0); /* base */
				#endif
				dcc_wr(0x02000000); /* size */
				dcc_wr(1); /* num_sectors */
				dcc_wr(4096 | ((unsigned long) 512 << 16)); /* buflen and bufalign */
				break;
				
			case OCL_READ:
				addr = dcc_rd();
				count = cmd & 0xffff;

				#ifdef EMULATION
				addr = 0x12; // (0x12 * 0x200)
				#endif

				dcc_wr(OCL_CMD_DONE);
				dcc_wr(READ_WIDTH);
				/* Assume addr and count is a multiple of 512 */
				read_offset = (addr * 512) % 0x02000000;

				i = 0;
				readattempts = 0;

				while (i < count) {
					chksum = OCL_CHKS_INIT;

					for (j = 0; j < (512 / READ_WIDTH); j++) {
						#ifdef READ_AT_0x12000000
						chksum ^= READ_CMD(0x12000000 + read_offset + (j * READ_WIDTH));
						dcc_wr(READ_CMD(0x12000000 + read_offset + (j * READ_WIDTH)));
						#elif READ_AT_0x12000000_AFTER_8MB
						chksum ^= READ_CMD((read_offset >= 0x800000 ? 0x11800000 : 0x0) + (read_offset + (j * READ_WIDTH)));
						dcc_wr(READ_CMD((read_offset >= 0x800000 ? 0x11800000 : 0x0) + (read_offset + (j * READ_WIDTH))));
						#else
						chksum ^= READ_CMD(read_offset + (j * READ_WIDTH));
						dcc_wr(READ_CMD(read_offset + (j * READ_WIDTH)));						
						#endif
					}

					dcc_wr(chksum);

					if ((dcc_rd() & OCL_CMD_MASK) == OCL_CMD_DONE) {
						i++;
						read_offset = (read_offset + 512) % 0x02000000;	
						
						dcc_wr(OCL_CMD_DONE);
					} else {
						if (readattempts++ >= 5) {
							dcc_wr(OCL_CMD_ERR);
							break;
						}

						dcc_wr(OCL_CMD_DONE);
					}					
				}

				break;
			default:
				/* unknown command */
				dcc_wr(OCL_CMD_ERR);
				break;
		}
	}

	return 0; /* we shall never get here, just to suppress compiler warning */
}
