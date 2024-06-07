// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2007 by Pavel Chromy                                    *
 *   chromy@asix.cz                                                        *
 ***************************************************************************/
#include "platform.h"

#include "ocl.h"
#include "dcc.h"

#ifdef ENABLE_OCL_READ2
#include "minilzo.h"

#define BUF_SIZE 0x2000

uint8 lzo_work_buffer[LZO1X_1_MEM_COMPRESS];
uint8 lzo_out_buffer[BUF_SIZE + 0x800];
#endif

#define READ_WIDTH 2
#define READ_CMD inw
#define WRITE_CMD outw
#define BLOCK_SIZE 512

#if 0
void copy(uint8 *dst, uint8 *src, uint32 count) {
	uint32 i;
	for (i = 0; i<count; i++) {
		*(dst + i) = *(src + i);
	}
}
#endif

int main (uint32 NorStartAddress)
{
	uint32 cmd;

	uint32 addr;
	uint32 addr_upper;

	uint32 count;
	uint32 count_upper;

	uint32 chksum;

	uint32 read_offset;
	uint32 i;
	uint32 j;

	unsigned char qry[3];	
	uint16 cfi_type;
	uint8 probed = 0;

	int readattempts;

	#ifdef ENABLE_OCL_READ2	
	uint32 lzo_out_len;
	uint32 dcc_temp_no;
	#endif

	for (;;) {		
		cmd = dcc_rd();		

		switch (cmd&OCL_CMD_MASK) {
			case OCL_PROBE:
				probed = 0;

				WRITE_CMD(NorStartAddress, 0xf0);
				WRITE_CMD(NorStartAddress, 0xff);

				WRITE_CMD(NorStartAddress + (0x55 * READ_WIDTH), 0x98);
				for (i = 0; i < 3; i++) {
					qry[i] = READ_CMD(NorStartAddress + ((i + 0x10) * READ_WIDTH)) & 0xff;
				}

				if (qry[0] != 0x51 || qry[1] != 0x52 || qry[2] != 0x59) {					
					WRITE_CMD(NorStartAddress + (0x555 * READ_WIDTH), 0x98);
					for (i = 0; i < 3; i++) {
						qry[i] = READ_CMD(NorStartAddress + ((i + 0x10) * READ_WIDTH)) & 0xff;
					}

					if (qry[0] != 0x51 || qry[1] != 0x52 || qry[2] != 0x59) {
						dcc_wr(OCL_CMD_ERR);
						break;
					}
				}

				cfi_type = (READ_CMD(NorStartAddress + (0x13 * READ_WIDTH)) & 0xff) | ((READ_CMD(NorStartAddress + (0x14 * READ_WIDTH)) & 0xff) << 8);

				switch (cfi_type) {
					case 0x1:
					case 0x3:
					case 0x200:
						// Intel/Sharp												
						dcc_wr(OCL_CMD_DONE);
						dcc_wr(NorStartAddress); /* base */
						dcc_wr(1 << READ_CMD(NorStartAddress + (0x27 * READ_WIDTH))); /* size */
						dcc_wr(1); /* num_sectors */
						dcc_wr(4096 | ((unsigned long) BLOCK_SIZE << 16)); /* buflen and bufalign */
						WRITE_CMD(NorStartAddress, 0xff);
						probed = 1;
						break;
					case 0x2:
						// Spansion/Toshiba/Samsung/Micron						
						dcc_wr(OCL_CMD_DONE);
						dcc_wr(NorStartAddress); /* base */
						dcc_wr(1 << READ_CMD(NorStartAddress + (0x27 * READ_WIDTH))); /* size */
						dcc_wr(1); /* num_sectors */
						dcc_wr(4096 | ((unsigned long) BLOCK_SIZE << 16)); /* buflen and bufalign */
						WRITE_CMD(NorStartAddress, 0xf0);
						probed = 1;
						break;
					default:
						dcc_wr(OCL_CMD_ERR); // Renesas chips are not supported								
				};
											
				break;
				
			case OCL_READ:
				if (!probed) {
					dcc_wr(OCL_CMD_ERR);
					break;
				}

				addr = dcc_rd();
				count = (cmd & 0xffff) + 1;				

				dcc_wr(OCL_CMD_DONE);
				dcc_wr(READ_WIDTH);

				/* Assume addr and count is a multiple of BLOCK_SIZE */
				read_offset = NorStartAddress + (addr * BLOCK_SIZE);

				i = 0;
				readattempts = 0;

				while (i < count) {
					chksum = OCL_CHKS_INIT;

					for (j = 0; j < (BLOCK_SIZE / READ_WIDTH); j++) {						
						chksum ^= READ_CMD(read_offset + (j * READ_WIDTH));
						dcc_wr(READ_CMD(read_offset + (j * READ_WIDTH)));
					}

					dcc_wr(chksum);

					if ((dcc_rd() & OCL_CMD_MASK) == OCL_CMD_DONE) {
						i++;
						read_offset += BLOCK_SIZE;	
						
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

#ifdef ENABLE_OCL_READ2
			case OCL_READ2:
				if (!probed) {
					dcc_wr(OCL_CMD_ERR);
					break;
				}

				count_upper = dcc_rd();
				count = ((cmd & 0xffff) | (count_upper & 0xffff) << 16) + 1;				

				addr_upper = dcc_rd();
				addr = ((count_upper >> 16) | (addr_upper & 0xffff) << 16);

				dcc_wr(OCL_CMD_DONE);		
				dcc_wr(BUF_SIZE);
					
				/* Assume addr and count is a multiple of BLOCK_SIZE */
				read_offset = NorStartAddress + (addr * BUF_SIZE);

				i = 0;
				readattempts = 0;

				while (i < count) {
					chksum = OCL_CHKS_INIT;
					lzo1x_1_compress((uint8 *)(read_offset), BUF_SIZE, lzo_out_buffer, &lzo_out_len, lzo_work_buffer);

					j = 0;
					while (lzo_out_len) {		
						dcc_temp_no = 0;				
						lzo_out_len--; // 3 -> 2

						chksum ^= inb(lzo_out_buffer + j);
						dcc_temp_no |= inb(lzo_out_buffer + j); // Read Buf 0

						if (lzo_out_len <= 0) {
							dcc_wr((2 << 24) | dcc_temp_no);
							break; // if 0, end
						}

						j++; // 0 -> 1

						lzo_out_len--; // 2 -> 1

						chksum ^= inb(lzo_out_buffer + j) << 8;
						dcc_temp_no |= inb(lzo_out_buffer + j) << 8; // Read Buf 1
						
						if (lzo_out_len <= 0) {
							dcc_wr((1 << 24) | dcc_temp_no);
							break; // if 0, end
						}

						j++; // 1 -> 2

						lzo_out_len--; // 1 -> 0

						chksum ^= inb(lzo_out_buffer + j) << 16;
						dcc_temp_no |= (inb(lzo_out_buffer + j) << 16) | (lzo_out_len > 0 ? 0xff : 0) << 24; // Read Buf 2
						
						dcc_wr(dcc_temp_no);

						j++; // 2 -> 3
					}

					dcc_wr(chksum);

					if ((dcc_rd() & OCL_CMD_MASK) == OCL_CMD_DONE) {
						i++;
						read_offset += BUF_SIZE;
						
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
#endif

			default:
				/* unknown command */
				dcc_wr(OCL_CMD_ERR);
				break;
		}
	}

	return 0; /* we shall never get here, just to suppress compiler warning */
}
