/* SPDX-License-Identifier: GPL-2.0-or-later */

/***************************************************************************
 *   Copyright (C) 2024 Dumpit                                             *
 *                                                                         *
 ***************************************************************************/

/*
 * OneNAND NAND Controller
 */

#ifndef OPENOCD_FLASH_NAND_ONENAND_H
#define OPENOCD_FLASH_NAND_ONENAND_H

#define O1N_BOOTRAM (0x0000 << 1)
#define O1N_DATARAM (0x0200 << 1)
#define O1N_SPARERAM (0x8010 << 1)
#define O1N_REG_MANUFACTURER_ID (0xF000 << 1)
#define O1N_REG_DEVICE_ID (0xF001 << 1)
#define O1N_REG_VERSION_ID (0xF002 << 1)
#define O1N_REG_DATA_BUFFER_SIZE (0xF003 << 1)
#define O1N_REG_BOOT_BUFFER_SIZE (0xF004 << 1)
#define O1N_REG_NUM_BUFFERS (0xF005 << 1)
#define O1N_REG_TECHNOLOGY (0xF006 << 1)
#define O1N_REG_START_ADDRESS1 (0xF100 << 1)
#define O1N_REG_START_ADDRESS2 (0xF101 << 1)
#define O1N_REG_START_ADDRESS3 (0xF102 << 1)
#define O1N_REG_START_ADDRESS4 (0xF103 << 1)
#define O1N_REG_START_ADDRESS5 (0xF104 << 1)
#define O1N_REG_START_ADDRESS6 (0xF105 << 1)
#define O1N_REG_START_ADDRESS7 (0xF106 << 1)
#define O1N_REG_START_ADDRESS8 (0xF107 << 1)
#define O1N_REG_START_BUFFER (0xF200 << 1)
#define O1N_REG_COMMAND (0xF220 << 1)
#define O1N_REG_SYS_CFG1 (0xF221 << 1)
#define O1N_REG_SYS_CFG2 (0xF222 << 1)
#define O1N_REG_CTRL_STATUS (0xF240 << 1)
#define O1N_REG_INTERRUPT (0xF241 << 1)
#define O1N_REG_START_BLOCK_ADDRESS (0xF24C << 1)
#define O1N_REG_END_BLOCK_ADDRESS (0xF24D << 1)
#define O1N_REG_WP_STATUS (0xF24E << 1)
#define O1N_REG_ECC_STATUS (0xFF00 << 1)
#define O1N_REG_ECC_M0 (0xFF01 << 1)
#define O1N_REG_ECC_S0 (0xFF02 << 1)
#define O1N_REG_ECC_M1 (0xFF03 << 1)
#define O1N_REG_ECC_S1 (0xFF04 << 1)
#define O1N_REG_ECC_M2 (0xFF05 << 1)
#define O1N_REG_ECC_S2 (0xFF06 << 1)
#define O1N_REG_ECC_M3 (0xFF07 << 1)
#define O1N_REG_ECC_S3 (0xFF08 << 1)

#define O1N_CMD_READ 0x00
#define O1N_CMD_READOOB 0x13
#define O1N_CMD_PROG 0x80
#define O1N_CMD_PROGOOB 0x1A
#define O1N_CMD_X2_PROG 0x7D
#define O1N_CMD_X2_CACHE_PROG 0x7F
#define O1N_CMD_UNLOCK 0x23
#define O1N_CMD_LOCK 0x2A
#define O1N_CMD_LOCK_TIGHT 0x2C
#define O1N_CMD_UNLOCK_ALL 0x27
#define O1N_CMD_ERASE 0x94
#define O1N_CMD_MULTIBLOCK_ERASE 0x95
#define O1N_CMD_ERASE_VERIFY 0x71
#define O1N_CMD_RESET 0xF0
#define O1N_CMD_HOT_RESET 0xF3
#define O1N_CMD_OTP_ACCESS 0x65
#define O1N_CMD_READID 0x90
#define O1N_CMD_PI_UPDATE 0x05
#define O1N_CMD_PI_ACCESS 0x66
#define O1N_CMD_RECOVER_LSB 0x05

#endif