// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2024 Dumpit                                             *
 *                                                                         *
 ***************************************************************************/

/*
 * OneNAND MSM controller
 */

#include "bitutils.h"

#ifndef OPENOCD_FLASH_ONENAND_MSM_H
#define OPENOCD_FLASH_ONENAND_MSM_H

#define MSM_NAND_TIMEOUT 5000

#define MSM7200_REG_FLASH_CMD 0x0000
#define MSM7200_REG_ADDR0 0x0004
#define MSM7200_REG_ADDR1 0x0008
#define MSM7200_REG_FLASH_CHIP_SELECT 0x000C
#define MSM7200_REG_EXEC_CMD 0x0010
#define MSM7200_REG_FLASH_STATUS 0x0014
#define MSM7200_REG_BUFFER_STATUS 0x0018
#define MSM7200_REG_SFLASHC_STATUS 0x001C
#define MSM7200_REG_DEV0_CFG0 0x0020
#define MSM7200_REG_DEV0_CFG1 0x0024
#define MSM7200_REG_DEV0_ECC_CFG 0x0028
#define MSM7200_REG_DEV1_ECC_CFG 0x002C
#define MSM7200_REG_DEV1_CFG0 0x0030
#define MSM7200_REG_DEV1_CFG1 0x0034
#define MSM7200_REG_SFLASHC_CMD 0x0038
#define MSM7200_REG_SFLASHC_EXEC_CMD 0x003C
#define MSM7200_REG_READ_ID 0x0040
#define MSM7200_REG_READ_STATUS 0x0044
#define MSM7200_REG_CONFIG_DATA 0x0050
#define MSM7200_REG_CONFIG 0x0054
#define MSM7200_REG_CONFIG_MODE 0x0058
#define MSM7200_REG_CONFIG_STATUS 0x0060
#define MSM7200_REG_MACRO1_REG 0x0064
#define MSM7200_REG_XFR_STEP1 0x0070
#define MSM7200_REG_XFR_STEP2 0x0074
#define MSM7200_REG_XFR_STEP3 0x0078
#define MSM7200_REG_XFR_STEP4 0x007C
#define MSM7200_REG_XFR_STEP5 0x0080
#define MSM7200_REG_XFR_STEP6 0x0084
#define MSM7200_REG_XFR_STEP7 0x0088
#define MSM7200_REG_GENP_REG0 0x0090
#define MSM7200_REG_GENP_REG1 0x0094
#define MSM7200_REG_GENP_REG2 0x0098
#define MSM7200_REG_GENP_REG3 0x009C
#define MSM7200_REG_DEV_CMD0 0x00A0
#define MSM7200_REG_DEV_CMD1 0x00A4
#define MSM7200_REG_DEV_CMD2 0x00A8
#define MSM7200_REG_DEV_CMD_VLD 0x00AC
#define MSM7200_REG_EBI2_MISR_SIG_REG 0x00B0
#define MSM7200_REG_ADDR2 0x00C0
#define MSM7200_REG_ADDR3 0x00C4
#define MSM7200_REG_ADDR4 0x00C8
#define MSM7200_REG_ADDR5 0x00CC
#define MSM7200_REG_DEV_CMD3 0x00D0
#define MSM7200_REG_DEV_CMD4 0x00D4
#define MSM7200_REG_DEV_CMD5 0x00D8
#define MSM7200_REG_DEV_CMD6 0x00DC
#define MSM7200_REG_SFLASHC_BURST_CFG 0x00E0
#define MSM7200_REG_ADDR6 0x00E4
#define MSM7200_REG_EBI2_ECC_BUF_CFG 0x00F0
#define MSM7200_REG_HW_INFO 0x00FC
#define MSM7200_REG_FLASH_BUFFER 0x0100
#define MSM7200_REG_NAND_MPU_ENABLE 0x100000

struct bitmask MSM7200_SFLASHC_EXEC_CMD_BUSY = {0, 0x1};
struct bitmask MSM7200_SFLASHC_OPER_STATUS = {0, 0xf};
#endif