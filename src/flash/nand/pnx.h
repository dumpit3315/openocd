/* SPDX-License-Identifier: GPL-2.0-or-later */

/***************************************************************************
 *   Copyright (C) 2024 Dumpit                                             *
 *                                                                         *
 ***************************************************************************/

/*
 * PNX NAND Controller
 */

#include "bitutils.h"

#ifndef OPENOCD_FLASH_NAND_PNX_H
#define OPENOCD_FLASH_NAND_PNX_H
#define PNX_NAND_TIMEOUT 5000

/* PNX67xx */

#define PNX6_REG_DATA 0x0
#define PNX6_REG_ADDR 0x4
#define PNX6_REG_CMD 0x8
#define PNX6_REG_STOP 0xC
#define PNX6_REG_CTRL 0x10
#define PNX6_REG_CONFIG 0x14
#define PNX6_REG_STAT 0x18
#define PNX6_REG_INT_STAT 0x1C
#define PNX6_REG_IEN 0x20
#define PNX6_REG_ISR 0x24
#define PNX6_REG_ICR 0x28
#define PNX6_REG_TAC 0x2C
#define PNX6_REG_TC 0x30
#define PNX6_REG_ECC 0x34
#define PNX6_REG_DMA_DATA 0x38
#define PNX6_REG_PAGE_SIZE 0x3C
#define PNX6_REG_READY 0x40
#define PNX6_REG_TAC_READ 0x44

struct bitmask PNX6_CTRL_SW_RESET = {2, 0x1};
struct bitmask PNX6_CTRL_ECC_CLEAR = {1, 0x1};
struct bitmask PNX6_CTRL_DMA_START = {0, 0x1};

struct bitmask PNX6_CFG_CMD_UNDER_BUSY = {7, 0x1};
struct bitmask PNX6_CFG_TAC_MODE = {6, 0x1};
struct bitmask PNX6_CFG_CE_LOW = {5, 0x1};
struct bitmask PNX6_CFG_DMA_ECC = {4, 0x1};
struct bitmask PNX6_CFG_ECC = {3, 0x1};
struct bitmask PNX6_CFG_DMA_BURST = {2, 0x1};
struct bitmask PNX6_CFG_DMA_DIR = {1, 0x1};
struct bitmask PNX6_CFG_WIDTH = {0, 0x1};

struct bitmask PNX6_STAT_DMA_READY = {4, 1};
struct bitmask PNX6_STAT_IF_READY = {3, 1};
struct bitmask PNX6_STAT_DMA_ACTIVE = {2, 1};
struct bitmask PNX6_STAT_IF_ACTIVE = {1, 1};
struct bitmask PNX6_STAT_RDY = {0, 1};

struct bitmask PNX6_STAT_TCZINT = {1, 0x1};
struct bitmask PNX6_STAT_RDYINT = {0, 0x1};

struct bitmask PNX6_STAT_BUSY = {12, 0xF};
struct bitmask PNX6_STAT_WI = {8, 0xF};
struct bitmask PNX6_STAT_HO = {4, 0xF};
struct bitmask PNX6_STAT_SU = {0, 0xF};

#define PNX6_CTRL_SW_RESET_0 0x0
#define PNX6_CTRL_SW_RESET_1 0x1
#define PNX6_CTRL_ECC_CLEAR_0 0x0
#define PNX6_CTRL_ECC_CLEAR_1 0x1
#define PNX6_CTRL_DMA_START_0 0x0
#define PNX6_CTRL_DMA_START_1 0x1

#define PNX6_CFG_CMD_UNDER_BUSY_DISABLE 0x0
#define PNX6_CFG_CMD_UNDER_BUSY_ENABLE 0x1
#define PNX6_CFG_TAC_MODE_0 0x0
#define PNX6_CFG_TAC_MODE_NFI_TAC 0x1
#define PNX6_CFG_CE_LOW_0 0x0
#define PNX6_CFG_CE_LOW_ALWAYS 0x1
#define PNX6_CFG_DMA_ECC_0 0x0
#define PNX6_CFG_DMA_ECC_ENABLE 0x1
#define PNX6_CFG_ECC_DISABLE 0x0
#define PNX6_CFG_ECC_ENABLE 0x1
#define PNX6_CFG_DMA_BURST_DISABLE 0x0
#define PNX6_CFG_DMA_BURST_ENABLE 0x1
#define PNX6_CFG_DMA_DIR_WRITE 0x0
#define PNX6_CFG_DMA_DIR_READ 0x1
#define PNX6_CFG_WIDTH_8_BIT 0x0
#define PNX6_CFG_WIDTH_16_BIT 0x1

#define PNX6_STAT_DMA_READY_READY 0x0
#define PNX6_STAT_DMA_READY_NOT_READY 0x1
#define PNX6_STAT_IF_READY_READY 0x0
#define PNX6_STAT_IF_READY_NOT_READY 0x1
#define PNX6_STAT_DMA_ACTIVE_NOT_ACTIVE 0x0
#define PNX6_STAT_DMA_ACTIVE_ACTIVE 0x1
#define PNX6_STAT_IF_ACTIVE_NOT_ACTIVE 0x0
#define PNX6_STAT_IF_ACTIVE_ACTIVE 0x1
#define PNX6_STAT_RDY_NOT_READY 0x0
#define PNX6_STAT_RDY_READY 0x1

#endif