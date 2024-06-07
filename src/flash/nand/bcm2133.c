// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2024 Dumpit                                             *
 *                                                                         *
 ***************************************************************************/

/*
 * BCM2133 NAND controller
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imp.h"
#include "arm_io.h"
#include <target/arm.h>

#include "debug.h"

struct bcm2133_nand_controller
{
    struct arm_nand_data io_r;
    struct arm_nand_data io_w;
    uint32_t axi_flag;
    uint32_t axi_addr_offset;    
    uint32_t axi_data_offset;
    bool is_axi;

    uint32_t page;
    uint32_t page_offset;
    uint32_t loaded_data;

    uint8_t cmd_last;
    bool executed;

#ifdef NAND_CONTROLLER_DEBUG
    uint32_t debug_idcode;
#endif
};

static int validate_target_state(struct nand_device *nand)
{
    struct target *target = nand->target;

    if (target->state != TARGET_HALTED)
    {
        LOG_ERROR("Target not halted");
        return ERROR_NAND_OPERATION_FAILED;
    }

    return ERROR_OK;
}

static int bcm2133_nand_command(struct nand_device *nand, uint8_t command)
{
    struct bcm2133_nand_controller *bcm2133_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;
    uint32_t temp;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    LOG_DEBUG("BCM2133 NANDC: cmd 0x%x", command);
    
    if (bcm2133_nand->is_axi) {
        bcm2133_nand->cmd_last = command;
        switch (command) {
            case NAND_CMD_READID:
                bcm2133_nand->axi_addr_offset = 0x2200480;
                bcm2133_nand->axi_data_offset = 0x2080000;
                bcm2133_nand->io_r.data = 0x2080000;         
                bcm2133_nand->io_r.data_width = nand->bus_width;
                bcm2133_nand->io_r.read_width = nand->bus_width;       
#ifdef NAND_CONTROLLER_DEBUG
                bcm2133_nand->debug_idcode = 0x5500b1ec;
#endif
                goto lock;
            case NAND_CMD_STATUS:
                bcm2133_nand->axi_addr_offset = 0x2000380;
                bcm2133_nand->axi_data_offset = 0x2280000;
                bcm2133_nand->io_r.data = 0x2280000;      
                bcm2133_nand->io_r.data_width = 32;
                bcm2133_nand->io_r.read_width = 32;          
                target_write_u32(target, bcm2133_nand->axi_addr_offset, 0);
                goto lock;
            case NAND_CMD_READ0:                
            case NAND_CMD_READ1:
            case NAND_CMD_READOOB:
                bcm2133_nand->axi_addr_offset = 0x2B18000;
                bcm2133_nand->axi_data_offset = 0x2298000;
                bcm2133_nand->io_r.data = 0x2298000;
                bcm2133_nand->io_r.data_width = 32;
                bcm2133_nand->io_r.read_width = 32;
                goto lock;
            case NAND_CMD_SEQIN:
                bcm2133_nand->axi_addr_offset = nand->page_size > 512 ? 0x2A08400 : 0x2B08400;
                bcm2133_nand->axi_data_offset = 0x2288000;
                bcm2133_nand->io_w.data = 0x2288000;
                bcm2133_nand->io_w.data_width = 32;
                bcm2133_nand->io_w.read_width = 32;
                goto lock;
            case NAND_CMD_ERASE1:
                bcm2133_nand->axi_addr_offset = 0x2768300;
            lock:                
                bcm2133_nand->executed = false;
                bcm2133_nand->page_offset = 0;
                bcm2133_nand->page = 0;
        }
    } else {    
        switch (command) {
            case NAND_CMD_SEQIN:
                bcm2133_nand->io_w.data = 0x8000008;
                bcm2133_nand->io_w.data_width = 16;
                bcm2133_nand->io_w.read_width = 16;
                goto lock2;
            case NAND_CMD_READID:
                bcm2133_nand->io_r.data = 0x8000008;
                bcm2133_nand->io_r.data_width = 16;
                bcm2133_nand->io_r.read_width = 16;
                break;
            case NAND_CMD_STATUS:
                bcm2133_nand->io_r.data = 0x8000008;
                bcm2133_nand->io_r.data_width = 16;
                bcm2133_nand->io_r.read_width = 16;
                goto lock2;
            case NAND_CMD_READ0:
            case NAND_CMD_READ1:
            case NAND_CMD_READOOB:
                bcm2133_nand->io_r.data = 0x2298000;
                bcm2133_nand->io_r.data_width = 32;
                bcm2133_nand->io_r.read_width = 32;
            /* fall through */
            case NAND_CMD_ERASE1:
            lock2:
                result = target_read_u32(target, 0x809001c, &temp);
                if (result != ERROR_OK) {
                    return result;
                }
                target_write_u32(target, 0x809001c, temp | 1);
        }
        target_write_u16(target, 0x8000000, command);
#ifdef NAND_CONTROLLER_DEBUG
        bcm2133_nand->debug_idcode = 0x5500b1ec;
#endif
    }

    return ERROR_OK;
}

static int bcm2133_nand_address(struct nand_device *nand, uint8_t address)
{
    struct bcm2133_nand_controller *bcm2133_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;
    
    if (bcm2133_nand->is_axi) {
        if (bcm2133_nand->cmd_last == NAND_CMD_READID) {
            target_write_u32(target, bcm2133_nand->axi_addr_offset, address);
            return ERROR_OK;
        }

        if (bcm2133_nand->cmd_last != NAND_CMD_ERASE1) {
            if (nand->page_size > 512)
            {
                if (bcm2133_nand->page_offset > 1)
                {
                    bcm2133_nand->page |= address << (8 * (bcm2133_nand->page_offset - 2));
                }
            }
            else
            {
                if (bcm2133_nand->page_offset > 0)
                {
                    bcm2133_nand->page |= address << (8 * (bcm2133_nand->page_offset - 1));
                }
            }
        } else {
            bcm2133_nand->page |= address << (8 * bcm2133_nand->page_offset);
        }
        bcm2133_nand->page_offset++;
    } else {
        target_write_u16(target, 0x8000004, address);
    }

    return ERROR_OK;
}

static int bcm2133_nand_read(struct nand_device *nand, void *data)
{
    struct bcm2133_nand_controller *bcm2133_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

#ifdef NAND_CONTROLLER_DEBUG
    if (bcm2133_nand->cmd_last == NAND_CMD_READID) {
        *(uint8_t *)data = bcm2133_nand->debug_idcode & 0xff;
        bcm2133_nand->debug_idcode >>= 8;
        return ERROR_OK;
    }
#endif

    if (bcm2133_nand->io_r.data_width == 32) {
        target_read_u32(target, bcm2133_nand->io_r.data, data);
    } else if (bcm2133_nand->io_r.data_width == 16) {
        target_read_u16(target, bcm2133_nand->io_r.data, data);
    } else {
        target_read_u8(target, bcm2133_nand->io_r.data, data);
    }

    return ERROR_OK;
}

static int bcm2133_nand_write(struct nand_device *nand, uint16_t data)
{
    struct bcm2133_nand_controller *bcm2133_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;
    uint32_t temp;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    if (bcm2133_nand->io_w.data_width == 16) {
        target_write_u16(target, bcm2133_nand->io_w.data, data);
    } else {
        target_write_u8(target, bcm2133_nand->io_w.data, data);
    }

    if (!bcm2133_nand->is_axi && bcm2133_nand->cmd_last == NAND_CMD_STATUS) {
        result = target_read_u32(target, 0x809001c, &temp);
        if (result != ERROR_OK) {
            return result;
        }
        target_write_u32(target, 0x809001c, temp & 0xfe);
    }

    return ERROR_OK;
}

static int bcm2133_nand_read_block_data(struct nand_device *nand,
                                        uint8_t *data, int data_size)
{
    struct bcm2133_nand_controller *bcm2133_nand = nand->controller_priv;
    struct target *target = nand->target;
    uint32_t temp;
    int result;
    int i;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    bcm2133_nand->io_r.chunk_size = nand->page_size;
    bcm2133_nand->io_r.data_width = nand->bus_width;
    bcm2133_nand->loaded_data -= data_size;

    /* try the fast way first */
    result = arm_nandread(&bcm2133_nand->io_r, data, data_size);
    if (result != ERROR_NAND_NO_BUFFER) {
        if (result == ERROR_OK) goto end;
        return result;
    }

    /* else do it slowly */
    while (data_size -= 4) {        
        target_read_u32(target, bcm2133_nand->io_r.data, &temp);
        for (i = 0; i < 4; i++) {
            *data++ = temp & 0xff;
            temp >>= 8;
        }   
    }
          

end:
    if (bcm2133_nand->loaded_data <= 0 && !bcm2133_nand->is_axi) {
        result = target_read_u32(target, 0x809001c, &temp);
        if (result != ERROR_OK) {
            return result;
        }
        target_write_u32(target, 0x809001c, temp & 0xfe);
    }

    return ERROR_OK;
}

static int bcm2133_nand_write_block_data(struct nand_device *nand,
                                         uint8_t *data, int data_size)
{
    struct bcm2133_nand_controller *bcm2133_nand = nand->controller_priv;
    struct target *target = nand->target;    
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    bcm2133_nand->io_w.chunk_size = nand->page_size;
    bcm2133_nand->io_w.data_width = nand->bus_width;
    bcm2133_nand->loaded_data -= data_size;

    /* try the fast way first */
    result = arm_nandwrite(&bcm2133_nand->io_w, data, data_size);
    if (result != ERROR_NAND_NO_BUFFER) return result;

    /* else do it slowly */
    if (bcm2133_nand->is_axi) {
        while (data_size -= 4) {        
            target_write_u32(target, bcm2133_nand->io_w.data, target_buffer_get_u32(target, data));
            data += 4;   
            if (data_size <= 4 && bcm2133_nand->loaded_data <= 0) bcm2133_nand->io_w.data = 0x2388000;
        }
    } else {
        while (data_size -= 2) {
            target_write_u16(target, bcm2133_nand->io_w.data, target_buffer_get_u16(target, data));
            data += 2;
        }
    }

    return ERROR_OK;
}

static int bcm2133_nand_reset(struct nand_device *nand)
{
    struct bcm2133_nand_controller *bcm2133_nand = nand->controller_priv;
    struct target *target = nand->target;

    if (bcm2133_nand->is_axi) {
        target_write_u32(target, 0x020007f8, 0);
        return ERROR_OK;
    } else {
        return bcm2133_nand_command(nand, NAND_CMD_RESET);
    }
}

static int bcm2133_nand_ready(struct nand_device *nand, int timeout)
{
    struct bcm2133_nand_controller *bcm2133_nand = nand->controller_priv;
    struct target *target = nand->target;
    uint32_t status;    
    int retval;

    LOG_DEBUG("bcm2133_wait_timeout count start=%d", timeout);

    if (bcm2133_nand->is_axi) {
        if (!bcm2133_nand->executed) {
            bcm2133_nand->executed = true;

            if (bcm2133_nand->cmd_last == NAND_CMD_ERASE2) {
                target_write_u32(target, bcm2133_nand->axi_addr_offset, bcm2133_nand->page);
            } else if (nand->page_size <= 512) {
                if (bcm2133_nand->cmd_last == NAND_CMD_READ0 || bcm2133_nand->cmd_last == NAND_CMD_READ1 || bcm2133_nand->cmd_last == NAND_CMD_READOOB) {
                    target_write_u32(target, 0x2800000, (bcm2133_nand->page << 8) & 0xffffffff);
                    target_write_u32(target, bcm2133_nand->axi_addr_offset, (bcm2133_nand->page >> 16) & 0x7);
                } else {
                    target_write_u32(target, bcm2133_nand->axi_addr_offset, (bcm2133_nand->page << 8) & 0xffffffff);
                    target_write_u32(target, bcm2133_nand->axi_addr_offset, (bcm2133_nand->page >> 16) & 0x7);
                }
                bcm2133_nand->loaded_data = 0x210;
            } else {                
                target_write_u32(target, bcm2133_nand->axi_addr_offset, (bcm2133_nand->page << 16) & 0xffffffff);
                target_write_u32(target, bcm2133_nand->axi_addr_offset, (bcm2133_nand->page >> 16) & 0xffffffff);
                bcm2133_nand->loaded_data = 0x840;
            }
        }
    } else {
        bcm2133_nand->loaded_data = nand->page_size <= 512 ? 0x210 : 0x840;
    }
    
    do
    { 
        if (bcm2133_nand->is_axi) {
            retval = target_read_u8(target, 0x809001c, (uint8_t *)&status);
            if (retval != ERROR_OK)
            {
                LOG_ERROR("Could not read REG_STATUS");
                return 0;
            }

            if (status & 2)
            {
                LOG_DEBUG("bcm2133_wait_timeout count=%d", timeout);            
                return 1;
            }

            alive_sleep(1);
        } else {    
            retval = target_read_u32(target, 0x8090000, &status);
            if (retval != ERROR_OK)
            {
                LOG_ERROR("Could not read REG_STATUS");
                return 0;
            }

            if (status & NAND_STATUS_READY)
            {
                LOG_DEBUG("bcm2133_wait_timeout count=%d", timeout);
                return 1;
            }

            alive_sleep(1);
        }
    } while (timeout-- > 0);

    return 0;
}

NAND_DEVICE_COMMAND_HANDLER(bcm2133_nand_device_command)
{
    struct bcm2133_nand_controller *bcm2133_nand;

    bcm2133_nand = calloc(1, sizeof(struct bcm2133_nand_controller));
    if (!bcm2133_nand)
    {
        LOG_ERROR("no memory for nand controller");
        return ERROR_NAND_DEVICE_INVALID;
    }

    nand->controller_priv = bcm2133_nand;

    return ERROR_OK;
}

static int bcm2133_nand_init(struct nand_device *nand)
{
    struct bcm2133_nand_controller *bcm2133_nand = nand->controller_priv;
    struct target *target = nand->target;    
    int result;
    uint32_t temp;
    uint32_t temp_bit_width;
    int bus_width = nand->bus_width ? nand->bus_width : 8;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    /* inform calling code about selected bus width */
    bcm2133_nand->io_r.target = target;
    bcm2133_nand->io_r.data = 0x8000008;
    bcm2133_nand->io_r.op = ARM_NAND_NONE;
    bcm2133_nand->io_r.data_width = 16;
    bcm2133_nand->io_r.read_width = 16;

    bcm2133_nand->io_w.target = target;
    bcm2133_nand->io_w.data = 0x8000008;
    bcm2133_nand->io_w.op = ARM_NAND_NONE;
    bcm2133_nand->io_w.data_width = 16;
    bcm2133_nand->io_w.read_width = 16;

    bcm2133_nand->is_axi = false;
    result = target_read_u32(target, 0x8880010, &temp);
    if (result != ERROR_OK)
        return ERROR_NAND_OPERATION_FAILED;

    bcm2133_nand->axi_flag = temp & 0xf0;
        
    if (bcm2133_nand->axi_flag == 0xf0 || bcm2133_nand->axi_flag == 0xe0) {
        bcm2133_nand->is_axi = true;
    }

#ifdef BCM2133_DEBUG_AXI
    bcm2133_nand->is_axi = true;
#endif
    
    if (bcm2133_nand->is_axi && !nand->bus_width) {
        result = target_read_u32(target, 0x8880008, &temp);
        if (result != ERROR_OK)
            return ERROR_NAND_OPERATION_FAILED;

        if (bcm2133_nand->axi_flag != 0x90 && bcm2133_nand->axi_flag != 0xb0) {
            temp_bit_width = (((temp >> 25) & 1) + 1) & 1;
        } else {
            temp_bit_width = temp & 2;
        }

        nand->bus_width = temp_bit_width == 0 ? 8 : 16;    
    } else {
        nand->bus_width = bus_width;
    }

    return ERROR_OK;
}

struct nand_flash_controller bcm2133_nand_controller = {
    .name = "bcm2133",
    .usage = "<target_id>",
    .command = bcm2133_nand_command,
    .address = bcm2133_nand_address,
    .read_data = bcm2133_nand_read,
    .write_data = bcm2133_nand_write,
    .write_block_data = bcm2133_nand_write_block_data,
    .read_block_data = bcm2133_nand_read_block_data,
    .nand_ready = bcm2133_nand_ready,
    .reset = bcm2133_nand_reset,
    .nand_device_command = bcm2133_nand_device_command,
    .init = bcm2133_nand_init,    
    .read1_supported = false,
};
