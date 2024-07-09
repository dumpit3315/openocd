// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2024 Dumpit                                             *
 *                                                                         *
 ***************************************************************************/

/*
 * OneNAND MSM controller
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imp.h"
#include "onenand.h"
#include "onenand_msm.h"
#include <target/arm.h>

#include "debug.h"

struct onenand_msm_controller
{
    uint32_t page_size;

    uint32_t read_id;

    uint32_t page;
    uint32_t page_index;

    bool ecc;

    uint8_t cmd_last;

    uint32_t base_offset;
	bool skip_init;
    uint32_t cfg1;
	uint32_t cfg2;
    uint8_t first_read;
    uint32_t prev_cfg1;
	uint32_t prev_cfg2;
	uint32_t prev_cfg1_f2;
	uint32_t prev_cfg2_f2;
	uint8_t init_done;
	uint32_t device_id;
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

/*
    def _cmdexec(self):
        while self._cmd_read(self._nfi_base + MSM7200_NANDREGS.SFLASHC_EXEC_CMD.value) & 0x1:
            pass

        self._cmd_write(self._nfi_base +
                        MSM7200_NANDREGS.SFLASHC_EXEC_CMD.value, 1)

        while self._cmd_read(self._nfi_base + MSM7200_NANDREGS.SFLASHC_EXEC_CMD.value) & 0x1:
            pass
*/

static int msm_sflashc_exec_timeout(struct nand_device *nand, int timeout)
{
	struct target *target = nand->target;
	struct onenand_msm_controller *onenand = nand->controller_priv;

	LOG_DEBUG("msm_sflashc_exec_timeout count start=%d", timeout);

	do
	{
		uint32_t status = 0x0;
		int retval;

		retval = GET_BIT32(target, onenand->base_offset + MSM7200_REG_SFLASHC_EXEC_CMD, MSM7200_SFLASHC_EXEC_CMD_BUSY, &status);
		if (retval != ERROR_OK)
		{
			LOG_ERROR("Could not read REG_SFLASHC_EXEC_CMD");
			return 0;
		}

#ifdef NAND_CONTROLLER_DEBUG
		status = 0;
#endif

		if (!status)
		{
			LOG_DEBUG("msm_sflashc_exec_timeout count=%d", timeout);
			return 1;
		}

		alive_sleep(1);
	} while (timeout-- > 0);

	return 0;
}

static int msm_sflashc_timeout(struct nand_device *nand, int timeout)
{
	struct target *target = nand->target;
	struct onenand_msm_controller *onenand = nand->controller_priv;

	LOG_DEBUG("msm_sflashc_timeout count start=%d", timeout);

	do
	{
		uint32_t status = 0x0;
		int retval;

		retval = GET_BIT32(target, onenand->base_offset + MSM7200_REG_SFLASHC_STATUS, MSM7200_SFLASHC_OPER_STATUS, &status);
		if (retval != ERROR_OK)
		{
			LOG_ERROR("Could not read MSM7200_REG_SFLASHC_STATUS");
			return 0;
		}

#ifdef NAND_CONTROLLER_DEBUG
		status = 0;
#endif

		if (!status)
		{
			LOG_DEBUG("msm_sflashc_timeout count=%d", timeout);
			return 1;
		}

		alive_sleep(1);
	} while (timeout-- > 0);

	return 0;
}

static int msm_sflashc_execute(struct nand_device *nand) {
    struct onenand_msm_controller *onenand = nand->controller_priv;
    struct target *target = nand->target;

    if (!msm_sflashc_exec_timeout(nand, MSM_NAND_TIMEOUT)) return ERROR_NAND_OPERATION_FAILED;
    target_write_u32(target, onenand->base_offset + MSM7200_REG_SFLASHC_EXEC_CMD, 1);

    return msm_sflashc_exec_timeout(nand, MSM_NAND_TIMEOUT) ? ERROR_OK : ERROR_NAND_OPERATION_FAILED;
}

static int msm_onld_reg_write(struct nand_device *nand, uint32_t offset, uint16_t value) {
    struct onenand_msm_controller *onenand = nand->controller_priv;
    struct target *target = nand->target;

    int retval;

    target_write_u32(target, onenand->base_offset + MSM7200_REG_ADDR0, offset >> 1);
    target_write_u32(target, onenand->base_offset + MSM7200_REG_GENP_REG0, value);

    target_write_u32(target, onenand->base_offset + MSM7200_REG_SFLASHC_CMD, 3 | (1 << 20) | 0x30);
    retval = msm_sflashc_execute(nand);
    if (retval != ERROR_OK) return retval;    
        
    return msm_sflashc_timeout(nand, MSM_NAND_TIMEOUT) ? ERROR_OK : ERROR_NAND_OPERATION_FAILED;
}

static int msm_onld_reg_read(struct nand_device *nand, uint32_t offset, uint16_t *value) {
    struct onenand_msm_controller *onenand = nand->controller_priv;
    struct target *target = nand->target;

    int retval;
    target_write_u32(target, onenand->base_offset + MSM7200_REG_ADDR0, offset >> 1);

    target_write_u32(target, onenand->base_offset + MSM7200_REG_SFLASHC_CMD, 2 | (1 << 20) | 0x10);
    retval = msm_sflashc_execute(nand);
    if (retval != ERROR_OK) return retval;

    retval = msm_sflashc_timeout(nand, MSM_NAND_TIMEOUT);
    if (retval != ERROR_OK) return retval;

    retval = target_read_u32(target, onenand->base_offset + MSM7200_REG_GENP_REG0, (uint32_t *)value);
    return retval;
}

static int msm_onld_nand2buf(struct nand_device *nand, uint32_t offset, uint32_t size, uint8_t *data) {
    struct onenand_msm_controller *onenand = nand->controller_priv;
    struct target *target = nand->target;
    int retval;
    uint32_t rdSize;
    uint32_t rdOffset = 0;

    assert(!(size & 1));
    assert(!(offset & 1));

    while (size > 0) {
        rdSize = size > 512 ? 512 : size;

        target_write_u32(target, onenand->base_offset + MSM7200_REG_MACRO1_REG, offset >> 1);
        target_write_u32(target, onenand->base_offset + MSM7200_REG_SFLASHC_CMD, 6 | ((rdSize >> 1) << 20) | 0x10);
        
        retval = msm_sflashc_execute(nand);
        if (retval != ERROR_OK) return retval;

        retval = msm_sflashc_timeout(nand, MSM_NAND_TIMEOUT);
        if (retval != ERROR_OK) return retval;

        target_read_memory(target, onenand->base_offset + MSM7200_REG_FLASH_BUFFER, 1, rdSize, data + rdOffset);

        offset += rdSize;
        rdOffset += rdSize;
        size -= rdSize;
    }

    return ERROR_OK;
};

static int msm_onld_buf2nand(struct nand_device *nand, uint32_t offset, uint32_t size, uint8_t *data) {
    struct onenand_msm_controller *onenand = nand->controller_priv;
    struct target *target = nand->target;
    int retval;
    uint32_t wrSize;
    uint32_t wrOffset = 0;

    assert(!(size & 1));
    assert(!(offset & 1));

    while (size > 0) {
        wrSize = size > 512 ? 512 : size;

        target_write_memory(target, onenand->base_offset + MSM7200_REG_FLASH_BUFFER, 1, wrSize, data + wrOffset);
        
        target_write_u32(target, onenand->base_offset + MSM7200_REG_MACRO1_REG, offset >> 1);
        target_write_u32(target, onenand->base_offset + MSM7200_REG_SFLASHC_CMD, 7 | ((wrSize >> 1) << 20) | 0x30);
        
        retval = msm_sflashc_execute(nand);
        if (retval != ERROR_OK) return retval;

        retval = msm_sflashc_timeout(nand, MSM_NAND_TIMEOUT);
        if (retval != ERROR_OK) return retval;
        
        offset += wrSize;
        wrOffset += wrSize;
        size -= wrSize;
    }

    return ERROR_OK;
};

static int onenand_msm_erase_page(struct nand_device *nand, uint32_t page);

static int onenand_msm_ready(struct nand_device *nand, int timeout)
{
    struct onenand_msm_controller *onenand = nand->controller_priv;
    uint16_t status;
    int retval;

    LOG_DEBUG("onenand_msm_wait_timeout count start=%d", timeout);

    if (onenand->cmd_last == NAND_CMD_ERASE2) {
        retval = onenand_msm_erase_page(nand, onenand->page);
        if (retval != ERROR_OK) {
            return 0;
        }
    } 

    do
    {
        status = 0;
        retval = msm_onld_reg_read(nand, O1N_REG_INTERRUPT, &status);
        if (retval != ERROR_OK)
		{
			LOG_ERROR("Could not read REG_INTERRUPT");
			return 0;
		}

        if (onenand->cmd_last == NAND_CMD_ERASE2) {
            if ((status & 0x8020) == 0x8020)
            {
                LOG_DEBUG("onenand_msm_wait_timeout count=%d", timeout);
                return 1;
            }
        } else {
            if ((status & 0x8000) == 0x8000)
            {
                LOG_DEBUG("onenand_msm_wait_timeout count=%d", timeout);
                return 1;
            }
        }

        alive_sleep(1);
    } while (timeout-- > 0);

    return 0;
}

static int onenand_msm_ready_flag(struct nand_device *nand, int timeout, uint16_t flag)
{
    uint16_t status;
    int retval;

    LOG_DEBUG("onenand_msm_wait_timeout_flag count start=%d flag=0x%x", timeout, flag);

    do
    {
        status = 0;
        retval = msm_onld_reg_read(nand, O1N_REG_INTERRUPT, &status);
        if (retval != ERROR_OK)
		{
			LOG_ERROR("Could not read REG_INTERRUPT");
			return 0;
		}

        if ((status & flag) == flag)
		{
			LOG_DEBUG("onenand_msm_wait_timeout_flag count=%d flag=0x%x", timeout, flag);
			return 1;
		}

        alive_sleep(1);
    } while (timeout-- > 0);

    return 0;
}

static int onenand_msm_command(struct nand_device *nand, uint8_t command)
{
    struct onenand_msm_controller *onenand = nand->controller_priv;
    int result;

    uint16_t temp;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;
    
    LOG_DEBUG("ONLD: cmd 0x%x", command);

    onenand->cmd_last = command;

    switch (command) {
        case NAND_CMD_READID:
            msm_onld_reg_read(nand, O1N_REG_MANUFACTURER_ID, &temp);
            onenand->read_id = temp;
            msm_onld_reg_read(nand, O1N_REG_DEVICE_ID, &temp);
            onenand->read_id |= temp << 16;

#ifdef NAND_CONTROLLER_DEBUG
            onenand->read_id = 0x014c00ec;
#endif
        /* fall through */
        default:
            onenand->page = 0;
            onenand->page_index = 0;
    }

    return ERROR_OK;
}

static int onenand_msm_address(struct nand_device *nand, uint8_t address)
{
    struct onenand_msm_controller *onenand = nand->controller_priv;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    LOG_DEBUG("ONLD: addr 0x%x", address);

    if (onenand->cmd_last == NAND_CMD_ERASE1) {
        onenand->page |= (address << (8 * onenand->page_index++));
    }

    return ERROR_OK;
}

static int onenand_msm_set_config1_bit(struct nand_device *nand, uint16_t flag) {
    uint16_t temp;
    int status;

    LOG_DEBUG("ONLD: set bit at cfg1 0x%x", flag);

    status = msm_onld_reg_read(nand, O1N_REG_SYS_CFG1, &temp);
    if (status != ERROR_OK) {
        return status;
    }

    msm_onld_reg_write(nand, O1N_REG_SYS_CFG1, temp | flag);

    return ERROR_OK;
}

static int onenand_msm_clear_config1_bit(struct nand_device *nand, uint16_t flag) {
    uint16_t temp;
    int status;

    LOG_DEBUG("ONLD: clear bit at cfg1 0x%x", flag);

    status = msm_onld_reg_read(nand, O1N_REG_SYS_CFG1, &temp);
    if (status != ERROR_OK) {
        return status;
    }

    msm_onld_reg_write(nand, O1N_REG_SYS_CFG1, temp & ~flag);

    return ERROR_OK;
}



static int onenand_msm_reset(struct nand_device *nand)
{
    LOG_DEBUG("ONLD: reset");

    msm_onld_reg_write(nand, O1N_REG_INTERRUPT, 0x0);
    msm_onld_reg_write(nand, O1N_REG_COMMAND, O1N_CMD_HOT_RESET);

    return onenand_msm_ready(nand, 1000) ? ERROR_OK : ERROR_NAND_OPERATION_FAILED;
}

static int onenand_msm_read_data(struct nand_device *nand, void *data)
{
	struct onenand_msm_controller *onenand = nand->controller_priv;
	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	if (onenand->cmd_last == NAND_CMD_READID) {
        LOG_DEBUG("ONLD: read id 0x%x", onenand->read_id & 0xffff);
        *(uint16_t *)data = onenand->read_id & 0xffff;
        onenand->read_id >>= 16;
    }

	return ERROR_OK;
}

static int onenand_msm_read_page(struct nand_device *nand, uint32_t page, uint8_t *data, uint32_t data_size, uint8_t *oob, uint32_t oob_size) {
    struct onenand_msm_controller *onenand = nand->controller_priv;
    bool flash_is_ddp;
    uint32_t onld_mask;

    if (onenand->ecc) {
        onenand_msm_clear_config1_bit(nand, 0x100);
    } else {
        onenand_msm_set_config1_bit(nand, 0x100);
    }

    LOG_DEBUG("ONLD: read page %d", page);

    msm_onld_reg_write(nand, O1N_REG_INTERRUPT, 0x0);
    msm_onld_reg_write(nand, O1N_REG_ECC_STATUS, 0x0);
    msm_onld_reg_write(nand, O1N_REG_START_BUFFER, (8 << 8));
    
    onld_mask = ((nand->device->id & 8) ? ((nand->device->chip_size << 3) / 2) : (nand->device->chip_size << 3)) - 1;
    LOG_DEBUG("ONLD: mask 0x%04x", onld_mask);

    flash_is_ddp = (bool)((nand->device->id & 8) && ((page >> 6) >= ((uint32_t)(nand->device->chip_size << 3) / 2)));
    msm_onld_reg_write(nand, O1N_REG_START_ADDRESS1, (flash_is_ddp ? 0x8000 : 0x0) | ((page >> 6) & onld_mask));
    msm_onld_reg_write(nand, O1N_REG_START_ADDRESS2, flash_is_ddp ? 0x8000 : 0x0);
    msm_onld_reg_write(nand, O1N_REG_START_ADDRESS8, (page & 63) << 2);

    msm_onld_reg_write(nand, O1N_REG_COMMAND, O1N_CMD_READ);
    if (!onenand_msm_ready_flag(nand, 2000, 0x8080)) {
        LOG_ERROR("timeout waiting for read to complete");
        return ERROR_NAND_OPERATION_FAILED;
    }

    msm_onld_nand2buf(nand, O1N_DATARAM, data_size, data);
    msm_onld_nand2buf(nand, O1N_SPARERAM, oob_size, oob);

    return ERROR_OK;    
}

static int onenand_msm_write_page(struct nand_device *nand, uint32_t page, uint8_t *data, uint32_t data_size, uint8_t *oob, uint32_t oob_size) {
    struct onenand_msm_controller *onenand = nand->controller_priv;
    bool flash_is_ddp;
    int result;
    uint16_t status;
    uint32_t onld_mask;

    if (onenand->ecc) {
        onenand_msm_clear_config1_bit(nand, 0x100);
    } else {
        onenand_msm_set_config1_bit(nand, 0x100);
    }

    LOG_DEBUG("ONLD: write page %d", page);

    msm_onld_reg_write(nand, O1N_REG_INTERRUPT, 0x0);
    msm_onld_reg_write(nand, O1N_REG_ECC_STATUS, 0x0);
    msm_onld_reg_write(nand, O1N_REG_START_BUFFER, (8 << 8));

    onld_mask = ((nand->device->id & 8) ? ((nand->device->chip_size << 3) / 2) : (nand->device->chip_size << 3)) - 1;
    LOG_DEBUG("ONLD: mask 0x%04x", onld_mask);

    flash_is_ddp = (bool)((nand->device->id & 8) && ((page >> 6) >= ((uint32_t)(nand->device->chip_size << 3) / 2)));
    msm_onld_reg_write(nand, O1N_REG_START_ADDRESS1, (flash_is_ddp ? 0x8000 : 0x0) | ((page >> 6) & onld_mask));
    msm_onld_reg_write(nand, O1N_REG_START_ADDRESS2, flash_is_ddp ? 0x8000 : 0x0);
    msm_onld_reg_write(nand, O1N_REG_START_ADDRESS8, (page & 63) << 2);

    msm_onld_buf2nand(nand, O1N_DATARAM, data_size, data);
    msm_onld_buf2nand(nand, O1N_SPARERAM, oob_size, oob);

    msm_onld_reg_write(nand, O1N_REG_COMMAND, O1N_CMD_PROG);
    if (!onenand_msm_ready_flag(nand, 2000, 0x8040)) {
        LOG_ERROR("timeout waiting for write to complete");
        return ERROR_NAND_OPERATION_FAILED;
    }

    result = msm_onld_reg_read(nand, O1N_REG_CTRL_STATUS, &status);
    if (result != ERROR_OK)
    {
        LOG_ERROR("Could not read REG_CTRL_STATUS");
        return ERROR_NAND_OPERATION_FAILED;
    }
    
    return (status & 0x400) ? ERROR_NAND_OPERATION_FAILED : ERROR_OK;
}

static int onenand_msm_erase_page(struct nand_device *nand, uint32_t page) {
    bool flash_is_ddp;
    int result;
    uint16_t status; 
    uint32_t onld_mask;

    LOG_DEBUG("ONLD: erase page %d", page);

    msm_onld_reg_write(nand, O1N_REG_INTERRUPT, 0x0);    

    onld_mask = ((nand->device->id & 8) ? ((nand->device->chip_size << 3) / 2) : (nand->device->chip_size << 3)) - 1;
    LOG_DEBUG("ONLD: mask 0x%04x", onld_mask);

    flash_is_ddp = (bool)((nand->device->id & 8) && ((page >> 6) >= ((uint32_t)(nand->device->chip_size << 3) / 2)));
    msm_onld_reg_write(nand, O1N_REG_START_ADDRESS1, (flash_is_ddp ? 0x8000 : 0x0) | ((page >> 6) & onld_mask));
    msm_onld_reg_write(nand, O1N_REG_START_ADDRESS2, flash_is_ddp ? 0x8000 : 0x0);
    msm_onld_reg_write(nand, O1N_REG_START_ADDRESS8, 0);

    msm_onld_reg_write(nand, O1N_REG_COMMAND, O1N_CMD_ERASE);
    if (!onenand_msm_ready_flag(nand, 2000, 0x8020)) {
        LOG_ERROR("timeout waiting for erase to complete");
        return ERROR_NAND_OPERATION_FAILED;
    }

    result = msm_onld_reg_read(nand, O1N_REG_CTRL_STATUS, &status);
    if (result != ERROR_OK)
    {
        LOG_ERROR("Could not read REG_CTRL_STATUS");
        return ERROR_NAND_OPERATION_FAILED;
    }
    
    return (status & 0x400) ? ERROR_NAND_OPERATION_FAILED : ERROR_OK;
}

NAND_DEVICE_COMMAND_HANDLER(onenand_msm_device_command)
{
    struct onenand_msm_controller *onenand;

    if (CMD_ARGC != 3)
        return ERROR_COMMAND_SYNTAX_ERROR;

    onenand = calloc(1, sizeof(struct onenand_msm_controller));
    if (!onenand)
    {
        LOG_ERROR("no memory for nand controller");
        return ERROR_NAND_DEVICE_INVALID;
    }

    nand->controller_priv = onenand;
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[2], onenand->page_size);
    onenand->ecc = true;
    onenand->base_offset = 0xa0a00000;
	onenand->skip_init = false;
    onenand->cfg1 = 0xffffffff;
	onenand->cfg2 = 0xffffffff;
    onenand->first_read = 0;
    onenand->prev_cfg1 = 0;
	onenand->prev_cfg2 = 0;
	onenand->prev_cfg1_f2 = 0;
	onenand->prev_cfg2_f2 = 0;
	onenand->init_done = 0;
	onenand->device_id = 0;

    return ERROR_OK;
}

static int onenand_msm_init(struct nand_device *nand)
{
    struct onenand_msm_controller *onenand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    /* inform calling code about selected bus width */
    nand->nand_type = NAND_TYPE_ONENAND;
    nand->bus_width = 16;
    nand->page_size = onenand->page_size;   
    
    /* from NAND mode */
    if (!onenand->init_done)
	{
		onenand->init_done = 1;

		result = target_read_u32(target, onenand->base_offset + MSM7200_REG_DEV0_CFG0, &onenand->prev_cfg1);
		if (result != ERROR_OK)
		{
			return ERROR_NAND_OPERATION_FAILED;
		}

		result = target_read_u32(target, onenand->base_offset + MSM7200_REG_DEV0_CFG1, &onenand->prev_cfg2);
		if (result != ERROR_OK)
		{
			return ERROR_NAND_OPERATION_FAILED;
		}

		result = target_read_u32(target, onenand->base_offset + MSM7200_REG_DEV1_CFG0, &onenand->prev_cfg1_f2);
		if (result != ERROR_OK)
		{
			return ERROR_NAND_OPERATION_FAILED;
		}

		result = target_read_u32(target, onenand->base_offset + MSM7200_REG_DEV1_CFG1, &onenand->prev_cfg2_f2);
		if (result != ERROR_OK)
		{
			return ERROR_NAND_OPERATION_FAILED;
		}

		if (!onenand->skip_init)
		{
			target_write_u32(target, onenand->base_offset + MSM7200_REG_DEV0_CFG0, 0xaad4001a);
			target_write_u32(target, onenand->base_offset + MSM7200_REG_DEV0_CFG1, 0x2101bd);
			target_write_u32(target, onenand->base_offset + MSM7200_REG_DEV_CMD_VLD, 0xd);
            target_write_u32(target, onenand->base_offset + MSM7200_REG_SFLASHC_BURST_CFG, 0x20100327);
            target_write_u32(target, onenand->base_offset + MSM7200_REG_XFR_STEP1, 0x47804780);
            target_write_u32(target, onenand->base_offset + MSM7200_REG_XFR_STEP2, 0x39003a0);
            target_write_u32(target, onenand->base_offset + MSM7200_REG_XFR_STEP3, 0x3b008a8);
            target_write_u32(target, onenand->base_offset + MSM7200_REG_XFR_STEP4, 0x9b488a0);
            target_write_u32(target, onenand->base_offset + MSM7200_REG_XFR_STEP5, 0x89a2c420);
            target_write_u32(target, onenand->base_offset + MSM7200_REG_XFR_STEP6, 0xc420c020);
            target_write_u32(target, onenand->base_offset + MSM7200_REG_XFR_STEP7, 0xc020c020);
			target_write_u32(target, onenand->base_offset + MSM7200_REG_FLASH_CHIP_SELECT, onenand->device_id);
		}
	}

    /* to OneNAND mode */
    msm_onld_reg_write(nand, O1N_REG_SYS_CFG1, 0x40c0);

    msm_onld_reg_write(nand, O1N_REG_START_ADDRESS1, 0x0);
    msm_onld_reg_write(nand, O1N_REG_START_ADDRESS2, 0x0);

    return ERROR_OK;
}

/* Command handlers */
#define BOOL_SETTER(name, setter, desc)                                        \
    COMMAND_HANDLER(name)                                                      \
    {                                                                          \
        struct nand_device *nand = NULL;                                       \
        struct onenand_msm_controller *p = NULL;                                   \
        uint32_t devid;                                                        \
                                                                               \
        if (CMD_ARGC > 2 || CMD_ARGC < 1)                                      \
            return ERROR_COMMAND_SYNTAX_ERROR;                                 \
                                                                               \
        COMMAND_PARSE_NUMBER(uint, CMD_ARGV[0], devid);                        \
        nand = get_nand_device_by_num(devid);                                  \
        if (!nand)                                                             \
        {                                                                      \
            command_print(CMD, "invalid nand device number: %s", CMD_ARGV[0]); \
            return ERROR_COMMAND_ARGUMENT_INVALID;                             \
        }                                                                      \
                                                                               \
        p = nand->controller_priv;                                             \
        if (CMD_ARGC > 1)                                                      \
            COMMAND_PARSE_ENABLE(CMD_ARGV[1], (setter));                       \
                                                                               \
        const char *msg = (setter) ? "enabled" : "disabled";                   \
        command_print(CMD, desc " is %s", msg);                                \
        return ERROR_OK;                                                       \
    }

#define INT_SETTER(name, setter, format, desc)                                 \
    COMMAND_HANDLER(name)                                                      \
    {                                                                          \
        struct nand_device *nand = NULL;                                       \
        struct onenand_msm_controller *p = NULL;                              \
        uint32_t devid;                                                        \
                                                                               \
        if (CMD_ARGC > 2 || CMD_ARGC < 1)                                      \
            return ERROR_COMMAND_SYNTAX_ERROR;                                 \
                                                                               \
        COMMAND_PARSE_NUMBER(uint, CMD_ARGV[0], devid);                        \
        nand = get_nand_device_by_num(devid);                                  \
        if (!nand)                                                             \
        {                                                                      \
            command_print(CMD, "invalid nand device number: %s", CMD_ARGV[0]); \
            return ERROR_COMMAND_ARGUMENT_INVALID;                             \
        }                                                                      \
                                                                               \
        p = nand->controller_priv;                                             \
        if (CMD_ARGC > 1)                                                      \
            COMMAND_PARSE_NUMBER(uint, CMD_ARGV[1], (setter));                 \
                                                                               \
        command_print(CMD, desc " is " format, (setter));                      \
        return ERROR_OK;                                                       \
    }

INT_SETTER(handle_onenand_msm_base_addr_command, p->base_offset, "0x%x", "base_addr")
BOOL_SETTER(handle_onenand_msm_skip_init_command, p->skip_init, "skip_init")
INT_SETTER(handle_onenand_msm_custom_cfg1_command, p->cfg1, "0x%x", "custom_cfg1")
INT_SETTER(handle_onenand_msm_custom_cfg2_command, p->cfg2, "0x%x", "custom_cfg2")
INT_SETTER(handle_onenand_msm_page_size_command, p->page_size, "0x%x", "Page size")
BOOL_SETTER(handle_onenand_msm_ecc_command, p->ecc, "ECC")

static const struct command_registration onenand_msm_sub_command_handlers[] = {
    {
		.name = "base_addr",
		.handler = handle_onenand_msm_base_addr_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [base_addr]",
	},
	{
		.name = "skip_init",
		.handler = handle_onenand_msm_skip_init_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [skip_init]",
	},
	{
		.name = "custom_cfg1",
		.handler = handle_onenand_msm_custom_cfg1_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [custom_cfg1]",
	},
	{
		.name = "custom_cfg2",
		.handler = handle_onenand_msm_custom_cfg2_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [custom_cfg2]",
	},
    {
        .name = "page_size",
        .handler = handle_onenand_msm_page_size_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [page_size]",
    },
    {
        .name = "ecc",
        .handler = handle_onenand_msm_ecc_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [ecc]",
    },
    COMMAND_REGISTRATION_DONE};

static const struct command_registration onenand_msm_commands[] = {
    {
        .name = "msm7200_onenand",
        .mode = COMMAND_ANY,
        .help = "OneNAND NAND flash controller commands",
        .usage = "",
        .chain = onenand_msm_sub_command_handlers,
    },
    COMMAND_REGISTRATION_DONE};

struct nand_flash_controller onenand_msm_controller = {
    .name = "msm7200_onenand",
    .usage = "<target_id> <page_size>",
    .command = onenand_msm_command,
    .address = onenand_msm_address,
    .read_data = onenand_msm_read_data,
    .read_page = onenand_msm_read_page,
    .write_page = onenand_msm_write_page,
    .nand_ready = onenand_msm_ready,
    .reset = onenand_msm_reset,
    .nand_device_command = onenand_msm_device_command,
    .init = onenand_msm_init,    
    .commands = onenand_msm_commands,
    .read1_supported = false,
};
