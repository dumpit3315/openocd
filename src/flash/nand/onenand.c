// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2024 Dumpit                                             *
 *                                                                         *
 ***************************************************************************/

/*
 * OneNAND controller
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imp.h"
#include "onenand.h"
#include <target/arm.h>

#include "debug.h"

struct onenand_controller
{
    uint32_t base_offset;
    uint32_t page_size;

    uint32_t read_id;

    uint32_t page;
    uint32_t page_index;

    bool ecc;

    uint8_t cmd_last;
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

static int onenand_erase_page(struct nand_device *nand, uint32_t page);

static int onenand_ready(struct nand_device *nand, int timeout)
{
    struct onenand_controller *onenand = nand->controller_priv;
    struct target *target = nand->target;
    uint16_t status;
    int retval;

    LOG_DEBUG("onenand_wait_timeout count start=%d", timeout);

    if (onenand->cmd_last == NAND_CMD_ERASE2) {
        retval = onenand_erase_page(nand, onenand->page);
        if (retval != ERROR_OK) {
            return 0;
        }
    } 

    do
    {
        status = 0;
        retval = target_read_u16(target, onenand->base_offset + O1N_REG_INTERRUPT, &status);
        if (retval != ERROR_OK)
		{
			LOG_ERROR("Could not read REG_INTERRUPT");
			return 0;
		}

        if (onenand->cmd_last == NAND_CMD_ERASE2) {
            if ((status & 0x8020) == 0x8020)
            {
                LOG_DEBUG("onenand_wait_timeout count=%d", timeout);
                return 1;
            }
        } else {
            if ((status & 0x8000) == 0x8000)
            {
                LOG_DEBUG("onenand_wait_timeout count=%d", timeout);
                return 1;
            }
        }

        alive_sleep(1);
    } while (timeout-- > 0);

    return 0;
}

static int onenand_ready_flag(struct nand_device *nand, int timeout, uint16_t flag)
{
    struct onenand_controller *onenand = nand->controller_priv;
    struct target *target = nand->target;
    uint16_t status;
    int retval;

    LOG_DEBUG("onenand_wait_timeout_flag count start=%d flag=0x%x", timeout, flag);

    do
    {
        status = 0;
        retval = target_read_u16(target, onenand->base_offset + O1N_REG_INTERRUPT, &status);
        if (retval != ERROR_OK)
		{
			LOG_ERROR("Could not read REG_INTERRUPT");
			return 0;
		}

        if ((status & flag) == flag)
		{
			LOG_DEBUG("onenand_wait_timeout_flag count=%d flag=0x%x", timeout, flag);
			return 1;
		}

        alive_sleep(1);
    } while (timeout-- > 0);

    return 0;
}

static int onenand_command(struct nand_device *nand, uint8_t command)
{
    struct onenand_controller *onenand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    uint16_t temp;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;
    
    LOG_DEBUG("ONLD: cmd 0x%x", command);

    onenand->cmd_last = command;

    switch (command) {
        case NAND_CMD_READID:
            target_read_u16(target, onenand->base_offset + O1N_REG_MANUFACTURER_ID, &temp);
            onenand->read_id = temp;
            target_read_u16(target, onenand->base_offset + O1N_REG_DEVICE_ID, &temp);
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

static int onenand_address(struct nand_device *nand, uint8_t address)
{
    struct onenand_controller *onenand = nand->controller_priv;
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

static int onenand_set_config1_bit(struct nand_device *nand, uint16_t flag) {
    struct onenand_controller *onenand = nand->controller_priv;
    struct target *target = nand->target;
    uint16_t temp;
    int status;

    LOG_DEBUG("ONLD: set bit at cfg1 0x%x", flag);

    status = target_read_u16(target, onenand->base_offset + O1N_REG_SYS_CFG1, &temp);
    if (status != ERROR_OK) {
        return status;
    }

    target_write_u16(target, onenand->base_offset + O1N_REG_SYS_CFG1, temp | flag);

    return ERROR_OK;
}

static int onenand_clear_config1_bit(struct nand_device *nand, uint16_t flag) {
    struct onenand_controller *onenand = nand->controller_priv;
    struct target *target = nand->target;
    uint16_t temp;
    int status;

    LOG_DEBUG("ONLD: clear bit at cfg1 0x%x", flag);

    status = target_read_u16(target, onenand->base_offset + O1N_REG_SYS_CFG1, &temp);
    if (status != ERROR_OK) {
        return status;
    }

    target_write_u16(target, onenand->base_offset + O1N_REG_SYS_CFG1, temp & ~flag);

    return ERROR_OK;
}



static int onenand_reset(struct nand_device *nand)
{
    struct onenand_controller *onenand = nand->controller_priv;
    struct target *target = nand->target;

    LOG_DEBUG("ONLD: reset");

    target_write_u16(target, onenand->base_offset + O1N_REG_INTERRUPT, 0x0);
    target_write_u16(target, onenand->base_offset + O1N_REG_COMMAND, O1N_CMD_HOT_RESET);

    return onenand_ready(nand, 1000) ? ERROR_OK : ERROR_NAND_OPERATION_FAILED;
}

static int onenand_read_data(struct nand_device *nand, void *data)
{
	struct onenand_controller *onenand = nand->controller_priv;
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

static int onenand_read_page(struct nand_device *nand, uint32_t page, uint8_t *data, uint32_t data_size, uint8_t *oob, uint32_t oob_size) {
    struct onenand_controller *onenand = nand->controller_priv;
    struct target *target = nand->target;
    bool flash_is_ddp;
    uint32_t onld_mask;

    if (onenand->ecc) {
        onenand_clear_config1_bit(nand, 0x100);
    } else {
        onenand_set_config1_bit(nand, 0x100);
    }

    LOG_DEBUG("ONLD: read page %d", page);

    target_write_u16(target, onenand->base_offset + O1N_REG_INTERRUPT, 0x0);
    target_write_u16(target, onenand->base_offset + O1N_REG_ECC_STATUS, 0x0);
    target_write_u16(target, onenand->base_offset + O1N_REG_START_BUFFER, (8 << 8));
    
    onld_mask = ((nand->device->id & 8) ? ((nand->device->chip_size << 3) / 2) : (nand->device->chip_size << 3)) - 1;
    LOG_DEBUG("ONLD: mask 0x%04x", onld_mask);

    flash_is_ddp = (bool)((nand->device->id & 8) && ((page >> 6) >= ((uint32_t)(nand->device->chip_size << 3) / 2)));
    target_write_u16(target, onenand->base_offset + O1N_REG_START_ADDRESS1, (flash_is_ddp ? 0x8000 : 0x0) | ((page >> 6) & onld_mask));
    target_write_u16(target, onenand->base_offset + O1N_REG_START_ADDRESS2, flash_is_ddp ? 0x8000 : 0x0);
    target_write_u16(target, onenand->base_offset + O1N_REG_START_ADDRESS8, (page & 63) << 2);

    target_write_u16(target, onenand->base_offset + O1N_REG_COMMAND, O1N_CMD_READ);
    if (!onenand_ready_flag(nand, 2000, 0x8080)) {
        LOG_ERROR("timeout waiting for read to complete");
        return ERROR_NAND_OPERATION_FAILED;
    }

    target_read_memory(target, onenand->base_offset + O1N_DATARAM, 1, data_size, data);
    target_read_memory(target, onenand->base_offset + O1N_SPARERAM, 1, oob_size, oob);

    return ERROR_OK;    
}

static int onenand_write_page(struct nand_device *nand, uint32_t page, uint8_t *data, uint32_t data_size, uint8_t *oob, uint32_t oob_size) {
    struct onenand_controller *onenand = nand->controller_priv;
    struct target *target = nand->target;
    bool flash_is_ddp;
    int result;
    uint16_t status;
    uint32_t onld_mask;

    if (onenand->ecc) {
        onenand_clear_config1_bit(nand, 0x100);
    } else {
        onenand_set_config1_bit(nand, 0x100);
    }

    LOG_DEBUG("ONLD: write page %d", page);

    target_write_u16(target, onenand->base_offset + O1N_REG_INTERRUPT, 0x0);
    target_write_u16(target, onenand->base_offset + O1N_REG_ECC_STATUS, 0x0);
    target_write_u16(target, onenand->base_offset + O1N_REG_START_BUFFER, (8 << 8));

    onld_mask = ((nand->device->id & 8) ? ((nand->device->chip_size << 3) / 2) : (nand->device->chip_size << 3)) - 1;
    LOG_DEBUG("ONLD: mask 0x%04x", onld_mask);

    flash_is_ddp = (bool)((nand->device->id & 8) && ((page >> 6) >= ((uint32_t)(nand->device->chip_size << 3) / 2)));
    target_write_u16(target, onenand->base_offset + O1N_REG_START_ADDRESS1, (flash_is_ddp ? 0x8000 : 0x0) | ((page >> 6) & onld_mask));
    target_write_u16(target, onenand->base_offset + O1N_REG_START_ADDRESS2, flash_is_ddp ? 0x8000 : 0x0);
    target_write_u16(target, onenand->base_offset + O1N_REG_START_ADDRESS8, (page & 63) << 2);

    target_write_memory(target, onenand->base_offset + O1N_DATARAM, 1, data_size, data);
    target_write_memory(target, onenand->base_offset + O1N_SPARERAM, 1, oob_size, oob);

    target_write_u16(target, onenand->base_offset + O1N_REG_COMMAND, O1N_CMD_PROG);
    if (!onenand_ready_flag(nand, 2000, 0x8040)) {
        LOG_ERROR("timeout waiting for write to complete");
        return ERROR_NAND_OPERATION_FAILED;
    }

    result = target_read_u16(target, onenand->base_offset + O1N_REG_CTRL_STATUS, &status);
    if (result != ERROR_OK)
    {
        LOG_ERROR("Could not read REG_CTRL_STATUS");
        return ERROR_NAND_OPERATION_FAILED;
    }
    
    return (status & 0x400) ? ERROR_NAND_OPERATION_FAILED : ERROR_OK;
}

static int onenand_erase_page(struct nand_device *nand, uint32_t page) {
    struct onenand_controller *onenand = nand->controller_priv;
    struct target *target = nand->target;
    bool flash_is_ddp;
    int result;
    uint16_t status; 
    uint32_t onld_mask;

    LOG_DEBUG("ONLD: erase page %d", page);

    target_write_u16(target, onenand->base_offset + O1N_REG_INTERRUPT, 0x0);    

    onld_mask = ((nand->device->id & 8) ? ((nand->device->chip_size << 3) / 2) : (nand->device->chip_size << 3)) - 1;
    LOG_DEBUG("ONLD: mask 0x%04x", onld_mask);

    flash_is_ddp = (bool)((nand->device->id & 8) && ((page >> 6) >= ((uint32_t)(nand->device->chip_size << 3) / 2)));
    target_write_u16(target, onenand->base_offset + O1N_REG_START_ADDRESS1, (flash_is_ddp ? 0x8000 : 0x0) | ((page >> 6) & onld_mask));
    target_write_u16(target, onenand->base_offset + O1N_REG_START_ADDRESS2, flash_is_ddp ? 0x8000 : 0x0);
    target_write_u16(target, onenand->base_offset + O1N_REG_START_ADDRESS8, 0);

    target_write_u16(target, onenand->base_offset + O1N_REG_COMMAND, O1N_CMD_ERASE);
    if (!onenand_ready_flag(nand, 2000, 0x8020)) {
        LOG_ERROR("timeout waiting for erase to complete");
        return ERROR_NAND_OPERATION_FAILED;
    }

    result = target_read_u16(target, onenand->base_offset + O1N_REG_CTRL_STATUS, &status);
    if (result != ERROR_OK)
    {
        LOG_ERROR("Could not read REG_CTRL_STATUS");
        return ERROR_NAND_OPERATION_FAILED;
    }
    
    return (status & 0x400) ? ERROR_NAND_OPERATION_FAILED : ERROR_OK;
}

NAND_DEVICE_COMMAND_HANDLER(onenand_device_command)
{
    struct onenand_controller *onenand;

    if (CMD_ARGC != 4)
        return ERROR_COMMAND_SYNTAX_ERROR;

    onenand = calloc(1, sizeof(struct onenand_controller));
    if (!onenand)
    {
        LOG_ERROR("no memory for nand controller");
        return ERROR_NAND_DEVICE_INVALID;
    }

    nand->controller_priv = onenand;
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[2], onenand->base_offset);
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[3], onenand->page_size);
    onenand->ecc = true;
    
    return ERROR_OK;
}

static int onenand_init(struct nand_device *nand)
{
    struct onenand_controller *onenand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    /* inform calling code about selected bus width */
    nand->nand_type = NAND_TYPE_ONENAND;
    nand->bus_width = 16;
    nand->page_size = onenand->page_size;   

    target_write_u16(target, onenand->base_offset + O1N_REG_SYS_CFG1, 0x40c0);

    target_write_u16(target, onenand->base_offset + O1N_REG_START_ADDRESS1, 0x0);
    target_write_u16(target, onenand->base_offset + O1N_REG_START_ADDRESS2, 0x0);

    return ERROR_OK;
}

/* Command handlers */
#define BOOL_SETTER(name, setter, desc)                                        \
    COMMAND_HANDLER(name)                                                      \
    {                                                                          \
        struct nand_device *nand = NULL;                                       \
        struct onenand_controller *p = NULL;                                   \
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
        struct onenand_controller *p = NULL;                              \
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

INT_SETTER(handle_onenand_base_offset_command, p->base_offset, "0x%x", "Base offset")
INT_SETTER(handle_onenand_page_size_command, p->page_size, "0x%x", "Page size")
BOOL_SETTER(handle_onenand_ecc_command, p->ecc, "ECC")

static const struct command_registration onenand_sub_command_handlers[] = {
    {
        .name = "base_offset",
        .handler = handle_onenand_base_offset_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [base_offset]",
    },
    {
        .name = "page_size",
        .handler = handle_onenand_page_size_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [page_size]",
    },
    {
        .name = "ecc",
        .handler = handle_onenand_ecc_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [ecc]",
    },
    COMMAND_REGISTRATION_DONE};

static const struct command_registration onenand_commands[] = {
    {
        .name = "onenand",
        .mode = COMMAND_ANY,
        .help = "OneNAND NAND flash controller commands",
        .usage = "",
        .chain = onenand_sub_command_handlers,
    },
    COMMAND_REGISTRATION_DONE};

struct nand_flash_controller onenand_controller = {
    .name = "onenand",
    .usage = "<target_id> <base_offset> <page_size>",
    .command = onenand_command,
    .address = onenand_address,
    .read_data = onenand_read_data,
    .read_page = onenand_read_page,
    .write_page = onenand_write_page,
    .nand_ready = onenand_ready,
    .reset = onenand_reset,
    .nand_device_command = onenand_device_command,
    .init = onenand_init,    
    .commands = onenand_commands,
    .read1_supported = false,
};
