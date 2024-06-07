// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2024 Dumpit                                             *
 *                                                                         *
 ***************************************************************************/

/*
 * PNX NAND controller
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imp.h"
#include "arm_io.h"
#include <target/arm.h>
#include "pnx.h"

struct pnx6_nand_controller
{
    struct arm_nand_data io;
    uint32_t base_offset;
    bool ecc;
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

static int pnx6_nand_command(struct nand_device *nand, uint8_t command)
{
    struct pnx6_nand_controller *pnx6_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;
    
    LOG_DEBUG("PNX NANDC: cmd 0x%x at 0x%x", command, pnx6_nand->base_offset + PNX6_REG_CMD);
    target_write_u32(target, pnx6_nand->base_offset + PNX6_REG_CMD, command);

    return ERROR_OK;
}

static int pnx6_nand_address(struct nand_device *nand, uint8_t address)
{
    struct pnx6_nand_controller *pnx6_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    LOG_DEBUG("PNX NANDC: addr 0x%x at 0x%x", address, pnx6_nand->base_offset + PNX6_REG_ADDR);
    target_write_u32(target, pnx6_nand->base_offset + PNX6_REG_ADDR, address);

    return ERROR_OK;
}

static int pnx6_nand_read(struct nand_device *nand, void *data)
{
    struct pnx6_nand_controller *pnx6_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    LOG_DEBUG("PNX NANDC: read at 0x%x", pnx6_nand->base_offset + PNX6_REG_DATA);
    target_read_u32(target, pnx6_nand->base_offset + PNX6_REG_DATA, data);

    return ERROR_OK;
}

static int pnx6_nand_write(struct nand_device *nand, uint16_t data)
{
    struct pnx6_nand_controller *pnx6_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    LOG_DEBUG("PNX NANDC: write at 0x%x", pnx6_nand->base_offset + PNX6_REG_DATA);
    target_write_u32(target, pnx6_nand->base_offset + PNX6_REG_DATA, data);

    return ERROR_OK;
}

static int pnx6_nand_read_block_data(struct nand_device *nand,
                                        uint8_t *data, int data_size)
{
    struct pnx6_nand_controller *pnx6_nand = nand->controller_priv;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    pnx6_nand->io.chunk_size = nand->page_size;

    /* try the fast way first */
    result = arm_nandread(&pnx6_nand->io, data, data_size);
    if (result != ERROR_NAND_NO_BUFFER)
        return result;

    /* else do it slowly */
    while (data_size--)
        pnx6_nand_read(nand, data++);

    return ERROR_OK;
}

static int pnx6_nand_write_block_data(struct nand_device *nand,
                                         uint8_t *data, int data_size)
{
    struct pnx6_nand_controller *pnx6_nand = nand->controller_priv;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    pnx6_nand->io.chunk_size = nand->page_size;

    /* try the fast way first */
    result = arm_nandwrite(&pnx6_nand->io, data, data_size);
    if (result != ERROR_NAND_NO_BUFFER)
        return result;

    /* else do it slowly */
    while (data_size--)
        pnx6_nand_write(nand, *data++);

    return ERROR_OK;
}

static int pnx6_nand_reset(struct nand_device *nand)
{
    return pnx6_nand_command(nand, NAND_CMD_RESET);
}

static int pnx6_nand_ready(struct nand_device *nand, int timeout)
{
    struct pnx6_nand_controller *pnx6_nand = nand->controller_priv;
    struct target *target = nand->target;
    uint32_t status;
    int retval;

    LOG_DEBUG("pnx6_wait_timeout count start=%d", timeout);

    do
    {        
        retval = GET_BIT32(target, pnx6_nand->base_offset + PNX6_REG_STAT, PNX6_STAT_RDY, &status);
        if (retval != ERROR_OK)
		{
			LOG_ERROR("Could not read REG_STATUS");
			return 0;
		}

        if (!status)
		{
			LOG_DEBUG("pnx6_wait_timeout count=%d", timeout);
			return 1;
		}

        alive_sleep(1);
    } while (timeout-- > 0);

    return 0;
}

NAND_DEVICE_COMMAND_HANDLER(pnx6_nand_device_command)
{
    struct pnx6_nand_controller *pnx6_nand;

    pnx6_nand = calloc(1, sizeof(struct pnx6_nand_controller));
    if (!pnx6_nand)
    {
        LOG_ERROR("no memory for nand controller");
        return ERROR_NAND_DEVICE_INVALID;
    }

    nand->controller_priv = pnx6_nand;
    
    pnx6_nand->base_offset = 0xc1300000;
    pnx6_nand->ecc = true;

    return ERROR_OK;
}

static int pnx6_nand_init(struct nand_device *nand)
{
    struct pnx6_nand_controller *pnx6_nand = nand->controller_priv;
    struct target *target = nand->target;
    int bus_width = nand->bus_width ? nand->bus_width : 8;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    /* inform calling code about selected bus width */
    nand->bus_width = bus_width;

    pnx6_nand->io.target = target;
    pnx6_nand->io.data = pnx6_nand->base_offset + PNX6_REG_DATA;
    pnx6_nand->io.op = ARM_NAND_NONE;
    pnx6_nand->io.data_width = 32;
    pnx6_nand->io.read_width = bus_width;

    SET_BIT32(target, pnx6_nand->base_offset + PNX6_REG_CONFIG, PNX6_CFG_WIDTH, bus_width == 16);
    SET_BIT32(target, pnx6_nand->base_offset + PNX6_REG_CONFIG, PNX6_CFG_ECC, pnx6_nand->ecc);

    return ERROR_OK;
}

/* Command handlers */
#define BOOL_SETTER(name, setter, desc)                                        \
    COMMAND_HANDLER(name)                                                      \
    {                                                                          \
        struct nand_device *nand = NULL;                                       \
        struct pnx6_nand_controller *p = NULL;                              \
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
        struct pnx6_nand_controller *p = NULL;                              \
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

INT_SETTER(handle_pnx6_base_offset_command, p->base_offset, "0x%x", "Base offset")
BOOL_SETTER(handle_pnx6_ecc_command, p->ecc, "Hardware ECC")

static const struct command_registration pnx6_sub_command_handlers[] = {
    {
        .name = "base_offset",
        .handler = handle_pnx6_base_offset_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [base_offset]",
    },
    {
        .name = "ecc",
        .handler = handle_pnx6_ecc_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [ecc]",
    },
    COMMAND_REGISTRATION_DONE};

static const struct command_registration pnx6_nand_commands[] = {
    {
        .name = "pnx6",
        .mode = COMMAND_ANY,
        .help = "PNX67xx NAND flash controller commands",
        .usage = "",
        .chain = pnx6_sub_command_handlers,
    },
    COMMAND_REGISTRATION_DONE};

struct nand_flash_controller pnx6_nand_controller = {
    .name = "pnx6",
    .usage = "<target_id>",
    .command = pnx6_nand_command,
    .address = pnx6_nand_address,
    .read_data = pnx6_nand_read,
    .write_data = pnx6_nand_write,
    .write_block_data = pnx6_nand_write_block_data,
    .read_block_data = pnx6_nand_read_block_data,
    .nand_ready = pnx6_nand_ready,
    .reset = pnx6_nand_reset,
    .nand_device_command = pnx6_nand_device_command,
    .init = pnx6_nand_init,
    .commands = pnx6_nand_commands,
    .read1_supported = true,
};
