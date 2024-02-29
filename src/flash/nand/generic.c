// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2024 Dumpit                                             *
 *                                                                         *
 ***************************************************************************/

/*
 * Generic NAND controllers
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imp.h"
#include "arm_io.h"
#include <target/arm.h>

struct generic_nand_controller
{
    struct arm_nand_data io;
    uint32_t ale;
    uint32_t ale_mask;

    uint32_t cle;
    uint32_t cle_mask;

    uint32_t re;

    uint32_t ale_width;
    uint32_t cle_width;
    uint32_t re_width;

    uint32_t rb;

    uint32_t rb_width;
    uint32_t rb_mask;

    uint32_t last_command;
    bool rb_inverted;
    bool is_gpio;
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

static int generic_nand_command(struct nand_device *nand, uint8_t command)
{
    struct generic_nand_controller *generic_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    uint32_t temp;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    generic_nand->last_command = command;
    LOG_DEBUG("NANDC: cmd 0x%x at 0x%x", command, generic_nand->cle);

    if (generic_nand->is_gpio)
    {
        switch (generic_nand->cle_width)
        {
        case 8:
            result = target_read_u8(target, generic_nand->cle, (uint8_t *)&temp);
            if (result != ERROR_OK)
                return ERROR_NAND_OPERATION_FAILED;

            target_write_u8(target, generic_nand->cle, temp | generic_nand->cle_mask);
            break;
        case 16:
            result = target_read_u16(target, generic_nand->cle, (uint16_t *)&temp);
            if (result != ERROR_OK)
                return ERROR_NAND_OPERATION_FAILED;

            target_write_u16(target, generic_nand->cle, temp | generic_nand->cle_mask);
            break;
        case 32:
            result = target_read_u32(target, generic_nand->cle, (uint32_t *)&temp);
            if (result != ERROR_OK)
                return ERROR_NAND_OPERATION_FAILED;

            target_write_u32(target, generic_nand->cle, temp | generic_nand->cle_mask);
        }

        switch (generic_nand->re_width)
        {
        case 8:
            target_write_u8(target, generic_nand->re, command);
            break;
        case 16:
            target_write_u16(target, generic_nand->re, command);
            break;
        case 32:
            target_write_u32(target, generic_nand->re, command);
        }

        switch (generic_nand->cle_width)
        {
        case 8:
            result = target_read_u8(target, generic_nand->cle, (uint8_t *)&temp);
            if (result != ERROR_OK)
                return ERROR_NAND_OPERATION_FAILED;

            target_write_u8(target, generic_nand->cle, temp & ~generic_nand->cle_mask);
            break;
        case 16:
            result = target_read_u16(target, generic_nand->cle, (uint16_t *)&temp);
            if (result != ERROR_OK)
                return ERROR_NAND_OPERATION_FAILED;

            target_write_u16(target, generic_nand->cle, temp & ~generic_nand->cle_mask);
            break;
        case 32:
            result = target_read_u32(target, generic_nand->cle, (uint32_t *)&temp);
            if (result != ERROR_OK)
                return ERROR_NAND_OPERATION_FAILED;

            target_write_u32(target, generic_nand->cle, temp & ~generic_nand->cle_mask);
        }
    }
    else
    {
        switch (generic_nand->cle_width)
        {
        case 8:
            target_write_u8(target, generic_nand->cle, command);
            break;
        case 16:
            target_write_u16(target, generic_nand->cle, command);
            break;
        case 32:
            target_write_u32(target, generic_nand->cle, command);
        }
    }

    return ERROR_OK;
}

static int generic_nand_address(struct nand_device *nand, uint8_t address)
{
    struct generic_nand_controller *generic_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    uint32_t temp;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    LOG_DEBUG("NANDC: addr 0x%x at 0x%x", address, generic_nand->ale);

    if (generic_nand->is_gpio)
    {
        switch (generic_nand->ale_width)
        {
        case 8:
            result = target_read_u8(target, generic_nand->ale, (uint8_t *)&temp);
            if (result != ERROR_OK)
                return ERROR_NAND_OPERATION_FAILED;

            target_write_u8(target, generic_nand->ale, temp | generic_nand->ale_mask);
            break;
        case 16:
            result = target_read_u16(target, generic_nand->ale, (uint16_t *)&temp);
            if (result != ERROR_OK)
                return ERROR_NAND_OPERATION_FAILED;

            target_write_u16(target, generic_nand->ale, temp | generic_nand->ale_mask);
            break;
        case 32:
            result = target_read_u32(target, generic_nand->ale, (uint32_t *)&temp);
            if (result != ERROR_OK)
                return ERROR_NAND_OPERATION_FAILED;

            target_write_u32(target, generic_nand->ale, temp | generic_nand->ale_mask);
        }

        switch (generic_nand->re_width)
        {
        case 8:
            target_write_u8(target, generic_nand->re, address);
            break;
        case 16:
            target_write_u16(target, generic_nand->re, address);
            break;
        case 32:
            target_write_u32(target, generic_nand->re, address);
        }

        switch (generic_nand->ale_width)
        {
        case 8:
            result = target_read_u8(target, generic_nand->ale, (uint8_t *)&temp);
            if (result != ERROR_OK)
                return ERROR_NAND_OPERATION_FAILED;

            target_write_u8(target, generic_nand->ale, temp & ~generic_nand->ale_mask);
            break;
        case 16:
            result = target_read_u16(target, generic_nand->ale, (uint16_t *)&temp);
            if (result != ERROR_OK)
                return ERROR_NAND_OPERATION_FAILED;

            target_write_u16(target, generic_nand->ale, temp & ~generic_nand->ale_mask);
            break;
        case 32:
            result = target_read_u32(target, generic_nand->ale, (uint32_t *)&temp);
            if (result != ERROR_OK)
                return ERROR_NAND_OPERATION_FAILED;

            target_write_u32(target, generic_nand->ale, temp & ~generic_nand->ale_mask);
        }
    }
    else
    {
        switch (generic_nand->ale_width)
        {
        case 8:
            target_write_u8(target, generic_nand->ale, address);
            break;
        case 16:
            target_write_u16(target, generic_nand->ale, address);
            break;
        case 32:
            target_write_u32(target, generic_nand->ale, address);
        }
    }

    return ERROR_OK;
}

static int generic_nand_read(struct nand_device *nand, void *data)
{
    struct generic_nand_controller *generic_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    LOG_DEBUG("NANDC: read at 0x%x", generic_nand->re);

    switch (generic_nand->re_width)
    {
    case 8:
        target_read_u8(target, generic_nand->re, data);
        break;
    case 16:
        target_read_u16(target, generic_nand->re, data);
        break;
    case 32:
        target_read_u32(target, generic_nand->re, data);
    }

    return ERROR_OK;
}

static int generic_nand_write(struct nand_device *nand, uint16_t data)
{
    struct generic_nand_controller *generic_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    LOG_DEBUG("NANDC: write at 0x%x", generic_nand->re);

    switch (generic_nand->re_width)
    {
    case 8:
        target_write_u8(target, generic_nand->re, data);
        break;
    case 16:
        target_write_u16(target, generic_nand->re, data);
        break;
    case 32:
        target_write_u32(target, generic_nand->re, data);
    }
    return ERROR_OK;
}

static int generic_nand_read_block_data(struct nand_device *nand,
                                        uint8_t *data, int data_size)
{
    struct generic_nand_controller *generic_nand = nand->controller_priv;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    generic_nand->io.chunk_size = nand->page_size;

    /* try the fast way first */
    result = arm_nandread(&generic_nand->io, data, data_size);
    if (result != ERROR_NAND_NO_BUFFER)
        return result;

    /* else do it slowly */
    while (data_size--)
        generic_nand_read(nand, data++);

    return ERROR_OK;
}

static int generic_nand_write_block_data(struct nand_device *nand,
                                         uint8_t *data, int data_size)
{
    struct generic_nand_controller *generic_nand = nand->controller_priv;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    generic_nand->io.chunk_size = nand->page_size;

    /* try the fast way first */
    result = arm_nandwrite(&generic_nand->io, data, data_size);
    if (result != ERROR_NAND_NO_BUFFER)
        return result;

    /* else do it slowly */
    while (data_size--)
        generic_nand_write(nand, *data++);

    return ERROR_OK;
}

static int generic_nand_reset(struct nand_device *nand)
{
    return generic_nand_command(nand, NAND_CMD_RESET);
}

static int generic_nand_ready(struct nand_device *nand, int timeout)
{
    struct generic_nand_controller *generic_nand = nand->controller_priv;
    struct target *target = nand->target;
    uint32_t status;

    LOG_DEBUG("generic_wait_timeout count start=%d", timeout);

    do
    {
        status = 0;

        if (generic_nand->rb == generic_nand->re)
        {
            generic_nand_command(nand, NAND_CMD_STATUS);
            generic_nand_read(nand, &status);
            generic_nand_command(nand, generic_nand->last_command);

            if (status & NAND_STATUS_READY)
            {
                LOG_DEBUG("generic_wait_timeout count=%d", timeout);
                return 1;
            }
        }
        else if (generic_nand->rb_mask != 0)
        {
            switch (generic_nand->rb_width)
            {
            case 8:
                target_read_u8(target, generic_nand->rb, (uint8_t *)&status);
                break;
            case 16:
                target_read_u16(target, generic_nand->rb, (uint16_t *)&status);
                break;
            case 32:
                target_read_u32(target, generic_nand->rb, (uint32_t *)&status);
            }

            if (status & generic_nand->rb_mask)
            {
                LOG_DEBUG("generic_wait_timeout count=%d", timeout);
                return 1;
            }
            else if (generic_nand->rb_inverted && !(status & generic_nand->rb_mask))
            {
                LOG_DEBUG("generic_wait_timeout count=%d", timeout);
                return 1;
            }
        }
        else
        {
            LOG_DEBUG("generic_wait_timeout isn't needed as it doesn't have rb");
            alive_sleep(1);
            return 1;
        }
        alive_sleep(1);
    } while (timeout-- > 0);

    return 0;
}

NAND_DEVICE_COMMAND_HANDLER(generic_nand_device_command)
{
    struct generic_nand_controller *generic_nand;

    if (CMD_ARGC != 5)
        return ERROR_COMMAND_SYNTAX_ERROR;

    generic_nand = calloc(1, sizeof(struct generic_nand_controller));
    if (!generic_nand)
    {
        LOG_ERROR("no memory for nand controller");
        return ERROR_NAND_DEVICE_INVALID;
    }

    nand->controller_priv = generic_nand;

    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[2], generic_nand->ale);
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[3], generic_nand->cle);
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[4], generic_nand->re);

    generic_nand->ale_mask = 0x1;
    generic_nand->cle_mask = 0x2;

    generic_nand->ale_width = 8;
    generic_nand->cle_width = 8;
    generic_nand->re_width = 8;

    generic_nand->rb = 0xffffffff;
    generic_nand->rb_width = 8;
    generic_nand->rb_mask = 0;

    generic_nand->last_command = 0;
    generic_nand->rb_inverted = false;
    generic_nand->is_gpio = false;

    return ERROR_OK;
}

static int generic_nand_init(struct nand_device *nand)
{
    struct generic_nand_controller *generic_nand = nand->controller_priv;
    struct target *target = nand->target;
    int bus_width = nand->bus_width ? nand->bus_width : 8;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    /* inform calling code about selected bus width */
    nand->bus_width = bus_width;

    generic_nand->io.target = target;
    generic_nand->io.data = generic_nand->re;
    generic_nand->io.op = ARM_NAND_NONE;
    generic_nand->io.data_width = generic_nand->re_width;

    return ERROR_OK;
}

/* Command handlers */
#define BOOL_SETTER(name, setter, desc)                                        \
    COMMAND_HANDLER(name)                                                      \
    {                                                                          \
        struct nand_device *nand = NULL;                                       \
        struct generic_nand_controller *p = NULL;                              \
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
        struct generic_nand_controller *p = NULL;                              \
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

INT_SETTER(handle_generic_ale_command, p->ale, "0x%x", "ALE")
INT_SETTER(handle_generic_ale_mask_command, p->ale_mask, "0x%x", "ALE mask")
INT_SETTER(handle_generic_cle_command, p->cle, "0x%x", "CLE")
INT_SETTER(handle_generic_cle_mask_command, p->cle_mask, "0x%x", "CLE mask")
INT_SETTER(handle_generic_re_command, p->re, "0x%x", "RE")
INT_SETTER(handle_generic_ale_width_command, p->ale_width, "%d", "ALE width")
INT_SETTER(handle_generic_cle_width_command, p->cle_width, "%d", "CLE width")
INT_SETTER(handle_generic_re_width_command, p->re_width, "%d", "RE width")
INT_SETTER(handle_generic_rb_command, p->rb, "0x%x", "RB")
INT_SETTER(handle_generic_rb_width_command, p->rb_width, "%d", "RB width")
INT_SETTER(handle_generic_rb_mask_command, p->rb_mask, "0x%x", "RB mask")
BOOL_SETTER(handle_generic_rb_invert_command, p->rb_inverted, "Inverted RB bits")
BOOL_SETTER(handle_generic_is_gpio_command, p->is_gpio, "Use GPIO")

static const struct command_registration generic_sub_command_handlers[] = {
    {
        .name = "ale",
        .handler = handle_generic_ale_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [ale]",
    },
    {
        .name = "cle",
        .handler = handle_generic_cle_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [cle]",
    },
    {
        .name = "ale_mask",
        .handler = handle_generic_ale_mask_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [ale_mask]",
    },
    {
        .name = "cle_mask",
        .handler = handle_generic_cle_mask_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [cle_mask]",
    },
    {
        .name = "re",
        .handler = handle_generic_re_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [re]",
    },
    {
        .name = "ale_width",
        .handler = handle_generic_ale_width_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [ale_width]",
    },
    {
        .name = "cle_width",
        .handler = handle_generic_cle_width_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [cle_width]",
    },
    {
        .name = "re_width",
        .handler = handle_generic_re_width_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [re_width]",
    },
    {
        .name = "rb",
        .handler = handle_generic_rb_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [rb]",
    },
    {
        .name = "rb_width",
        .handler = handle_generic_rb_width_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [rb_width]",
    },
    {
        .name = "rb_mask",
        .handler = handle_generic_rb_mask_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [rb_mask]",
    },
    {
        .name = "rb_inverted",
        .handler = handle_generic_rb_invert_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [rb_inverted]",
    },
    {
        .name = "is_gpio",
        .handler = handle_generic_is_gpio_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [is_gpio]",
    },
    COMMAND_REGISTRATION_DONE};

static const struct command_registration generic_nand_commands[] = {
    {
        .name = "nand_generic",
        .mode = COMMAND_ANY,
        .help = "Generic NAND flash controller commands",
        .usage = "",
        .chain = generic_sub_command_handlers,
    },
    COMMAND_REGISTRATION_DONE};

struct nand_flash_controller generic_nand_controller = {
    .name = "generic",
    .usage = "<target_id> <ale> <cle> <re>",
    .command = generic_nand_command,
    .address = generic_nand_address,
    .read_data = generic_nand_read,
    .write_data = generic_nand_write,
    .write_block_data = generic_nand_write_block_data,
    .read_block_data = generic_nand_read_block_data,
    .nand_ready = generic_nand_ready,
    .reset = generic_nand_reset,
    .nand_device_command = generic_nand_device_command,
    .init = generic_nand_init,
    .commands = generic_nand_commands,
};
