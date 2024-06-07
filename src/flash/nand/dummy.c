// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2024 Dumpit                                             *
 *                                                                         *
 ***************************************************************************/

/*
 * Dummy
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imp.h"
#include "arm_io.h"
#include <target/arm.h>

enum
{
    DUMMY_NAND_TYPE_SMALL_BLOCK_8BIT,  // 512;8
    DUMMY_NAND_TYPE_SMALL_BLOCK_16BIT, // 512;16
    DUMMY_NAND_TYPE_LARGE_BLOCK_8BIT,  // 2048;8
    DUMMY_NAND_TYPE_LARGE_BLOCK_16BIT, // 2048;16
};

struct dummy_nand_controller
{
    uint8_t nand_buffer[0x04200000];
    uint8_t nand_write_buffer[0x1080];
    uint32_t nand_type;
    uint8_t last_command;
    uint32_t address_cycles;
    uint32_t ra;
    uint32_t wa;
    uint32_t pa;
    uint32_t da;
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

static int dummy_nand_command(struct nand_device *nand, uint8_t command)
{
    struct dummy_nand_controller *dummy_nand = nand->controller_priv;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    LOG_INFO("DUMMY NANDC: cmd 0x%x", command);
    dummy_nand->last_command = command;

    if ((command != NAND_CMD_PAGEPROG) && (command != NAND_CMD_ERASE2) && (command != NAND_CMD_READSTART))
    {
        dummy_nand->da = 0;
        dummy_nand->pa = 0;
        dummy_nand->address_cycles = 0;
        switch (command)
        {        
        case NAND_CMD_SEQIN:
            if (nand->page_size >= 512) dummy_nand->ra = 0;
            dummy_nand->wa = dummy_nand->ra;
            break;        
        case NAND_CMD_READ1:
            dummy_nand->ra = 256;
            break;
        case NAND_CMD_READOOB:
            dummy_nand->ra = 512;
            break;
        case NAND_CMD_READ0:
        case NAND_CMD_READID:
        default:
            dummy_nand->ra = 0;
            break;
        }
    }
    else if (command == NAND_CMD_ERASE2)
    {
        memset(dummy_nand->nand_buffer + (dummy_nand->pa * (nand->page_size + (nand->page_size <= 512 ? 16 : 64))), 0xff, nand->page_size);
    }
    else if (command == NAND_CMD_PAGEPROG)
    {
        LOG_INFO("DUMMY NANDC: PROG: 0x%x DEST", (dummy_nand->pa * (nand->page_size + (nand->page_size <= 512 ? 16 : 64))) + dummy_nand->da + dummy_nand->wa);
        memcpy(dummy_nand->nand_buffer + (dummy_nand->pa * (nand->page_size + (nand->page_size <= 512 ? 16 : 64))) + dummy_nand->da + dummy_nand->wa, dummy_nand->nand_write_buffer, dummy_nand->ra - dummy_nand->wa);
    }

    return ERROR_OK;
}

static int dummy_nand_address(struct nand_device *nand, uint8_t address)
{
    struct dummy_nand_controller *dummy_nand = nand->controller_priv;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    LOG_INFO("DUMMY NANDC: addr 0x%x", address);

    if (dummy_nand->last_command == NAND_CMD_ERASE1)
    {
        dummy_nand->pa |= address << (8 * dummy_nand->address_cycles);
    }
    else
    {
        switch (dummy_nand->nand_type)
        {
        case DUMMY_NAND_TYPE_SMALL_BLOCK_8BIT:
        case DUMMY_NAND_TYPE_SMALL_BLOCK_16BIT:
            if (dummy_nand->address_cycles > 0)
            {
                dummy_nand->pa |= address << (8 * (dummy_nand->address_cycles - 1));
            }
            else
            {
                dummy_nand->da |= address << (8 * dummy_nand->address_cycles);
            }
            break;
        case DUMMY_NAND_TYPE_LARGE_BLOCK_8BIT:
        case DUMMY_NAND_TYPE_LARGE_BLOCK_16BIT:
            if (dummy_nand->address_cycles > 1)
            {
                dummy_nand->pa |= address << (8 * (dummy_nand->address_cycles - 2));
            }
            else
            {
                dummy_nand->da |= address << (8 * dummy_nand->address_cycles);
            }
            break;
        default:
            LOG_ERROR("it shouldn't have happened");
            exit(-1);
        }
    }

    dummy_nand->address_cycles++;

    return ERROR_OK;
}

static int dummy_nand_read(struct nand_device *nand, void *data)
{
    struct dummy_nand_controller *dummy_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    LOG_INFO("DUMMY NANDC: read at 0x%x PA, 0x%x DA, 0x%x RA, 0x%x DTA", dummy_nand->pa, dummy_nand->da, dummy_nand->ra, (dummy_nand->pa * (nand->page_size + (nand->page_size <= 512 ? 16 : 64))) + dummy_nand->da + dummy_nand->ra);

    if (dummy_nand->last_command == NAND_CMD_READID)
    {
        switch (dummy_nand->ra++)
        {
        case 0:
            *(uint8_t *)data = 0xec;
            break;
        case 1:
            switch (dummy_nand->nand_type)
            {
            case DUMMY_NAND_TYPE_SMALL_BLOCK_8BIT:
                *(uint8_t *)data = 0x36;
                break;
            case DUMMY_NAND_TYPE_SMALL_BLOCK_16BIT:
                *(uint8_t *)data = 0x46;
                break;
            case DUMMY_NAND_TYPE_LARGE_BLOCK_8BIT:
                *(uint8_t *)data = 0xa2;
                break;
            case DUMMY_NAND_TYPE_LARGE_BLOCK_16BIT:
                *(uint8_t *)data = 0xb2;
                break;
            default:
                LOG_ERROR("it shouldn't have happened");
                exit(-1);
            }
            break;
        case 2:
            *(uint8_t *)data = 0x00;
            break;
        case 3:
            *(uint8_t *)data = dummy_nand->nand_type < 2 ? 0xc0 : 0x55;
            break;
        default:
            *(uint8_t *)data = 0xff;
        }
    }
    else if (dummy_nand->last_command == NAND_CMD_STATUS)
    {
        *(uint8_t *)data = NAND_STATUS_TRUE_READY | NAND_STATUS_READY | NAND_STATUS_WP;
    }
    else
    {
        if (dummy_nand->nand_type & 1)
        {
            *(uint16_t *)data = target_buffer_get_u16(target, &dummy_nand->nand_buffer[(dummy_nand->pa * (nand->page_size + (nand->page_size <= 512 ? 16 : 64))) + dummy_nand->da + dummy_nand->ra]);
            dummy_nand->ra += 2;
        }
        else
        {
            *(uint8_t *)data = dummy_nand->nand_buffer[(dummy_nand->pa * (nand->page_size + (nand->page_size <= 512 ? 16 : 64))) + dummy_nand->da + (dummy_nand->ra++)];
        }
    }

    return ERROR_OK;
}

static int dummy_nand_write(struct nand_device *nand, uint16_t data)
{
    struct dummy_nand_controller *dummy_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    LOG_INFO("DUMMY NANDC: write at 0x%x PA, 0x%x DA, 0x%x RA, 0x%x WA, 0x%x DTA", dummy_nand->pa, dummy_nand->da, dummy_nand->ra, dummy_nand->wa, dummy_nand->da + dummy_nand->ra - dummy_nand->wa);

    if (dummy_nand->nand_type & 1)
    {
        target_buffer_set_u16(target, &dummy_nand->nand_write_buffer[dummy_nand->da + dummy_nand->ra - dummy_nand->wa], data);
        dummy_nand->ra += 2;
    }
    else
    {
        dummy_nand->nand_write_buffer[dummy_nand->da + (dummy_nand->ra++) - dummy_nand->wa] = (uint16_t)data;
    }

    return ERROR_OK;
}

static int dummy_nand_reset(struct nand_device *nand)
{
    return dummy_nand_command(nand, NAND_CMD_RESET);
}

static int dummy_nand_ready(struct nand_device *nand, int timeout)
{
    return 1;
}

NAND_DEVICE_COMMAND_HANDLER(dummy_nand_device_command)
{
    struct dummy_nand_controller *dummy_nand;

    dummy_nand = calloc(1, sizeof(struct dummy_nand_controller));
    if (!dummy_nand)
    {
        LOG_ERROR("no memory for nand controller");
        return ERROR_NAND_DEVICE_INVALID;
    }

    nand->controller_priv = dummy_nand;
    nand->nand_type = 0;

    return ERROR_OK;
}

static int dummy_nand_init(struct nand_device *nand)
{
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    return ERROR_OK;
}

/* Command handlers */
#define BOOL_SETTER(name, setter, desc)                                        \
    COMMAND_HANDLER(name)                                                      \
    {                                                                          \
        struct nand_device *nand = NULL;                                       \
        struct dummy_nand_controller *p = NULL;                                \
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
        struct dummy_nand_controller *p = NULL;                                \
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

INT_SETTER(handle_dummy_type_command, p->nand_type, "0x%x", "Dummy NAND type")

static const struct command_registration dummy_sub_command_handlers[] = {
    {
        .name = "type",
        .handler = handle_dummy_type_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [type]",
    },
    COMMAND_REGISTRATION_DONE};

static const struct command_registration dummy_nand_commands[] = {
    {
        .name = "nand_dummy",
        .mode = COMMAND_ANY,
        .help = "dummy NAND flash controller commands",
        .usage = "",
        .chain = dummy_sub_command_handlers,
    },
    COMMAND_REGISTRATION_DONE};

struct nand_flash_controller dummy_nand_controller = {
    .name = "dummy",
    .usage = "<target_id>",
    .command = dummy_nand_command,
    .address = dummy_nand_address,
    .read_data = dummy_nand_read,
    .write_data = dummy_nand_write,
    .nand_ready = dummy_nand_ready,
    .reset = dummy_nand_reset,
    .nand_device_command = dummy_nand_device_command,
    .init = dummy_nand_init,
    .commands = dummy_nand_commands,
    .read1_supported = true,
};
