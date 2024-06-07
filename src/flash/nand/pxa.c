// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2024 Dumpit                                             *
 *                                                                         *
 ***************************************************************************/

/*
 * PXA312 NAND Controller
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "bitutils.h"
#include "imp.h"
#include "arm_io.h"
#include <target/arm.h>
#include "pxa.h"

#include "debug.h"

struct pxa3_nand_controller
{
    struct arm_nand_data io;
    uint32_t device_id;
    uint8_t last_command;
    bool arbiter;

    uint32_t next_cycle;
    uint32_t temp_addr_buf;
    int data_position;
    bool executed;

    uint32_t temp_buffer;
    uint32_t buffer_bitpos;
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

static int pxa3_start(struct nand_device *nand)
{
    struct target *target = nand->target;

    target_write_u32(target, PXA3_REG_NDSR, 0xfff);
    SET_BIT32(target, PXA3_REG_NDCR, PXA3_NDCR_ND_RUN, 1);

    int timeout = PXA_NAND_TIMEOUT;
    LOG_DEBUG("PXA3 NANDC: cmd request timeout %d", timeout);

    do
    {
        uint32_t status;

        GET_BIT32(target, PXA3_REG_NDSR, PXA3_NDSR_WRCMDREQ, &status);

#ifdef NAND_CONTROLLER_DEBUG
        status = 1;
#endif

        if (status)
        {
            LOG_DEBUG("PXA3 NANDC: cmd request at %d", timeout);
            break;
        }

        alive_sleep(1);
    } while (timeout-- > 0);

    if (timeout <= 0)
    {
        LOG_ERROR("timeout waiting to start NAND operations");
        return ERROR_NAND_OPERATION_FAILED;
    }

    return ERROR_OK;
}

static int pxa3_end(struct nand_device *nand)
{
    struct target *target = nand->target;

    SET_BIT32(target, PXA3_REG_NDCR, PXA3_NDCR_ND_RUN, 0);

    return ERROR_OK;
}

static int pxa3_nand_ready(struct nand_device *nand, int timeout);

static int pxa3_reset(struct nand_device *nand)
{
    struct pxa3_nand_controller *pxa3_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = pxa3_start(nand);
    if (result != ERROR_OK)
        return result;

    target_write_u32(target, PXA3_REG_NDCB0, 0xff | (5 << PXA3_NDCB_CMD_TYPE.bit_pos) | (pxa3_nand->device_id << PXA3_NDCB_CSEL.bit_pos));
    target_write_u32(target, PXA3_REG_NDCB1, 0x00);
    target_write_u32(target, PXA3_REG_NDCB2, 0x00);

    int timeout = PXA_NAND_TIMEOUT;
    LOG_DEBUG("PXA3 NANDC: cmd reset timeout %d", timeout);

    do
    {
        uint32_t status;

        GET_BIT32(target, PXA3_REG_NDSR, pxa3_nand->device_id == 0 ? PXA3_NDSR_CS0_CMDD : PXA3_NDSR_CS1_CMDD, &status);

#ifdef NAND_CONTROLLER_DEBUG
        status = 1;
#endif

        if (status)
        {
            LOG_DEBUG("PXA3 NANDC: cmd reset at %d", timeout);
            break;
        }

        alive_sleep(1);
    } while (timeout-- > 0);

    if (timeout <= 0)
    {
        LOG_ERROR("timeout waiting to reset the NAND");
        return ERROR_NAND_OPERATION_FAILED;
    }

    if (!pxa3_nand_ready(nand, 1000))
    {
        LOG_WARNING("timeout waiting for ready status");
    }

    return ERROR_OK;
}

static int pxa3_read_id_start(struct nand_device *nand)
{
    struct pxa3_nand_controller *pxa3_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = pxa3_start(nand);
    if (result != ERROR_OK)
        return result;

    target_write_u32(target, PXA3_REG_NDCB0, 0x90 | (3 << PXA3_NDCB_CMD_TYPE.bit_pos) | (1 << PXA3_NDCB_ADDR_CYC.bit_pos) | (pxa3_nand->device_id << PXA3_NDCB_CSEL.bit_pos));
    target_write_u32(target, PXA3_REG_NDCB1, 0x00);
    target_write_u32(target, PXA3_REG_NDCB2, 0x00);

    int timeout = PXA_NAND_TIMEOUT;
    LOG_DEBUG("PXA3 NANDC: wait for data timeout %d", timeout);

    do
    {
        uint32_t status;

        GET_BIT32(target, PXA3_REG_NDSR, PXA3_NDSR_RDDREQ, &status);

#ifdef NAND_CONTROLLER_DEBUG
        status = 1;
#endif

        if (status)
        {
            LOG_DEBUG("PXA3 NANDC: wait for data done at %d", timeout);
            break;
        }

        alive_sleep(1);
    } while (timeout-- > 0);

    if (timeout <= 0)
    {
        LOG_ERROR("timeout waiting to send read ID request to the NAND");
        return ERROR_NAND_OPERATION_FAILED;
    }

    return ERROR_OK;
}

static int pxa3_read_status_start(struct nand_device *nand)
{
    struct pxa3_nand_controller *pxa3_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = pxa3_start(nand);
    if (result != ERROR_OK)
        return result;

    target_write_u32(target, PXA3_REG_NDCB0, 0x70 | (4 << PXA3_NDCB_CMD_TYPE.bit_pos) | (1 << PXA3_NDCB_ADDR_CYC.bit_pos) | (pxa3_nand->device_id << PXA3_NDCB_CSEL.bit_pos));
    target_write_u32(target, PXA3_REG_NDCB1, 0x00);
    target_write_u32(target, PXA3_REG_NDCB2, 0x00);

    int timeout = PXA_NAND_TIMEOUT;
    LOG_DEBUG("PXA3 NANDC: wait for data timeout %d", timeout);

    do
    {
        uint32_t status;

#ifdef NAND_CONTROLLER_DEBUG
        status = 1;
#endif

        GET_BIT32(target, PXA3_REG_NDSR, PXA3_NDSR_RDDREQ, &status);

        if (status)
        {
            LOG_DEBUG("PXA3 NANDC: wait for data done at %d", timeout);
            break;
        }

        alive_sleep(1);
    } while (timeout-- > 0);

    if (timeout <= 0)
    {
        LOG_ERROR("timeout waiting to send read status request to the NAND");
        return ERROR_NAND_OPERATION_FAILED;
    }

    return ERROR_OK;
}

static int pxa3_read_start(struct nand_device *nand, uint32_t page)
{
    struct pxa3_nand_controller *pxa3_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = pxa3_start(nand);
    if (result != ERROR_OK)
        return result;

    if (nand->page_size > 512)
    {
        target_write_u32(target, PXA3_REG_NDCB0, 0x3000 | (5 << PXA3_NDCB_ADDR_CYC.bit_pos) | (1 << PXA3_NDCB_DBC.bit_pos) | (pxa3_nand->device_id << PXA3_NDCB_CSEL.bit_pos));
        target_write_u32(target, PXA3_REG_NDCB1, (page << 16) & 0xffffffff);
        target_write_u32(target, PXA3_REG_NDCB2, (page >> 16) & 0xffffffff);
    }
    else
    {
        target_write_u32(target, PXA3_REG_NDCB0, 0x00 | (4 << PXA3_NDCB_ADDR_CYC.bit_pos) | (pxa3_nand->device_id << PXA3_NDCB_CSEL.bit_pos));
        target_write_u32(target, PXA3_REG_NDCB1, (page << 8) & 0xffffffff);
        target_write_u32(target, PXA3_REG_NDCB2, 0x00);
    }

    int timeout = PXA_NAND_TIMEOUT;
    LOG_DEBUG("PXA3 NANDC: wait for data timeout %d", timeout);

    do
    {
        uint32_t status;

#ifdef NAND_CONTROLLER_DEBUG
        status = 1;
#endif

        GET_BIT32(target, PXA3_REG_NDSR, PXA3_NDSR_RDDREQ, &status);

        if (status)
        {
            LOG_DEBUG("PXA3 NANDC: wait for data done at %d", timeout);
            break;
        }

        alive_sleep(1);
    } while (timeout-- > 0);

    if (timeout <= 0)
    {
        LOG_ERROR("timeout waiting to send read request to the NAND");
        return ERROR_NAND_OPERATION_FAILED;
    }

    return ERROR_OK;
}

/*
static int pxa3_write_start(struct nand_device *nand, uint32_t page) {
    struct pxa3_nand_controller *pxa3_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = pxa3_start(nand);
    if (result != ERROR_OK)
        return result;

    if (nand->page_size > 512) {
        target_write_u32(target, PXA3_REG_NDCB0, 0x80 | (5 << PXA3_NDCB_ADDR_CYC.bit_pos) | (pxa3_nand->device_id << PXA3_NDCB_CSEL.bit_pos));
        target_write_u32(target, PXA3_REG_NDCB1, (page << 16) & 0xffffffff);
        target_write_u32(target, PXA3_REG_NDCB2, (page >> 16) & 0xffffffff);
    } else {
        target_write_u32(target, PXA3_REG_NDCB0, 0x80 | (4 << PXA3_NDCB_ADDR_CYC.bit_pos) | (pxa3_nand->device_id << PXA3_NDCB_CSEL.bit_pos));
        target_write_u32(target, PXA3_REG_NDCB1, (page << 8) & 0xffffffff);
        target_write_u32(target, PXA3_REG_NDCB2, 0x00);
    }

    int timeout = PXA_NAND_TIMEOUT;

    do {
        uint32_t status;

        GET_BIT32(target, PXA3_REG_NDSR, PXA3_NDSR_WRDREQ, &status);

        if (status) {
            break;
        }

        alive_sleep(1);
    } while (timeout-- > 0);

    if (timeout <= 0) {
        LOG_ERROR("timeout waiting to send write request to the NAND");
        return ERROR_NAND_OPERATION_FAILED;
    }

    return ERROR_OK;
}
*/

static int pxa3_write_start(struct nand_device *nand, uint32_t page)
{
    struct pxa3_nand_controller *pxa3_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = pxa3_start(nand);
    if (result != ERROR_OK)
        return result;

    target_write_u32(target, PXA3_REG_NDCB0, 0x1080 | (1 << PXA3_NDCB_CMD_TYPE.bit_pos) | (pxa3_nand->device_id << PXA3_NDCB_CSEL.bit_pos) | (1 << PXA3_NDCB_ST_ROW_EN.bit_pos) | (1 << PXA3_NDCB_DBC.bit_pos) | ((nand->page_size > 512 ? 5 : 4) << PXA3_NDCB_ADDR_CYC.bit_pos));

    if (nand->page_size > 512)
    {
        target_write_u32(target, PXA3_REG_NDCB1, (page << 16) & 0xffffffff);
        target_write_u32(target, PXA3_REG_NDCB2, (page >> 16) & 0xffffffff);
    }
    else
    {
        target_write_u32(target, PXA3_REG_NDCB1, (page << 8) & 0xffffffff);
        target_write_u32(target, PXA3_REG_NDCB2, 0x00);
    }

    int timeout = PXA_NAND_TIMEOUT;
    LOG_DEBUG("PXA3 NANDC: wait for data input timeout %d", timeout);

    do
    {
        uint32_t status;

        GET_BIT32(target, PXA3_REG_NDSR, PXA3_NDSR_WRDREQ, &status);

#ifdef NAND_CONTROLLER_DEBUG
        status = 1;
#endif

        if (status)
        {
            LOG_DEBUG("PXA3 NANDC: wait for data input done at %d", timeout);
            break;
        }

        alive_sleep(1);
    } while (timeout-- > 0);

    if (timeout <= 0)
    {
        LOG_ERROR("timeout waiting to send write request to the NAND");
        return ERROR_NAND_OPERATION_FAILED;
    }

    return ERROR_OK;
}

static int pxa3_erase_start(struct nand_device *nand, uint32_t page)
{
    struct pxa3_nand_controller *pxa3_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = pxa3_start(nand);
    if (result != ERROR_OK)
        return result;

    target_write_u32(target, PXA3_REG_NDCB0, 0xd060 | (2 << PXA3_NDCB_CMD_TYPE.bit_pos) | (pxa3_nand->device_id << PXA3_NDCB_CSEL.bit_pos) | (1 << PXA3_NDCB_AUTO_RS.bit_pos) | (1 << PXA3_NDCB_DBC.bit_pos) | (3 << PXA3_NDCB_ADDR_CYC.bit_pos));

    target_write_u32(target, PXA3_REG_NDCB1, page);
    target_write_u32(target, PXA3_REG_NDCB2, 0x00);
    
    return ERROR_OK;
}

static int pxa3_nand_command(struct nand_device *nand, uint8_t command)
{
    struct pxa3_nand_controller *pxa3_nand = nand->controller_priv;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    LOG_DEBUG("PXA3 NANDC: cmd 0x%x", command);
    pxa3_nand->last_command = command;

    switch (command)
    {
    case NAND_CMD_RESET:
    case NAND_CMD_READ0:
    case NAND_CMD_READ1:
    case NAND_CMD_READOOB:
    case NAND_CMD_READID:
    case NAND_CMD_SEQIN:
    case NAND_CMD_ERASE1:
        LOG_DEBUG("PXA3 NANDC: reset io operation");
        pxa3_nand->next_cycle = 0;
        pxa3_nand->temp_addr_buf = 0;
        pxa3_nand->data_position = 0;
        /* fall through */
    case NAND_CMD_STATUS:
    case NAND_CMD_READSTART:
    case NAND_CMD_PAGEPROG:
    case NAND_CMD_ERASE2:
        pxa3_nand->executed = false;
        pxa3_nand->temp_buffer = 0;
        pxa3_nand->buffer_bitpos = 0;
        break;
    default:
        LOG_ERROR("NAND CMD operation 0x%x is not supported.", command);
    }

    return ERROR_OK;
}

static int pxa3_nand_address(struct nand_device *nand, uint8_t address)
{
    struct pxa3_nand_controller *pxa3_nand = nand->controller_priv;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    LOG_DEBUG("PXA3 NANDC: addr 0x%x, cycle %d", address, pxa3_nand->next_cycle);

    if (pxa3_nand->last_command != NAND_CMD_ERASE1)
    {
        if (nand->page_size > 512)
        {
            if (pxa3_nand->next_cycle > 1)
            {
                pxa3_nand->temp_addr_buf |= address << (8 * (pxa3_nand->next_cycle - 2));
            }
        }
        else
        {
            if (pxa3_nand->next_cycle > 0)
            {
                pxa3_nand->temp_addr_buf |= address << (8 * (pxa3_nand->next_cycle - 1));
            }
        }
    }
    else
    {
        pxa3_nand->temp_addr_buf |= address << (8 * pxa3_nand->next_cycle);
    }

    LOG_DEBUG("PXA3 NANDC: nand address buffer 0x%x = %d", pxa3_nand->temp_addr_buf, pxa3_nand->temp_addr_buf);

    pxa3_nand->next_cycle++;
    return ERROR_OK;
}

static int pxa3_nand_read(struct nand_device *nand, void *data)
{
    struct pxa3_nand_controller *pxa3_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    LOG_DEBUG("PXA3 NANDC: executed? %s", pxa3_nand->executed ? "yes" : "no");

    if (!pxa3_nand->executed)
    {
        pxa3_nand->executed = true;

        switch (pxa3_nand->last_command)
        {        
        case NAND_CMD_STATUS:
            LOG_DEBUG("PXA3 NANDC: execute status read function");
            result = pxa3_read_status_start(nand);
            if (result != ERROR_OK)
                return result;
            break;
        case NAND_CMD_READID:
            LOG_DEBUG("PXA3 NANDC: execute id read read function");
            result = pxa3_read_id_start(nand);
            if (result != ERROR_OK)
                return result;
            break;
        }
    }

    if (pxa3_nand->buffer_bitpos <= 0)
    {
        LOG_DEBUG("PXA3 NANDC: read nddb");
        result = target_read_u32(target, PXA3_REG_NDDB, &pxa3_nand->temp_buffer);

        if (result != ERROR_OK)
            return ERROR_NAND_OPERATION_FAILED;

#ifdef NAND_CONTROLLER_DEBUG
        if (pxa3_nand->last_command == NAND_CMD_READID)
        {
#if DEBUG_PXA_NAND_SIZE == 1
            pxa3_nand->temp_buffer = 0x5500b198;
#elif DEBUG_PXA_NAND_SIZE == 0
            pxa3_nand->temp_buffer = 0xc0007298;
#elif DEBUG_PXA_NAND_SIZE == 3
            pxa3_nand->temp_buffer = 0x5500a198;
#elif DEBUG_PXA_NAND_SIZE == 2
            pxa3_nand->temp_buffer = 0xc0007898;
#endif
        }
#endif
    }

    LOG_DEBUG("PXA3 NANDC: before: data 0x%x, bitpos: %d, datapos: 0x%x", pxa3_nand->temp_buffer, pxa3_nand->buffer_bitpos, pxa3_nand->data_position);

    if (pxa3_nand->last_command == NAND_CMD_READID)
    {
        *(uint8_t *)data = pxa3_nand->temp_buffer & 0xff;
        pxa3_nand->temp_buffer >>= 8;
        pxa3_nand->buffer_bitpos++;
        pxa3_nand->data_position++;
    }
    else
    {
        switch (nand->bus_width)
        {
        case 16:
            *(uint16_t *)data = pxa3_nand->temp_buffer & 0xffff;
            pxa3_nand->temp_buffer >>= 16;
            pxa3_nand->buffer_bitpos += 2;
            pxa3_nand->data_position += 2;
            break;

        case 8:
            *(uint8_t *)data = pxa3_nand->temp_buffer & 0xff;
            pxa3_nand->temp_buffer >>= 8;
            pxa3_nand->buffer_bitpos++;
            pxa3_nand->data_position++;
        }
    }

    if (pxa3_nand->buffer_bitpos >= 4)
    {
        pxa3_nand->buffer_bitpos = 0;
    }

    LOG_DEBUG("PXA3 NANDC: after: data 0x%x, bitpos: %d, datapos: 0x%x", pxa3_nand->temp_buffer, pxa3_nand->buffer_bitpos, pxa3_nand->data_position);

    switch (pxa3_nand->last_command)
    {
    case NAND_CMD_READID:
        if (pxa3_nand->data_position == 4)
        {
            LOG_DEBUG("PXA3 NANDC: read finished");
            pxa3_end(nand);
        }
    case NAND_CMD_STATUS:
        break;
    default:
        if (pxa3_nand->data_position == (nand->page_size + (nand->page_size > 512 ? 64 : 16)))
        {
            LOG_DEBUG("PXA3 NANDC: read finished");
            pxa3_end(nand);
        }
    }

    return ERROR_OK;
}

static int pxa3_nand_write(struct nand_device *nand, uint16_t data)
{
    struct pxa3_nand_controller *pxa3_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    LOG_DEBUG("PXA3 NANDC: before: data 0x%x, bitpos: %d, datapos: 0x%x", pxa3_nand->temp_buffer, pxa3_nand->buffer_bitpos, pxa3_nand->data_position);

    pxa3_nand->temp_buffer |= (data << (8 * pxa3_nand->buffer_bitpos));

    switch (nand->bus_width)
    {
    case 16:
        pxa3_nand->buffer_bitpos += 2;
        pxa3_nand->data_position += 2;
        break;

    case 8:
        pxa3_nand->buffer_bitpos++;
        pxa3_nand->data_position++;
    }

    if (pxa3_nand->buffer_bitpos >= 4)
    {
        pxa3_nand->buffer_bitpos = 0;
        target_write_u32(target, PXA3_REG_NDDB, pxa3_nand->temp_buffer);
        LOG_DEBUG("PXA3 NANDC: write data 0x%x", pxa3_nand->temp_buffer);
        pxa3_nand->temp_buffer = 0;
    }

    LOG_DEBUG("PXA3 NANDC: after: data 0x%x, bitpos: %d, datapos: 0x%x", pxa3_nand->temp_buffer, pxa3_nand->buffer_bitpos, pxa3_nand->data_position);

    /*
    if (pxa3_nand->data_position == (nand->page_size + (nand->page_size > 512 ? 64 : 16)))
    {
        LOG_DEBUG("PXA3 NANDC: write finished");
        pxa3_end(nand);
    }
    */

    return ERROR_OK;
}

static int pxa3_nand_read_block_data(struct nand_device *nand,
                                        uint8_t *data, int data_size)
{
    struct pxa3_nand_controller *pxa3_nand = nand->controller_priv;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    pxa3_nand->io.chunk_size = nand->page_size;

    /* try the fast way first */
    result = arm_nandread(&pxa3_nand->io, data, data_size);
    if (result != ERROR_NAND_NO_BUFFER) {
        if (result == ERROR_OK) {
            pxa3_nand->data_position += data_size;
            if (pxa3_nand->data_position == (nand->page_size + (nand->page_size > 512 ? 64 : 16)))
            {
                LOG_DEBUG("PXA3 NANDC: read finished");
                pxa3_end(nand);
            }
        }
        return result;
    }

    /* else do it slowly */
    while (data_size--)
        pxa3_nand_read(nand, data++);

    return ERROR_OK;
}

static int pxa3_nand_write_block_data(struct nand_device *nand,
                                         uint8_t *data, int data_size)
{
    struct pxa3_nand_controller *pxa3_nand = nand->controller_priv;
    int result;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    pxa3_nand->io.chunk_size = nand->page_size;

    /* try the fast way first */
    result = arm_nandwrite(&pxa3_nand->io, data, data_size);
    if (result != ERROR_NAND_NO_BUFFER)
        return result;

    /* else do it slowly */
    while (data_size--)
        pxa3_nand_write(nand, *data++);

    return ERROR_OK;
}

static int pxa3_nand_reset(struct nand_device *nand)
{
    LOG_DEBUG("PXA3 NANDC: execute reset operation");
    return pxa3_reset(nand);
}

static int pxa3_nand_ready(struct nand_device *nand, int timeout)
{
    struct pxa3_nand_controller *pxa3_nand = nand->controller_priv;
    struct target *target = nand->target;

    LOG_DEBUG("PXA3 NANDC: executed? %s", pxa3_nand->executed ? "yes" : "no");

    if (!pxa3_nand->executed)
    {
        pxa3_nand->executed = true;

        switch (pxa3_nand->last_command)
        {
        case NAND_CMD_READ0:
        case NAND_CMD_READ1:
        case NAND_CMD_READOOB:
        case NAND_CMD_READSTART:
            LOG_DEBUG("PXA3 NANDC: execute read function for page %d", pxa3_nand->temp_addr_buf);
            return pxa3_read_start(nand, pxa3_nand->temp_addr_buf) == ERROR_OK ? 1 : 0;            
        case NAND_CMD_SEQIN:
            LOG_DEBUG("PXA3 NANDC: execute write function for page %d", pxa3_nand->temp_addr_buf);
            return pxa3_write_start(nand, pxa3_nand->temp_addr_buf) == ERROR_OK ? 1 : 0;
        case NAND_CMD_ERASE2:
            LOG_DEBUG("PXA3 NANDC: execute erase function for page %d", pxa3_nand->temp_addr_buf);
            return pxa3_erase_start(nand, pxa3_nand->temp_addr_buf) == ERROR_OK ? 1 : 0;
        }
    }

    LOG_DEBUG("PXA3 NANDC: ready timeout %d", timeout);

    do
    {
        uint32_t status;

        GET_BIT32(target, PXA3_REG_NDSR, PXA3_NDSR_RDY, &status);

        if (status)
        {
            LOG_DEBUG("PXA3 NANDC: ready at %d", timeout);

            if (pxa3_nand->last_command == NAND_CMD_PAGEPROG || pxa3_nand->last_command == NAND_CMD_ERASE2){                
                pxa3_end(nand);
            }

            return 1;
        }

        alive_sleep(1);
    } while (timeout-- > 0);

    return 0;
}

NAND_DEVICE_COMMAND_HANDLER(pxa3_nand_device_command)
{
    struct pxa3_nand_controller *pxa3_nand;

    pxa3_nand = calloc(1, sizeof(struct pxa3_nand_controller));
    if (!pxa3_nand)
    {
        LOG_ERROR("no memory for nand controller");
        return ERROR_NAND_DEVICE_INVALID;
    }

    nand->controller_priv = pxa3_nand;
    nand->nand_type = 0;

    return ERROR_OK;
}

static int pxa3_nand_init(struct nand_device *nand)
{
    struct pxa3_nand_controller *pxa3_nand = nand->controller_priv;
    struct target *target = nand->target;
    int result;
    int bus_width = nand->bus_width ? nand->bus_width : 8;
    int page_size = nand->page_size ? nand->page_size : 512;

    result = validate_target_state(nand);
    if (result != ERROR_OK)
        return result;

    if (bus_width != 8 && bus_width != 16)
    {
        LOG_ERROR("pxa3xx nandc only supports 8 bit and 16-bit bus width, not %i", bus_width);
        return ERROR_NAND_OPERATION_NOT_SUPPORTED;
    }

    if (page_size != 512 && page_size != 2048)
    {
        LOG_ERROR("pxa3xx nandc only supports small and large block NAND, got %d", page_size);
        return ERROR_NAND_OPERATION_NOT_SUPPORTED;
    }

    nand->bus_width = bus_width;
    nand->page_size = page_size;
    SET_BIT32(target, PXA3_REG_NDCR, PXA3_NDCR_DMA_EN, 0);
    SET_BIT32(target, PXA3_REG_NDCR, PXA3_NDCR_ECC_EN, 0);
    SET_BIT32(target, PXA3_REG_NDCR, PXA3_NDCR_ND_RUN, 0);

    SET_BIT32(target, PXA3_REG_NDCR, PXA3_NDCR_ND_ARB_EN, pxa3_nand->arbiter ? 1 : 0);
    SET_BIT32(target, PXA3_REG_NDCR, PXA3_NDCR_SPARE_EN, 1);
    SET_BIT32(target, PXA3_REG_NDCR, PXA3_NDCR_RD_ID_CNT, 4);

    SET_BIT32(target, PXA3_REG_NDCR, PXA3_NDCR_RA_START, page_size > 512 ? 1 : 0);
    SET_BIT32(target, PXA3_REG_NDCR, PXA3_NDCR_PG_PER_BLK, page_size > 512 ? 1 : 0);
    SET_BIT32(target, PXA3_REG_NDCR, PXA3_NDCR_PAGE_SZ, page_size > 512 ? 1 : 0);

    SET_BIT32(target, PXA3_REG_NDCR, PXA3_NDCR_DWIDTH_C, bus_width == 16 ? 1 : 0);
    SET_BIT32(target, PXA3_REG_NDCR, PXA3_NDCR_DWIDTH_M, bus_width == 16 ? 1 : 0);

    pxa3_nand->io.target = target;
    pxa3_nand->io.data = PXA3_REG_NDDB;
    pxa3_nand->io.op = ARM_NAND_NONE;
    pxa3_nand->io.data_width = 32;
    pxa3_nand->io.read_width = 32;

    return ERROR_OK;
}

/* Command handlers */
#define BOOL_SETTER(name, setter, desc)                                        \
    COMMAND_HANDLER(name)                                                      \
    {                                                                          \
        struct nand_device *nand = NULL;                                       \
        struct pxa3_nand_controller *p = NULL;                                 \
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
        struct pxa3_nand_controller *p = NULL;                                 \
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

BOOL_SETTER(handle_pxa3_arbiter_command, p->arbiter, "NAND arbiter");

static const struct command_registration pxa3_sub_command_handlers[] = {
    {
        .name = "arbiter",
        .handler = handle_pxa3_arbiter_command,
        .mode = COMMAND_ANY,
        .help = "TODO",
        .usage = "[nand_id] [arbiter]",
    },
    COMMAND_REGISTRATION_DONE};

static const struct command_registration pxa3_nand_commands[] = {
    {
        .name = "pxa3",
        .mode = COMMAND_ANY,
        .help = "PXA3xx NAND flash controller commands",
        .usage = "",
        .chain = pxa3_sub_command_handlers,
    },
    COMMAND_REGISTRATION_DONE};

struct nand_flash_controller pxa3_nand_controller = {
    .name = "pxa3",
    .usage = "<target_id>",
    .command = pxa3_nand_command,
    .address = pxa3_nand_address,
    .read_data = pxa3_nand_read,
    .write_data = pxa3_nand_write,
    .read_block_data = pxa3_nand_read_block_data,
    .write_block_data = pxa3_nand_write_block_data,
    .nand_ready = pxa3_nand_ready,
    .reset = pxa3_nand_reset,
    .nand_device_command = pxa3_nand_device_command,
    .init = pxa3_nand_init,
    .commands = pxa3_nand_commands,
    .read1_supported = false,
};
