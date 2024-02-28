// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2024 Dumpit                                             *
 *                                                                         *
 ***************************************************************************/

/*
 * MSM NAND Controller
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define DEBUG_MSM_NANDC
#define DEBUG_MSM_NAND_SIZE 1

#include "imp.h"
#include "msm_nand.h"
#include "arm_io.h"
#include <target/arm.h>

/* Helpers */

static int _get_bit(struct target *target, uint32_t offset, uint32_t bit_position, uint32_t bit_mask, uint32_t *value)
{
	uint32_t temp = 0x0;
	int result;

	LOG_DEBUG("MSM NAND: ((read_u32(0x%x) >> %d) & %d)", offset, bit_position, bit_mask);

	result = target_read_u32(target, offset, &temp);
	if (result != ERROR_OK)
		return result;

	*value = (temp >> bit_position) & bit_mask;
	return ERROR_OK;
}

static int _set_bit(struct target *target, uint32_t offset, uint32_t bit_position, uint32_t bit_mask, uint32_t value)
{
	uint32_t temp = 0x0;
	int result;

	LOG_DEBUG("MSM NAND: ((read_u32(0x%x) & ~(%d << %d)) | ((%d & %d) << %d))", offset, bit_mask, bit_position, value, bit_mask, bit_position);

	result = target_read_u32(target, offset, &temp);
	if (result != ERROR_OK)
		return result;

	target_write_u32(target, offset, (temp & ~(bit_mask << bit_position)) | ((value & bit_mask) << bit_position));
	return ERROR_OK;
}

static int GET_BIT(struct target *target, uint32_t offset, struct bitmask bitmask, uint32_t *value)
{
	return _get_bit(target, offset, bitmask.bit_pos, bitmask.bit_mask, value);
}
static int SET_BIT(struct target *target, uint32_t offset, struct bitmask bitmask, uint32_t value)
{
	return _set_bit(target, offset, bitmask.bit_pos, bitmask.bit_mask, value);
}

/* Begin 01 - MSM6250 NAND Controller */

struct msm6250_nand_controller
{
	uint8_t target_cmd;
	uint32_t base_offset;
	uint32_t clr_address;
	uint32_t int_address;
	uint32_t op_reset_flag;
	bool skip_init;
	bool msm6550_discrepancy;
	uint32_t prev_cfg;
	int next_cycle;
	uint32_t temp_addr_buf;

	uint32_t temp_idcode;
	uint8_t temp_data[0x210];
	uint32_t data_position;

	uint8_t first_read;
	uint8_t init_done;
};

#define CHECK_TIMEOUT_6250                                                     \
	do                                                                         \
	{                                                                          \
		if (!msm6250_wait_timeout(nand, MSM_NAND_TIMEOUT))                     \
		{                                                                      \
			LOG_ERROR("timeout while waiting for nand operation to complete"); \
			return ERROR_NAND_OPERATION_FAILED;                                \
		}                                                                      \
	} while (0)

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

static int msm6250_wait_timeout(struct nand_device *nand, int timeout)
{
	struct target *target = nand->target;
	struct msm6250_nand_controller *msm6250_nand = nand->controller_priv;

	LOG_DEBUG("msm6250_wait_timeout count start=%d", timeout);

	do
	{
		uint32_t status = 0x0;
		int retval;

		retval = GET_BIT(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_STATUS, MSM6250_STATUS_OP_STATUS, &status);
		if (retval != ERROR_OK)
		{
			LOG_ERROR("Could not read REG_FLASH_STATUS");
			return 0;
		}

#ifdef DEBUG_MSM_NANDC
		status = 0;
#endif

		if (!status)
		{
			LOG_DEBUG("msm6250_wait_timeout count=%d", timeout);
			return 1;
		}

		alive_sleep(1);
	} while (timeout-- > 0);

	return 0;
}

static int msm6250_nand_command(struct nand_device *nand, uint8_t command)
{
	struct target *target = nand->target;
	struct msm6250_nand_controller *msm6250_nand = nand->controller_priv;

	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	LOG_DEBUG("MSM6250 NANDC: cmd 0x%x", command);
	msm6250_nand->target_cmd = command;

	switch (command)
	{
	case NAND_CMD_RESET:
	{
		LOG_DEBUG("MSM6250 NANDC: execute reset operation");
		target_write_u32(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_CMD, MSM6250_CMD_FLASH_RESET_NAND);
		CHECK_TIMEOUT_6250;
	}
	// fall through
	case NAND_CMD_READ0:
	case NAND_CMD_READ1:
	case NAND_CMD_READOOB:
	case NAND_CMD_READID:
	case NAND_CMD_SEQIN:
	case NAND_CMD_ERASE1:
		LOG_DEBUG("MSM6250 NANDC: reset io operation");
		msm6250_nand->next_cycle = 0;
		msm6250_nand->temp_addr_buf = 0;
	case NAND_CMD_STATUS:
		break;
	default:
		LOG_ERROR("NAND CMD operation 0x%x is not supported.", command);
	}

	return ERROR_OK;
}

static int msm6250_read_request(struct nand_device *nand, uint32_t page, uint8_t ecc)
{
	struct target *target = nand->target;
	struct msm6250_nand_controller *msm6250_nand = nand->controller_priv;

	uint32_t temp = 0x0;
	int result;

	int timeout = MSM_NAND_TIMEOUT;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	LOG_DEBUG("MSM6250 NANDC: request page read, no: %d", page);

	if (!msm6250_nand->first_read)
	{
		msm6250_nand->first_read = 1;

		if (!msm6250_nand->skip_init)
		{
			target_write_u32(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_CMD, MSM6250_CMD_FLASH_RESET);
			CHECK_TIMEOUT_6250;
		}

		target_write_u32(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_CMD, MSM6250_CMD_FLASH_RESET_NAND);
		CHECK_TIMEOUT_6250;

		if (!msm6250_nand->skip_init)
		{
			target_write_u32(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_CFG1, 0x25a | ((nand->bus_width == 16 ? 1 : 0) << 5) | (uint32_t)!ecc);
		}
		else
		{
			result = SET_BIT(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_CFG1, MSM6250_CONFIG_ECC_DISABLED, !ecc);
			if (result != ERROR_OK)
				return ERROR_NAND_OPERATION_FAILED;

			result = SET_BIT(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_CFG1, MSM6250_CONFIG_WIDE_NAND, nand->bus_width == 16 ? 1 : 0);
			if (result != ERROR_OK)
				return ERROR_NAND_OPERATION_FAILED;
		}
	}

	result = SET_BIT(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_ADDR, MSM6250_6800_ADDR_FLASH_PAGE_ADDRESS, page);
	if (result != ERROR_OK)
		return ERROR_NAND_OPERATION_FAILED;

	if (msm6250_nand->op_reset_flag != 0)
	{
		target_write_u32(target, msm6250_nand->clr_address, msm6250_nand->op_reset_flag);

		do
		{
			result = target_read_u32(target, msm6250_nand->int_address, &temp);
			if (result != ERROR_OK)
				return ERROR_NAND_OPERATION_FAILED;

#ifdef DEBUG_MSM_NANDC
			break;
#endif

			if ((temp & msm6250_nand->op_reset_flag) == 0)
			{
				break;
			}

			alive_sleep(1);
		} while (timeout-- > 0);

		if (!timeout)
		{
			LOG_ERROR("timeout waiting for NAND interrupt flag to be cleared");
			return ERROR_NAND_OPERATION_FAILED;
		}
	}

	target_write_u32(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_CMD, MSM6250_CMD_FLASH_PAGE_READ);
	CHECK_TIMEOUT_6250;

	return ERROR_OK;
}

static int msm6250_nand_address(struct nand_device *nand, uint8_t address)
{
	struct target *target = nand->target;
	struct msm6250_nand_controller *msm6250_nand = nand->controller_priv;
	uint32_t temp = 0x0;

	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	msm6250_nand->next_cycle++;
	LOG_DEBUG("MSM6250 NANDC: address cycle %d: 0x%x", msm6250_nand->next_cycle, address);

	if (msm6250_nand->next_cycle > 1)
	{
		msm6250_nand->temp_addr_buf |= (address << (8 * (msm6250_nand->next_cycle - 2)));
		LOG_DEBUG("MSM6250 NANDC: address shift, page number data: 0x%x, shift: %d", msm6250_nand->temp_addr_buf, (8 * (msm6250_nand->next_cycle - 2)));
	}

	switch (msm6250_nand->target_cmd)
	{
	case NAND_CMD_READID:
		if (msm6250_nand->next_cycle == 1)
		{
			LOG_DEBUG("MSM6250 NANDC: execute read id operation");

			target_write_u32(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_CMD, MSM6250_CMD_FLASH_ID_FETCH);
			CHECK_TIMEOUT_6250;

			target_write_u32(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_CMD, MSM6250_CMD_FLASH_STATUS_CHECK);
			CHECK_TIMEOUT_6250;

			result = GET_BIT(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_STATUS, MSM6250_STATUS_NAND_MFRID, &temp);
			if (result != ERROR_OK)
				return ERROR_NAND_OPERATION_FAILED;

#ifdef DEBUG_MSM_NANDC
			temp = 0x98;
#endif

			msm6250_nand->temp_idcode = temp;
			result = GET_BIT(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_STATUS, MSM6250_STATUS_NAND_DEVID, &temp);
			if (result != ERROR_OK)
				return ERROR_NAND_OPERATION_FAILED;

#ifdef DEBUG_MSM_NANDC
			temp = 0x76;
#endif

			msm6250_nand->temp_idcode |= temp << 8;
		}
		break;

	case NAND_CMD_READ0:
	case NAND_CMD_READ1:
	case NAND_CMD_READOOB:
		if (msm6250_nand->next_cycle == nand->address_cycles)
		{
			msm6250_nand->data_position = msm6250_nand->target_cmd == NAND_CMD_READOOB ? 0x200 : (msm6250_nand->target_cmd == NAND_CMD_READ1 ? 0x100 : 0x0);
			LOG_DEBUG("MSM6250 NANDC: execute read operation, data position set to 0x%x, page number: %d", msm6250_nand->data_position, msm6250_nand->temp_addr_buf);

			result = msm6250_read_request(nand, msm6250_nand->temp_addr_buf, 0);
			if (result != ERROR_OK)
				return result;

			result = target_read_memory(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_BUFFER, 1, 0x210, msm6250_nand->temp_data);
			if (result != ERROR_OK)
				return ERROR_NAND_OPERATION_FAILED;

#ifdef DEBUG_MSM_NANDC
			memset(msm6250_nand->temp_data, 0x11, 0x200);
			memset(msm6250_nand->temp_data + 0x200, 0x22, 0x10);
#endif
		}
		break;

	case NAND_CMD_PAGEPROG:
	case NAND_CMD_ERASE2:
		return ERROR_NAND_OPERATION_NOT_SUPPORTED;
		/*
		default:
			LOG_ERROR("should not reach here");
			return ERROR_NAND_OPERATION_FAILED;
		*/
	}

	return ERROR_OK;
}

static int msm6250_nand_read(struct nand_device *nand, void *data)
{
	struct target *target = nand->target;
	struct msm6250_nand_controller *msm6250_nand = nand->controller_priv;
	int result;

	uint32_t temp;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	switch (msm6250_nand->target_cmd)
	{
	case NAND_CMD_READID:
		*(uint8_t *)data = (uint8_t)(msm6250_nand->temp_idcode & 0xff);
		msm6250_nand->temp_idcode >>= 8;
		break;

	case NAND_CMD_STATUS:
		LOG_DEBUG("MSM6250 NANDC: get status");

		target_write_u32(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_CMD, MSM6250_CMD_FLASH_STATUS_CHECK);
		CHECK_TIMEOUT_6250;

		result = target_read_u32(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_STATUS, &temp);
		if (result != ERROR_OK)
			return ERROR_NAND_OPERATION_FAILED;

		*(uint8_t *)data = ((temp & 0x8) ? 1 : 0) | ((((temp & 7) == 0) ? 1 : 0) << 6) | (((temp & 0x4000) ? 1 : 0) << 7);

#ifdef DEBUG_MSM_NANDC
		*(uint8_t *)data = NAND_STATUS_READY | NAND_STATUS_WP;
#endif
		break;

	default:
		LOG_DEBUG("MSM6250 NANDC: read %d bytes from buffer 0x%x", nand->bus_width / 8, msm6250_nand->data_position);
		if (nand->bus_width == 16)
		{
			*(uint16_t *)data = target_buffer_get_u16(target, &msm6250_nand->temp_data[msm6250_nand->data_position]);
		}
		else
		{
			*(uint8_t *)data = msm6250_nand->temp_data[msm6250_nand->data_position];
		}

		msm6250_nand->data_position += nand->bus_width / 8;
		msm6250_nand->data_position %= nand->page_size + (nand->page_size <= 512 ? 16 : 64);
	}

	return ERROR_OK;
}

static int msm6250_nand_read_data(struct nand_device *nand, uint8_t *data, int size)
{
	struct msm6250_nand_controller *msm6250_nand = nand->controller_priv;
	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	LOG_DEBUG("MSM6250 NANDC: read %d bytes from buffer 0x%x", size, msm6250_nand->data_position);

	memcpy(data, msm6250_nand->temp_data + msm6250_nand->data_position, size);

	msm6250_nand->data_position += size;
	msm6250_nand->data_position %= nand->page_size + (nand->page_size <= 512 ? 16 : 64);

	return ERROR_OK;
}

static int msm6250_nand_fastread(struct nand_device *nand, uint32_t page, uint8_t *data, uint32_t data_size, uint8_t *oob, uint32_t oob_size)
{
	struct target *target = nand->target;
	struct msm6250_nand_controller *msm6250_nand = nand->controller_priv;

	int result;
	uint8_t temp_spare[16];

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	LOG_DEBUG("MSM6250 NANDC: execute read operation, read 0x%x data bytes, 0x%x spare bytes, page number: %d", data_size, oob_size, page);

	result = msm6250_read_request(nand, page, 1);
	if (result != ERROR_OK)
		return result;

	if (msm6250_nand->msm6550_discrepancy)
	{
		memset(temp_spare, 0xff, 16);

		result = target_read_memory(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_BUFFER + (nand->bus_width == 16 ? 2 : 1), 1, data_size, data);
		if (result != ERROR_OK)
			return ERROR_NAND_OPERATION_FAILED;

		result = target_read_memory(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_BUFFER + 0x200 + (nand->bus_width == 16 ? 2 : 1), 1, (nand->bus_width == 16 ? 0xe : 0xf), temp_spare);
		if (result != ERROR_OK)
			return ERROR_NAND_OPERATION_FAILED;

		memcpy(oob, temp_spare, oob_size);
	}
	else
	{
		result = target_read_memory(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_BUFFER, 1, data_size, data);
		if (result != ERROR_OK)
			return ERROR_NAND_OPERATION_FAILED;

		result = target_read_memory(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_BUFFER + 0x200, 1, oob_size, oob);
		if (result != ERROR_OK)
			return ERROR_NAND_OPERATION_FAILED;
	}

#ifdef DEBUG_MSM_NANDC
	memset(data, 0x11, data_size);
	memset(oob, 0x22, oob_size);
#endif

	return ERROR_OK;
}

static int msm6250_nand_fastwrite(struct nand_device *nand, uint32_t page, uint8_t *data, uint32_t data_size, uint8_t *oob, uint32_t oob_size)
{
	return ERROR_NAND_OPERATION_NOT_SUPPORTED; // TODO
}

static int msm6250_nand_write_data(struct nand_device *nand, uint8_t *data, int size)
{
	struct msm6250_nand_controller *msm6250_nand = nand->controller_priv;
	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	LOG_DEBUG("MSM6250 NANDC: write %d bytes to buffer 0x%x", size, msm6250_nand->data_position);

	memcpy(msm6250_nand->temp_data + msm6250_nand->data_position, data, size);

	msm6250_nand->data_position += size;
	msm6250_nand->data_position %= nand->page_size + (nand->page_size <= 512 ? 16 : 64);

	return ERROR_OK;
}

static int msm6250_nand_write(struct nand_device *nand, uint16_t data)
{
	struct target *target = nand->target;
	struct msm6250_nand_controller *msm6250_nand = nand->controller_priv;
	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	LOG_DEBUG("MSM6250 NANDC: write %d bytes to buffer 0x%x", nand->bus_width / 8, msm6250_nand->data_position);

	if (nand->bus_width == 16)
	{
		target_buffer_set_u16(target, &msm6250_nand->temp_data[msm6250_nand->data_position], data);
	}
	else
	{
		msm6250_nand->temp_data[msm6250_nand->data_position] = (uint8_t)data;
	}

	msm6250_nand->data_position += nand->bus_width / 8;
	msm6250_nand->data_position %= nand->page_size + (nand->page_size <= 512 ? 16 : 64);

	return ERROR_OK;
}

static int msm6250_nand_reset(struct nand_device *nand)
{
	return ERROR_OK; // Dummy Reset Command
}

static int msm6250_nand_ready(struct nand_device *nand, int timeout)
{
	return msm6250_wait_timeout(nand, timeout);
}

NAND_DEVICE_COMMAND_HANDLER(msm6250_nand_device_command)
{
	struct msm6250_nand_controller *msm6250_nand;

	msm6250_nand = calloc(1, sizeof(struct msm6250_nand_controller));
	if (!msm6250_nand)
	{
		LOG_ERROR("no memory for nand controller");
		return ERROR_NAND_DEVICE_INVALID;
	}

	nand->controller_priv = msm6250_nand;

	msm6250_nand->base_offset = 0x64000000;
	msm6250_nand->clr_address = 0x8400024c;
	msm6250_nand->int_address = 0x84000244;
	msm6250_nand->op_reset_flag = 6;
	msm6250_nand->skip_init = false;
	msm6250_nand->msm6550_discrepancy = false;
	msm6250_nand->first_read = 0;
	msm6250_nand->prev_cfg = 0;
	msm6250_nand->init_done = 0;

	return ERROR_OK;
}

static int msm6250_nand_init(struct nand_device *nand)
{
	struct msm6250_nand_controller *msm6250_nand = nand->controller_priv;
	struct target *target = nand->target;
	int bus_width = nand->bus_width ? nand->bus_width : 8;
	int page_size = nand->page_size ? nand->page_size : 512;
	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	if (bus_width != 8 && bus_width != 16)
	{
		LOG_ERROR("msm6250 nandc only supports 8 bit and 16-bit bus width, not %i", bus_width);
		return ERROR_NAND_OPERATION_NOT_SUPPORTED;
	}

	if (page_size != 512)
	{
		LOG_ERROR("msm6250 nandc only supports small block NAND");
		return ERROR_NAND_OPERATION_NOT_SUPPORTED;
	}

	/* inform calling code about selected bus width */
	nand->bus_width = bus_width;
	nand->page_size = page_size;

	/* configure nand controller */
	if (!msm6250_nand->init_done)
	{
		msm6250_nand->init_done = 1;

		if (!msm6250_nand->skip_init)
		{
			target_write_u32(target, 0x84000174, 0);
			target_write_u32(target, 0x84000178, 0x7e);
			target_write_u32(target, 0x8400017c, 0x1fff);
			target_write_u32(target, 0x84000180, 0);
		}

		result = target_read_u32(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_CFG1, &msm6250_nand->prev_cfg);
		if (result != ERROR_OK)
		{
			return ERROR_NAND_OPERATION_FAILED;
		}

		if (!msm6250_nand->skip_init)
		{
			target_write_u32(target, msm6250_nand->base_offset + MSM6250_REG_FLASH_CFG1, 0x253);
		}
	}

	return ERROR_OK;
}

/* Command handlers */

#define BOOL_SETTER_6250(name, setter, desc)                                   \
	COMMAND_HANDLER(name)                                                      \
	{                                                                          \
		struct nand_device *nand = NULL;                                       \
		struct msm6250_nand_controller *p = NULL;                              \
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

#define INT_SETTER_6250(name, setter, format, desc)                            \
	COMMAND_HANDLER(name)                                                      \
	{                                                                          \
		struct nand_device *nand = NULL;                                       \
		struct msm6250_nand_controller *p = NULL;                              \
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

INT_SETTER_6250(handle_msm6250_base_addr_command, p->base_offset, "0x%x", "base_addr")
INT_SETTER_6250(handle_msm6250_int_clr_addr_command, p->clr_address, "0x%x", "int_clr_addr")
INT_SETTER_6250(handle_msm6250_int_addr_command, p->int_address, "0x%x", "int_addr")
INT_SETTER_6250(handle_msm6250_op_command, p->op_reset_flag, "%u", "op")
BOOL_SETTER_6250(handle_msm6250_skip_init_command, p->skip_init, "skip_init")
BOOL_SETTER_6250(handle_msm6250_msm6550_discrepancy_command, p->msm6550_discrepancy, "msm6550_discrepancy")

static const struct command_registration msm6250_sub_command_handlers[] = {
	{
		.name = "base_addr",
		.handler = handle_msm6250_base_addr_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [base_addr]",
	},
	{
		.name = "int_clr_addr",
		.handler = handle_msm6250_int_clr_addr_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [int_clr_addr]",
	},
	{
		.name = "int_addr",
		.handler = handle_msm6250_int_addr_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [int_addr]",
	},
	{
		.name = "op",
		.handler = handle_msm6250_op_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [op]",
	},
	{
		.name = "skip_init",
		.handler = handle_msm6250_skip_init_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [skip_init]",
	},
	{
		.name = "msm6550_discrepancy",
		.handler = handle_msm6250_msm6550_discrepancy_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [msm6550_discrepancy]",
	},
	COMMAND_REGISTRATION_DONE};

static const struct command_registration msm6250_nand_commands[] = {
	{
		.name = "msm6250",
		.mode = COMMAND_ANY,
		.help = "MSM6250 NAND flash controller commands",
		.usage = "",
		.chain = msm6250_sub_command_handlers,
	},
	COMMAND_REGISTRATION_DONE};

struct nand_flash_controller msm6250_nand_controller = {
	.name = "msm6250",
	.command = msm6250_nand_command,
	.address = msm6250_nand_address,
	.read_data = msm6250_nand_read,
	.write_data = msm6250_nand_write,
	.write_page = msm6250_nand_fastwrite,
	.read_page = msm6250_nand_fastread,
	.read_block_data = msm6250_nand_read_data,
	.write_block_data = msm6250_nand_write_data,
	.nand_ready = msm6250_nand_ready,
	.reset = msm6250_nand_reset,
	.nand_device_command = msm6250_nand_device_command,
	.commands = msm6250_nand_commands,
	.init = msm6250_nand_init,
};

/* Begin 02 - MSM6800 NAND Controller */
struct msm6800_nand_controller
{
	uint8_t target_cmd;
	uint32_t base_offset;
	uint32_t clr_address;
	uint32_t int_address;
	uint32_t op_reset_flag;
	bool skip_init;
	bool skip_gpio_init;
	uint32_t prev_cfg1;
	uint32_t prev_cfg2;
	uint32_t prev_cfg1_f2;
	uint32_t prev_cfg2_f2;
	uint32_t prev_cfg_common;
	uint32_t cfg1;
	uint32_t cfg2;
	uint32_t cfg_common;
	int next_cycle;
	uint32_t temp_addr_buf;

	uint32_t temp_idcode;
	uint8_t temp_data[0x840];
	uint32_t data_position;

	uint8_t first_read;
	uint8_t init_done;

	uint32_t device_id;
};

#define CHECK_TIMEOUT_6800                                                     \
	do                                                                         \
	{                                                                          \
		if (!msm6800_wait_timeout(nand, MSM_NAND_TIMEOUT))                     \
		{                                                                      \
			LOG_ERROR("timeout while waiting for nand operation to complete"); \
			return ERROR_NAND_OPERATION_FAILED;                                \
		}                                                                      \
	} while (0)

static int msm6800_wait_timeout(struct nand_device *nand, int timeout)
{
	struct target *target = nand->target;
	struct msm6800_nand_controller *msm6800_nand = nand->controller_priv;

	LOG_DEBUG("msm6800_wait_timeout count start=%d", timeout);

	do
	{
		uint32_t status = 0x0;
		int retval;

		retval = GET_BIT(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_STATUS, MSM6800_STATUS_OP_STATUS, &status);
		if (retval != ERROR_OK)
		{
			LOG_ERROR("Could not read REG_FLASH_STATUS");
			return 0;
		}

#ifdef DEBUG_MSM_NANDC
		status = 0;
#endif

		if (!status)
		{
			LOG_DEBUG("msm6800_wait_timeout count=%d", timeout);
			return 1;
		}

		alive_sleep(1);
	} while (timeout-- > 0);

	return 0;
}

static int msm6800_read_request(struct nand_device *nand, uint32_t page, uint8_t ecc, uint32_t subsequent);
static int msm6800_nand_command(struct nand_device *nand, uint8_t command)
{
	struct target *target = nand->target;
	struct msm6800_nand_controller *msm6800_nand = nand->controller_priv;

	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	LOG_DEBUG("MSM6800 NANDC: cmd 0x%x", command);

	msm6800_nand->target_cmd = command;

	switch (command)
	{
	case NAND_CMD_RESET:
	{
		LOG_DEBUG("MSM6800 NANDC: execute reset operation");
		target_write_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CMD, MSM6250_CMD_FLASH_RESET_NAND);
		CHECK_TIMEOUT_6800;
	}
	// fall through
	case NAND_CMD_READ0:
	case NAND_CMD_READ1:
	case NAND_CMD_READOOB:
	case NAND_CMD_READID:
	case NAND_CMD_SEQIN:
	case NAND_CMD_ERASE1:
		LOG_DEBUG("MSM6800 NANDC: reset io operation");
		msm6800_nand->next_cycle = 0;
		msm6800_nand->temp_addr_buf = 0;
	case NAND_CMD_STATUS:
		break;
	case NAND_CMD_READSTART:
	{
		if (nand->page_size > 512)
		{
			LOG_DEBUG("MSM6800 NANDC: execute large block read operation, page number: %d", msm6800_nand->temp_addr_buf);
			msm6800_nand->data_position = 0;

			for (int cycle = 0; cycle < 4; cycle++)
			{
				LOG_DEBUG("MSM6800 NANDC: data: 0x%x, spare: 0x%x", (0x200 * cycle), 0x800 + (0x10 * cycle));

				result = msm6800_read_request(nand, msm6800_nand->temp_addr_buf, 0, cycle > 0 ? 1 : 0);
				if (result != ERROR_OK)
					return result;

				result = target_read_memory(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_BUFFER, 1, 0x200, msm6800_nand->temp_data + (0x200 * cycle));
				if (result != ERROR_OK)
					return ERROR_NAND_OPERATION_FAILED;

				result = target_read_memory(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_BUFFER + 0x200, 1, 0x10, msm6800_nand->temp_data + 0x800 + (0x10 * cycle));
				if (result != ERROR_OK)
					return ERROR_NAND_OPERATION_FAILED;

#ifdef DEBUG_MSM_NANDC
				memset(msm6800_nand->temp_data + (0x200 * cycle), 0x11 + (0x11 * cycle), 0x200);
				memset(msm6800_nand->temp_data + 0x800 + (0x10 * cycle), 0x22 + (0x11 * cycle), 0x10);
#endif
			}
			break;
		}
	}
	// fall through
	default:
		LOG_ERROR("NAND CMD operation 0x%x is not supported.", command);
	}

	return ERROR_OK;
}

static int msm6800_read_request(struct nand_device *nand, uint32_t page, uint8_t ecc, uint32_t subsequent)
{
	struct target *target = nand->target;
	struct msm6800_nand_controller *msm6800_nand = nand->controller_priv;

	uint32_t temp = 0x0;
	int result;

	int timeout = MSM_NAND_TIMEOUT;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	LOG_DEBUG("MSM6800 NANDC: request page read, no: %d, subsequent: %d", page, subsequent);

	if (!subsequent)
	{
		if (!msm6800_nand->first_read)
		{
			msm6800_nand->first_read = 1;

			if (!msm6800_nand->skip_init)
			{
				target_write_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CMD, MSM6250_CMD_FLASH_RESET);
				CHECK_TIMEOUT_6800;
			}

			target_write_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CMD, MSM6250_CMD_FLASH_RESET_NAND);
			CHECK_TIMEOUT_6800;

			if (!msm6800_nand->skip_init)
			{
				target_write_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_COMMON_CFG, msm6800_nand->cfg_common);
				target_write_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CFG1_FLASH1, msm6800_nand->cfg1);
				target_write_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CFG2_FLASH1, msm6800_nand->cfg2);
				target_write_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CFG1_FLASH2, msm6800_nand->cfg1);
				target_write_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CFG2_FLASH2, msm6800_nand->cfg2);
			}

			result = SET_BIT(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CFG1_FLASH1, MSM6800_CONFIG1_ECC_DISABLED, !ecc);
			if (result != ERROR_OK)
				return ERROR_NAND_OPERATION_FAILED;

			result = SET_BIT(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CFG1_FLASH2, MSM6800_CONFIG1_ECC_DISABLED, !ecc);
			if (result != ERROR_OK)
				return ERROR_NAND_OPERATION_FAILED;
		}

		result = SET_BIT(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_ADDR, MSM6250_6800_ADDR_FLASH_PAGE_ADDRESS, page);
		if (result != ERROR_OK)
			return ERROR_NAND_OPERATION_FAILED;

		if (msm6800_nand->op_reset_flag != 0)
		{
			target_write_u32(target, msm6800_nand->clr_address, msm6800_nand->op_reset_flag);

			do
			{
				result = target_read_u32(target, msm6800_nand->int_address, &temp);
				if (result != ERROR_OK)
					return ERROR_NAND_OPERATION_FAILED;

#ifdef DEBUG_MSM_NANDC
				break;
#endif

				if ((temp & msm6800_nand->op_reset_flag) == 0)
				{
					break;
				}

				alive_sleep(1);
			} while (timeout-- > 0);

			if (!timeout)
			{
				LOG_ERROR("timeout waiting for NAND interrupt flag to be cleared");
				return ERROR_NAND_OPERATION_FAILED;
			}
		}
	}

	target_write_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CMD, MSM6250_CMD_FLASH_PAGE_READ);
	CHECK_TIMEOUT_6800;

	return ERROR_OK;
}

static int msm6800_nand_address(struct nand_device *nand, uint8_t address)
{
	struct target *target = nand->target;
	struct msm6800_nand_controller *msm6800_nand = nand->controller_priv;
	uint32_t temp = 0x0;

	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	msm6800_nand->next_cycle++;
	LOG_DEBUG("MSM6800 NANDC: address cycle %d: 0x%x", msm6800_nand->next_cycle, address);

	if (msm6800_nand->next_cycle > (nand->page_size <= 512 ? 1 : 2))
	{
		msm6800_nand->temp_addr_buf |= (address << (8 * (msm6800_nand->next_cycle - (nand->page_size <= 512 ? 2 : 3))));
		LOG_DEBUG("MSM6800 NANDC: address shift, page number data: 0x%x, shift: %d", msm6800_nand->temp_addr_buf, (8 * (msm6800_nand->next_cycle - (nand->page_size <= 512 ? 2 : 3))));
	}

	switch (msm6800_nand->target_cmd)
	{
	case NAND_CMD_READID:
		if (msm6800_nand->next_cycle == 1)
		{
			LOG_DEBUG("MSM6800 NANDC: execute read id operation");
			target_write_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CMD, MSM6250_CMD_FLASH_ID_FETCH);
			CHECK_TIMEOUT_6800;

			target_write_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CMD, MSM6250_CMD_FLASH_STATUS_CHECK);
			CHECK_TIMEOUT_6800;

			result = GET_BIT(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_ID_DATA, MSM6800_FLASH_NAND_MFRID, &temp);
			if (result != ERROR_OK)
				return ERROR_NAND_OPERATION_FAILED;

#ifdef DEBUG_MSM_NANDC
			temp = 0x98;
#endif

			msm6800_nand->temp_idcode = temp;
			result = GET_BIT(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_ID_DATA, MSM6800_FLASH_NAND_DEVID, &temp);
			if (result != ERROR_OK)
				return ERROR_NAND_OPERATION_FAILED;

#ifdef DEBUG_MSM_NANDC
#if DEBUG_MSM_NAND_SIZE == 1
			temp = 0xb1;
#else
			temp = 0x72;
#endif
#endif

			msm6800_nand->temp_idcode |= temp << 8;
			result = GET_BIT(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_ID_DATA, MSM6800_FLASH_NAND_EXTID, &temp);
			if (result != ERROR_OK)
				return ERROR_NAND_OPERATION_FAILED;

#ifdef DEBUG_MSM_NANDC
			temp = 0x00;
#endif

			msm6800_nand->temp_idcode |= temp << 24;
		}
		break;

	case NAND_CMD_READ0:
	case NAND_CMD_READ1:
	case NAND_CMD_READOOB:
		if (msm6800_nand->next_cycle == nand->address_cycles && nand->page_size <= 512)
		{
			msm6800_nand->data_position = msm6800_nand->target_cmd == NAND_CMD_READOOB ? 0x200 : (msm6800_nand->target_cmd == NAND_CMD_READ1 ? 0x100 : 0x0);
			LOG_DEBUG("MSM6800 NANDC: execute read operation, data position set to 0x%x, page number: %d", msm6800_nand->data_position, msm6800_nand->temp_addr_buf);

			result = msm6800_read_request(nand, msm6800_nand->temp_addr_buf, 0, 0);
			if (result != ERROR_OK)
				return result;

			result = target_read_memory(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_BUFFER, 1, 0x210, msm6800_nand->temp_data);
			if (result != ERROR_OK)
				return ERROR_NAND_OPERATION_FAILED;

#ifdef DEBUG_MSM_NANDC
			memset(msm6800_nand->temp_data, 0x11, 0x200);
			memset(msm6800_nand->temp_data + 0x200, 0x22, 0x10);
#endif
		}
		break;

	case NAND_CMD_PAGEPROG:
	case NAND_CMD_ERASE2:
		return ERROR_NAND_OPERATION_NOT_SUPPORTED;
		/*
		default:
			LOG_ERROR("should not reach here");
			return ERROR_NAND_OPERATION_FAILED;
		*/
	}

	return ERROR_OK;
}

static int msm6800_nand_read(struct nand_device *nand, void *data)
{
	struct target *target = nand->target;
	struct msm6800_nand_controller *msm6800_nand = nand->controller_priv;
	int result;

	uint32_t temp;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	switch (msm6800_nand->target_cmd)
	{
	case NAND_CMD_READID:
		*(uint8_t *)data = (uint8_t)(msm6800_nand->temp_idcode & 0xff);
		msm6800_nand->temp_idcode >>= 8;
		break;

	case NAND_CMD_STATUS:
		LOG_DEBUG("MSM6800 NANDC: get status");

		target_write_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CMD, MSM6250_CMD_FLASH_STATUS_CHECK);
		CHECK_TIMEOUT_6800;

		result = target_read_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_STATUS, &temp);
		if (result != ERROR_OK)
			return ERROR_NAND_OPERATION_FAILED;

		*(uint8_t *)data = ((temp & 0x8) ? 1 : 0) | ((((temp & 7) == 0) ? 1 : 0) << 6) | ((((temp & 7) == 0) ? 1 : 0) << 5) | (((temp & 0x4000) ? 1 : 0) << 7);

#ifdef DEBUG_MSM_NANDC
		*(uint8_t *)data = NAND_STATUS_READY | NAND_STATUS_WP | NAND_STATUS_TRUE_READY;
#endif
		break;

	default:
		LOG_DEBUG("MSM6800 NANDC: read %d bytes from buffer 0x%x", nand->bus_width / 8, msm6800_nand->data_position);
		if (nand->bus_width == 16)
		{
			*(uint16_t *)data = target_buffer_get_u16(target, &msm6800_nand->temp_data[msm6800_nand->data_position]);
		}
		else
		{
			*(uint8_t *)data = msm6800_nand->temp_data[msm6800_nand->data_position];
		}

		msm6800_nand->data_position += nand->bus_width / 8;
		msm6800_nand->data_position %= nand->page_size + (nand->page_size <= 512 ? 16 : 64);
	}

	return ERROR_OK;
}

static int msm6800_nand_read_data(struct nand_device *nand, uint8_t *data, int size)
{
	struct msm6800_nand_controller *msm6800_nand = nand->controller_priv;
	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	LOG_DEBUG("MSM6800 NANDC: read %d bytes from buffer 0x%x", size, msm6800_nand->data_position);

	memcpy(data, msm6800_nand->temp_data + msm6800_nand->data_position, size);

	msm6800_nand->data_position += size;
	msm6800_nand->data_position %= nand->page_size + (nand->page_size <= 512 ? 16 : 64);

	return ERROR_OK;
}

static int msm6800_nand_fastread(struct nand_device *nand, uint32_t page, uint8_t *data, uint32_t data_size, uint8_t *oob, uint32_t oob_size)
{
	struct target *target = nand->target;
	struct msm6800_nand_controller *msm6800_nand = nand->controller_priv;

	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	LOG_DEBUG("MSM6800 NANDC: execute read operation, read 0x%x data bytes, 0x%x spare bytes, page number: %d", data_size, oob_size, page);

	if (nand->page_size <= 512)
	{
		result = msm6800_read_request(nand, page, 1, 0);
		if (result != ERROR_OK)
			return result;

		result = target_read_memory(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_BUFFER, 1, data_size, data);
		if (result != ERROR_OK)
			return ERROR_NAND_OPERATION_FAILED;

		result = target_read_memory(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_BUFFER + 0x200, 1, oob_size, oob);
		if (result != ERROR_OK)
			return ERROR_NAND_OPERATION_FAILED;

#ifdef DEBUG_MSM_NANDC
		memset(data, 0x11, data_size);
		memset(oob, 0x22, oob_size);
#endif
	}
	else
	{
		for (int cycle = 0; cycle < 4; cycle++)
		{
			LOG_DEBUG("MSM6800 NANDC: data: 0x%x, spare: 0x%x", (0x200 * cycle), (0x10 * cycle));

			result = msm6800_read_request(nand, page, 1, cycle > 0 ? 1 : 0);
			if (result != ERROR_OK)
				return result;

			result = target_read_memory(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_BUFFER, 1, 0x200, data + (0x200 * cycle));
			if (result != ERROR_OK)
				return ERROR_NAND_OPERATION_FAILED;

			result = target_read_memory(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_BUFFER + 0x200, 1, 0x10, oob + (0x10 * cycle));
			if (result != ERROR_OK)
				return ERROR_NAND_OPERATION_FAILED;

#ifdef DEBUG_MSM_NANDC
			memset(data + (0x200 * cycle), 0x11 + (0x11 * cycle), 0x200);
			memset(oob + (0x10 * cycle), 0x22 + (0x11 * cycle), 0x10);
#endif
		}
	}

	return ERROR_OK;
}

static int msm6800_nand_fastwrite(struct nand_device *nand, uint32_t page, uint8_t *data, uint32_t data_size, uint8_t *oob, uint32_t oob_size)
{
	return ERROR_NAND_OPERATION_NOT_SUPPORTED; // TODO
}

static int msm6800_nand_write_data(struct nand_device *nand, uint8_t *data, int size)
{
	struct msm6800_nand_controller *msm6800_nand = nand->controller_priv;
	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	LOG_DEBUG("MSM6800 NANDC: write %d bytes to buffer 0x%x", size, msm6800_nand->data_position);

	memcpy(msm6800_nand->temp_data + msm6800_nand->data_position, data, size);

	msm6800_nand->data_position += size;
	msm6800_nand->data_position %= nand->page_size + (nand->page_size <= 512 ? 16 : 64);

	return ERROR_OK;
}

static int msm6800_nand_write(struct nand_device *nand, uint16_t data)
{
	struct target *target = nand->target;
	struct msm6800_nand_controller *msm6800_nand = nand->controller_priv;
	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	LOG_DEBUG("MSM6800 NANDC: write %d bytes to buffer 0x%x", nand->bus_width / 8, msm6800_nand->data_position);

	if (nand->bus_width == 16)
	{
		target_buffer_set_u16(target, &msm6800_nand->temp_data[msm6800_nand->data_position], data);
	}
	else
	{
		msm6800_nand->temp_data[msm6800_nand->data_position] = (uint8_t)data;
	}

	msm6800_nand->data_position += nand->bus_width / 8;
	msm6800_nand->data_position %= nand->page_size + (nand->page_size <= 512 ? 16 : 64);

	return ERROR_OK;
}

static int msm6800_nand_reset(struct nand_device *nand)
{
	return ERROR_OK; // Dummy Reset Command
}

static int msm6800_nand_ready(struct nand_device *nand, int timeout)
{
	return msm6800_wait_timeout(nand, timeout);
}

NAND_DEVICE_COMMAND_HANDLER(msm6800_nand_device_command)
{
	struct msm6800_nand_controller *msm6800_nand;

	msm6800_nand = calloc(1, sizeof(struct msm6800_nand_controller));
	if (!msm6800_nand)
	{
		LOG_ERROR("no memory for nand controller");
		return ERROR_NAND_DEVICE_INVALID;
	}

	nand->controller_priv = msm6800_nand;

	msm6800_nand->base_offset = 0x60000000;
	msm6800_nand->clr_address = 0x80000414;
	msm6800_nand->int_address = 0x80000488;
	msm6800_nand->op_reset_flag = 2;
	msm6800_nand->skip_init = false;
	msm6800_nand->skip_gpio_init = false;
	msm6800_nand->cfg1 = 0xffffffff;
	msm6800_nand->cfg2 = 0xffffffff;
	msm6800_nand->cfg_common = 0xffffffff;
	msm6800_nand->first_read = 0;
	msm6800_nand->prev_cfg1 = 0;
	msm6800_nand->prev_cfg2 = 0;
	msm6800_nand->prev_cfg1_f2 = 0;
	msm6800_nand->prev_cfg2_f2 = 0;
	msm6800_nand->prev_cfg_common = 0;
	msm6800_nand->init_done = 0;
	msm6800_nand->device_id = 0;

	return ERROR_OK;
}

static int msm6800_nand_init(struct nand_device *nand)
{
	struct msm6800_nand_controller *msm6800_nand = nand->controller_priv;
	struct target *target = nand->target;
	int autodetect = !nand->page_size;
	int bus_width = nand->bus_width ? nand->bus_width : 8;
	int page_size = nand->page_size ? nand->page_size : 512;
	int result;
	uint32_t temp;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	if (bus_width != 8 && bus_width != 16)
	{
		LOG_ERROR("msm6800 nandc only supports 8 bit and 16-bit bus width, not %i", bus_width);
		return ERROR_NAND_OPERATION_NOT_SUPPORTED;
	}

	if (page_size != 512 && page_size != 2048)
	{
		if ((page_size < 1024) || (page_size > 4096))
		{
			LOG_ERROR("msm6800 nandc only supports small and large block NAND");
			return ERROR_NAND_OPERATION_NOT_SUPPORTED;
		}

		LOG_WARNING("BUG: extended IDCODE is null?");
		page_size = 2048;
	}

	/* inform calling code about selected bus width */
	nand->bus_width = bus_width;
	nand->page_size = page_size;

	/* configure nand controller */
	if (!msm6800_nand->init_done)
	{
		msm6800_nand->init_done = 1;

		if (!msm6800_nand->skip_gpio_init)
		{
			for (int c = 0; c < 8; c++)
			{
				target_write_u32(target, 0x80000900 + (c * 4), 0xffffffff);
			}
		}

		result = target_read_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_COMMON_CFG, &msm6800_nand->prev_cfg_common);
		if (result != ERROR_OK)
		{
			return ERROR_NAND_OPERATION_FAILED;
		}

		result = target_read_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CFG1_FLASH1, &msm6800_nand->prev_cfg1);
		if (result != ERROR_OK)
		{
			return ERROR_NAND_OPERATION_FAILED;
		}

		result = target_read_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CFG2_FLASH1, &msm6800_nand->prev_cfg2);
		if (result != ERROR_OK)
		{
			return ERROR_NAND_OPERATION_FAILED;
		}

		result = target_read_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CFG1_FLASH2, &msm6800_nand->prev_cfg1_f2);
		if (result != ERROR_OK)
		{
			return ERROR_NAND_OPERATION_FAILED;
		}

		result = target_read_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CFG2_FLASH2, &msm6800_nand->prev_cfg2_f2);
		if (result != ERROR_OK)
		{
			return ERROR_NAND_OPERATION_FAILED;
		}

		if (!msm6800_nand->skip_init)
		{
			target_write_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CFG1_FLASH1, 0xa2);
			target_write_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CFG1_FLASH2, 0x22);
		}

		if (autodetect)
		{
			target_write_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CMD, MSM6250_CMD_FLASH_RESET_NAND);
			CHECK_TIMEOUT_6800;

			result = GET_BIT(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_STATUS, MSM6800_STATUS_NAND_AUTOPROBE_DONE, &temp);
			if (result != ERROR_OK)
			{
				return ERROR_NAND_OPERATION_FAILED;
			}

			if (temp)
			{
				target_write_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_COMMON_CFG, (1 << MSM6800_COMMONCFG_NAND_AUTOPROBE.bit_pos) | (msm6800_nand->device_id << MSM6800_COMMONCFG_NAND_SEL.bit_pos));
				target_write_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_CMD, MSM6250_CMD_FLASH_PAGE_READ);
				CHECK_TIMEOUT_6800;

				target_write_u32(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_COMMON_CFG, msm6800_nand->prev_cfg_common);
			}

			result = GET_BIT(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_STATUS, MSM6800_STATUS_NAND_AUTOPROBE_ISLARGE, &temp);
			if (result != ERROR_OK)
			{
				return ERROR_NAND_OPERATION_FAILED;
			}

#ifdef DEBUG_MSM_NANDC
			temp = DEBUG_MSM_NAND_SIZE;
#endif

			page_size = temp ? 2048 : 512;
			result = GET_BIT(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_STATUS, MSM6800_STATUS_NAND_AUTOPROBE_IS16BIT, &temp);
			if (result != ERROR_OK)
			{
				return ERROR_NAND_OPERATION_FAILED;
			}

			bus_width = temp ? 16 : 8;

			nand->bus_width = bus_width;
			nand->page_size = page_size;

			SET_BIT(target, msm6800_nand->base_offset + MSM6800_REG_FLASH_COMMON_CFG, MSM6800_COMMONCFG_NAND_SEL, msm6800_nand->cfg_common);
		}
	}

	msm6800_nand->cfg_common = msm6800_nand->cfg_common != 0xffffffff ? msm6800_nand->cfg_common : (0x3 | (msm6800_nand->device_id << MSM6800_COMMONCFG_NAND_SEL.bit_pos));
	msm6800_nand->cfg1 = msm6800_nand->cfg1 != 0xffffffff ? msm6800_nand->cfg1 : 0xa;
	msm6800_nand->cfg2 = msm6800_nand->cfg2 != 0xffffffff ? msm6800_nand->cfg2 : 0x4219442;

	msm6800_nand->cfg1 &= ~((1 << MSM6800_CONFIG1_WIDE_NAND.bit_pos) | (1 << MSM6800_CONFIG1_PAGE_IS_2KB.bit_pos));
	msm6800_nand->cfg1 |= ((bus_width == 16 ? 1 : 0) << MSM6800_CONFIG1_WIDE_NAND.bit_pos) | ((page_size > 512 ? 1 : 0) << MSM6800_CONFIG1_PAGE_IS_2KB.bit_pos);

	return ERROR_OK;
}

/* Command handlers */

#define BOOL_SETTER_6800(name, setter, desc)                                   \
	COMMAND_HANDLER(name)                                                      \
	{                                                                          \
		struct nand_device *nand = NULL;                                       \
		struct msm6800_nand_controller *p = NULL;                              \
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

#define INT_SETTER_6800(name, setter, format, desc)                            \
	COMMAND_HANDLER(name)                                                      \
	{                                                                          \
		struct nand_device *nand = NULL;                                       \
		struct msm6800_nand_controller *p = NULL;                              \
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
                                                                               \
		if (CMD_ARGC > 1)                                                      \
			COMMAND_PARSE_NUMBER(uint, CMD_ARGV[1], (setter));                 \
                                                                               \
		command_print(CMD, desc " is " format, (setter));                      \
		return ERROR_OK;                                                       \
	}

INT_SETTER_6800(handle_msm6800_base_addr_command, p->base_offset, "0x%x", "base_addr")
INT_SETTER_6800(handle_msm6800_int_clr_addr_command, p->clr_address, "0x%x", "int_clr_addr")
INT_SETTER_6800(handle_msm6800_int_addr_command, p->int_address, "0x%x", "int_addr")
INT_SETTER_6800(handle_msm6800_op_command, p->op_reset_flag, "%u", "op")
BOOL_SETTER_6800(handle_msm6800_skip_init_command, p->skip_init, "skip_init")
BOOL_SETTER_6800(handle_msm6800_skip_gpio_init_command, p->skip_gpio_init, "skip_gpio_init")
INT_SETTER_6800(handle_msm6800_custom_cfg1_command, p->cfg1, "0x%x", "custom_cfg1")
INT_SETTER_6800(handle_msm6800_custom_cfg2_command, p->cfg2, "0x%x", "custom_cfg2")
INT_SETTER_6800(handle_msm6800_custom_cfg_common_command, p->cfg_common, "0x%x", "custom_cfg_common")
INT_SETTER_6800(handle_msm6800_device_id_command, p->device_id, "%u", "device_id")

static const struct command_registration msm6800_sub_command_handlers[] = {
	{
		.name = "base_addr",
		.handler = handle_msm6800_base_addr_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [base_addr]",
	},
	{
		.name = "int_clr_addr",
		.handler = handle_msm6800_int_clr_addr_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [int_clr_addr]",
	},
	{
		.name = "int_addr",
		.handler = handle_msm6800_int_addr_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [int_addr]",
	},
	{
		.name = "op",
		.handler = handle_msm6800_op_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [op]",
	},
	{
		.name = "skip_init",
		.handler = handle_msm6800_skip_init_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [skip_init]",
	},
	{
		.name = "skip_gpio_init",
		.handler = handle_msm6800_skip_gpio_init_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [skip_gpio_init]",
	},
	{
		.name = "custom_cfg1",
		.handler = handle_msm6800_custom_cfg1_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [custom_cfg1]",
	},
	{
		.name = "custom_cfg2",
		.handler = handle_msm6800_custom_cfg2_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [custom_cfg2]",
	},
	{
		.name = "custom_cfg_common",
		.handler = handle_msm6800_custom_cfg_common_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [custom_cfg_common]",
	},
	{
		.name = "device_id",
		.handler = handle_msm6800_device_id_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [device_id]",
	},
	COMMAND_REGISTRATION_DONE};

static const struct command_registration msm6800_nand_commands[] = {
	{
		.name = "msm6800",
		.mode = COMMAND_ANY,
		.help = "MSM6800 NAND flash controller commands",
		.usage = "",
		.chain = msm6800_sub_command_handlers,
	},
	COMMAND_REGISTRATION_DONE};

struct nand_flash_controller msm6800_nand_controller = {
	.name = "msm6800",
	.command = msm6800_nand_command,
	.address = msm6800_nand_address,
	.read_data = msm6800_nand_read,
	.write_data = msm6800_nand_write,
	.write_page = msm6800_nand_fastwrite,
	.read_page = msm6800_nand_fastread,
	.read_block_data = msm6800_nand_read_data,
	.write_block_data = msm6800_nand_write_data,
	.nand_ready = msm6800_nand_ready,
	.reset = msm6800_nand_reset,
	.nand_device_command = msm6800_nand_device_command,
	.commands = msm6800_nand_commands,
	.init = msm6800_nand_init,
};

/* Begin 03 - MSM7200 NAND Controller */
struct msm7200_nand_controller
{
	uint8_t target_cmd;
	uint32_t base_offset;
	bool skip_init;
	uint32_t prev_cfg1;
	uint32_t prev_cfg2;
	uint32_t prev_cfg1_f2;
	uint32_t prev_cfg2_f2;
	uint32_t cfg1;
	uint32_t cfg2;
	uint32_t bad_block_offset;

	int next_cycle;
	uint32_t temp_addr_buf;

	uint32_t temp_idcode;
	uint8_t temp_data[0x840];
	uint32_t data_position;

	uint8_t first_read;
	uint8_t init_done;

	uint32_t device_id;
};

#define CHECK_TIMEOUT_7200                                                     \
	do                                                                         \
	{                                                                          \
		if (!msm7200_wait_timeout(nand, MSM_NAND_TIMEOUT))                     \
		{                                                                      \
			LOG_ERROR("timeout while waiting for nand operation to complete"); \
			return ERROR_NAND_OPERATION_FAILED;                                \
		}                                                                      \
	} while (0)

static int msm7200_wait_timeout(struct nand_device *nand, int timeout)
{
	struct target *target = nand->target;
	struct msm7200_nand_controller *msm7200_nand = nand->controller_priv;

	LOG_DEBUG("msm7200_wait_timeout count start=%d", timeout);

	do
	{
		uint32_t status = 0x0;
		int retval;

		retval = GET_BIT(target, msm7200_nand->base_offset + MSM7200_REG_FLASH_STATUS, MSM7200_NAND_FLASH_STATUS_OPER_STATUS, &status);
		if (retval != ERROR_OK)
		{
			LOG_ERROR("Could not read REG_FLASH_STATUS");
			return 0;
		}

#ifdef DEBUG_MSM_NANDC
		status = 0;
#endif

		if (!status)
		{
			LOG_DEBUG("msm7200_wait_timeout count=%d", timeout);
			return 1;
		}

		alive_sleep(1);
	} while (timeout-- > 0);

	return 0;
}

static int msm7200_read_request(struct nand_device *nand, uint32_t page, uint8_t ecc, uint32_t subsequent);
static int msm7200_send_command(struct nand_device *nand, uint32_t command)
{
	struct target *target = nand->target;
	struct msm7200_nand_controller *msm7200_nand = nand->controller_priv;

	LOG_DEBUG("MSM7200 NANDC: send command 0x%x", command);

	target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_FLASH_CMD, command);
	target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_EXEC_CMD, 1);
	CHECK_TIMEOUT_7200;

	return ERROR_OK;
}

static int msm7200_nand_command(struct nand_device *nand, uint8_t command)
{
	struct target *target = nand->target;
	struct msm7200_nand_controller *msm7200_nand = nand->controller_priv;

	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	LOG_DEBUG("MSM7200 NANDC: cmd 0x%x", command);

	msm7200_nand->target_cmd = command;

	switch (command)
	{
	case NAND_CMD_RESET:
	{
		LOG_DEBUG("MSM7200 NANDC: execute reset operation");

		result = msm7200_send_command(nand, MSM7200_CMD_RESET_NAND);
		if (result != ERROR_OK)
			return result;
	}
	// fall through
	case NAND_CMD_READ0:
	case NAND_CMD_READ1:
	case NAND_CMD_READOOB:
	case NAND_CMD_READID:
	case NAND_CMD_SEQIN:
	case NAND_CMD_ERASE1:
		LOG_DEBUG("MSM7200 NANDC: reset io operation");
		msm7200_nand->next_cycle = 0;
		msm7200_nand->temp_addr_buf = 0;
	case NAND_CMD_STATUS:
		break;
	case NAND_CMD_READSTART:
	{
		if (nand->page_size > 512)
		{
			LOG_DEBUG("MSM7200 NANDC: execute large block read operation, page number: %d", msm7200_nand->temp_addr_buf);
			msm7200_nand->data_position = 0;

			for (int cycle = 0; cycle < 4; cycle++)
			{
				LOG_DEBUG("MSM7200 NANDC: data: 0x%x, spare: 0x%x", (0x200 * cycle), 0x800 + (0x10 * cycle));

				result = msm7200_read_request(nand, msm7200_nand->temp_addr_buf, 0, cycle > 0 ? 1 : 0);
				if (result != ERROR_OK)
					return result;

				result = target_read_memory(target, msm7200_nand->base_offset + MSM7200_REG_FLASH_BUFFER, 1, 0x200, msm7200_nand->temp_data + (0x200 * cycle));
				if (result != ERROR_OK)
					return ERROR_NAND_OPERATION_FAILED;

				result = target_read_memory(target, msm7200_nand->base_offset + MSM7200_REG_FLASH_BUFFER + 0x200, 1, 0x10, msm7200_nand->temp_data + 0x800 + (0x10 * cycle));
				if (result != ERROR_OK)
					return ERROR_NAND_OPERATION_FAILED;

#ifdef DEBUG_MSM_NANDC
				memset(msm7200_nand->temp_data + (0x200 * cycle), 0x11 + (0x11 * cycle), 0x200);
				memset(msm7200_nand->temp_data + 0x800 + (0x10 * cycle), 0x22 + (0x11 * cycle), 0x10);
#endif
			}
			break;
		}
	}
	// fall through
	default:
		LOG_ERROR("NAND CMD operation 0x%x is not supported.", command);
	}

	return ERROR_OK;
}

static int msm7200_read_request(struct nand_device *nand, uint32_t page, uint8_t ecc, uint32_t subsequent)
{
	struct target *target = nand->target;
	struct msm7200_nand_controller *msm7200_nand = nand->controller_priv;

	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	LOG_DEBUG("MSM7200 NANDC: request page read, no: %d, subsequent: %d", page, subsequent);

	if (!subsequent)
	{
		if (!msm7200_nand->first_read)
		{
			msm7200_nand->first_read = 1;

			if (!msm7200_nand->skip_init)
			{
				result = msm7200_send_command(nand, MSM7200_CMD_RESET);
				if (result != ERROR_OK)
					return result;
			}

			result = msm7200_send_command(nand, MSM7200_CMD_RESET_NAND);
			if (result != ERROR_OK)
				return result;

			if (!msm7200_nand->skip_init)
			{
				target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_DEV0_CFG0, msm7200_nand->cfg1);
				target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_DEV0_CFG1, msm7200_nand->cfg2);
				target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_DEV1_CFG0, msm7200_nand->cfg1);
				target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_DEV1_CFG1, msm7200_nand->cfg2);
				target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_DEV_CMD_VLD, 0xd);
			}

			result = SET_BIT(target, msm7200_nand->base_offset + MSM7200_REG_DEV0_CFG1, MSM7200_NAND_DEV_CFG1_ECC_DISABLE, !ecc);
			if (result != ERROR_OK)
				return ERROR_NAND_OPERATION_FAILED;

			result = SET_BIT(target, msm7200_nand->base_offset + MSM7200_REG_DEV1_CFG1, MSM7200_NAND_DEV_CFG1_ECC_DISABLE, !ecc);
			if (result != ERROR_OK)
				return ERROR_NAND_OPERATION_FAILED;
		}

		if (nand->page_size <= 512)
		{
			target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_ADDR0, (page << 8) & 0xffffffff);
			target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_ADDR1, (page >> 24) & 0xffffffff);
		}
		else
		{
			target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_ADDR0, (page << 16) & 0xffffffff);
			target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_ADDR0, (page >> 16) & 0xffffffff);
		}

		target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_FLASH_CMD, MSM7200_CMD_PAGE_READ_ALL);
	}

	target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_EXEC_CMD, 1);
	CHECK_TIMEOUT_7200;
	return ERROR_OK;
}

static int msm7200_nand_address(struct nand_device *nand, uint8_t address)
{
	struct target *target = nand->target;
	struct msm7200_nand_controller *msm7200_nand = nand->controller_priv;

	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	msm7200_nand->next_cycle++;
	LOG_DEBUG("MSM7200 NANDC: address cycle %d: 0x%x", msm7200_nand->next_cycle, address);

	if (msm7200_nand->next_cycle > (nand->page_size <= 512 ? 1 : 2))
	{
		msm7200_nand->temp_addr_buf |= (address << (8 * (msm7200_nand->next_cycle - (nand->page_size <= 512 ? 2 : 3))));
		LOG_DEBUG("MSM7200 NANDC: address shift, page number data: 0x%x, shift: %d", msm7200_nand->temp_addr_buf, (8 * (msm7200_nand->next_cycle - (nand->page_size <= 512 ? 2 : 3))));
	}

	switch (msm7200_nand->target_cmd)
	{
	case NAND_CMD_READID:
		if (msm7200_nand->next_cycle == 1)
		{
			LOG_DEBUG("MSM7200 NANDC: execute read id operation");
			result = msm7200_send_command(nand, MSM7200_CMD_FETCH_ID);
			if (result != ERROR_OK)
				return result;

			result = target_read_u32(target, msm7200_nand->base_offset + MSM7200_REG_READ_ID, &msm7200_nand->temp_idcode);
			if (result != ERROR_OK)
				return ERROR_NAND_OPERATION_FAILED;

#ifdef DEBUG_MSM_NANDC
#if DEBUG_MSM_NAND_SIZE == 1
			msm7200_nand->temp_idcode = 0x5500b198;
#else
			msm7200_nand->temp_idcode = 0x00007298;
#endif
#endif
		}
		break;

	case NAND_CMD_READ0:
	case NAND_CMD_READ1:
	case NAND_CMD_READOOB:
		if (msm7200_nand->next_cycle == nand->address_cycles && nand->page_size <= 512)
		{
			msm7200_nand->data_position = msm7200_nand->target_cmd == NAND_CMD_READOOB ? 0x200 : (msm7200_nand->target_cmd == NAND_CMD_READ1 ? 0x100 : 0x0);
			LOG_DEBUG("MSM7200 NANDC: execute read operation, data position set to 0x%x, page number: %d", msm7200_nand->data_position, msm7200_nand->temp_addr_buf);

			result = msm7200_read_request(nand, msm7200_nand->temp_addr_buf, 0, 0);
			if (result != ERROR_OK)
				return result;

			result = target_read_memory(target, msm7200_nand->base_offset + MSM7200_REG_FLASH_BUFFER, 1, 0x210, msm7200_nand->temp_data);
			if (result != ERROR_OK)
				return ERROR_NAND_OPERATION_FAILED;

#ifdef DEBUG_MSM_NANDC
			memset(msm7200_nand->temp_data, 0x11, 0x200);
			memset(msm7200_nand->temp_data + 0x200, 0x22, 0x10);
#endif
		}
		break;

	case NAND_CMD_PAGEPROG:
	case NAND_CMD_ERASE2:
		return ERROR_NAND_OPERATION_NOT_SUPPORTED;
		/*
		default:
			LOG_ERROR("should not reach here");
			return ERROR_NAND_OPERATION_FAILED;
		*/
	}

	return ERROR_OK;
}

static int msm7200_nand_read(struct nand_device *nand, void *data)
{
	struct target *target = nand->target;
	struct msm7200_nand_controller *msm7200_nand = nand->controller_priv;
	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	switch (msm7200_nand->target_cmd)
	{
	case NAND_CMD_READID:
		*(uint8_t *)data = (uint8_t)(msm7200_nand->temp_idcode & 0xff);
		msm7200_nand->temp_idcode >>= 8;
		break;

	case NAND_CMD_STATUS:
		LOG_DEBUG("MSM7200 NANDC: get status");
		result = msm7200_send_command(nand, MSM7200_CMD_STATUS);
		if (result != ERROR_OK)
			return result;

		result = GET_BIT(target, msm7200_nand->base_offset + MSM7200_REG_FLASH_STATUS, MSM7200_NAND_FLASH_STATUS_DEV_STATUS, data);
		if (result != ERROR_OK)
			return ERROR_NAND_OPERATION_FAILED;

#ifdef DEBUG_MSM_NANDC
		*(uint8_t *)data = NAND_STATUS_READY | NAND_STATUS_WP | NAND_STATUS_TRUE_READY;
#endif
		break;

	default:
		LOG_DEBUG("MSM7200 NANDC: read %d bytes from buffer 0x%x", nand->bus_width / 8, msm7200_nand->data_position);
		if (nand->bus_width == 16)
		{
			*(uint16_t *)data = target_buffer_get_u16(target, &msm7200_nand->temp_data[msm7200_nand->data_position]);
		}
		else
		{
			*(uint8_t *)data = msm7200_nand->temp_data[msm7200_nand->data_position];
		}

		msm7200_nand->data_position += nand->bus_width / 8;
		msm7200_nand->data_position %= nand->page_size + (nand->page_size <= 512 ? 16 : 64);
	}

	return ERROR_OK;
}

static int msm7200_nand_read_data(struct nand_device *nand, uint8_t *data, int size)
{
	struct msm7200_nand_controller *msm7200_nand = nand->controller_priv;
	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	LOG_DEBUG("MSM7200 NANDC: read %d bytes from buffer 0x%x", size, msm7200_nand->data_position);

	memcpy(data, msm7200_nand->temp_data + msm7200_nand->data_position, size);

	msm7200_nand->data_position += size;
	msm7200_nand->data_position %= nand->page_size + (nand->page_size <= 512 ? 16 : 64);

	return ERROR_OK;
}

static int msm7200_nand_fastread(struct nand_device *nand, uint32_t page, uint8_t *data, uint32_t data_size, uint8_t *oob, uint32_t oob_size)
{
	struct target *target = nand->target;
	struct msm7200_nand_controller *msm7200_nand = nand->controller_priv;

	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	LOG_DEBUG("MSM7200 NANDC: execute read operation, read 0x%x data bytes, 0x%x spare bytes, page number: %d", data_size, oob_size, page);

	if (nand->page_size <= 512)
	{
		result = msm7200_read_request(nand, page, 1, 0);
		if (result != ERROR_OK)
			return result;

		result = target_read_memory(target, msm7200_nand->base_offset + MSM7200_REG_FLASH_BUFFER, 1, data_size, data);
		if (result != ERROR_OK)
			return ERROR_NAND_OPERATION_FAILED;

		result = target_read_memory(target, msm7200_nand->base_offset + MSM7200_REG_FLASH_BUFFER + 0x200, 1, oob_size, oob);
		if (result != ERROR_OK)
			return ERROR_NAND_OPERATION_FAILED;
#ifdef DEBUG_MSM_NANDC
		memset(data, 0x11, data_size);
		memset(oob, 0x22, oob_size);
#endif
	}
	else
	{
		for (int cycle = 0; cycle < 4; cycle++)
		{
			LOG_DEBUG("MSM7200 NANDC: data: 0x%x, spare: 0x%x", (0x200 * cycle), (0x10 * cycle));

			result = msm7200_read_request(nand, page, 1, cycle > 0 ? 1 : 0);
			if (result != ERROR_OK)
				return result;

			result = target_read_memory(target, msm7200_nand->base_offset + MSM7200_REG_FLASH_BUFFER, 1, 0x200, data + (0x200 * cycle));
			if (result != ERROR_OK)
				return ERROR_NAND_OPERATION_FAILED;

			result = target_read_memory(target, msm7200_nand->base_offset + MSM7200_REG_FLASH_BUFFER + 0x200, 1, 0x10, oob + (0x10 * cycle));
			if (result != ERROR_OK)
				return ERROR_NAND_OPERATION_FAILED;
#ifdef DEBUG_MSM_NANDC
			memset(data + (0x200 * cycle), 0x11 + (0x11 * cycle), 0x200);
			memset(oob + (0x10 * cycle), 0x22 + (0x11 * cycle), 0x10);
#endif
		}
	}

	return ERROR_OK;
}

static int msm7200_nand_fastwrite(struct nand_device *nand, uint32_t page, uint8_t *data, uint32_t data_size, uint8_t *oob, uint32_t oob_size)
{
	return ERROR_NAND_OPERATION_NOT_SUPPORTED; // TODO
}

static int msm7200_nand_write_data(struct nand_device *nand, uint8_t *data, int size)
{
	struct msm7200_nand_controller *msm7200_nand = nand->controller_priv;
	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	LOG_DEBUG("MSM7200 NANDC: write %d bytes to buffer 0x%x", size, msm7200_nand->data_position);

	memcpy(msm7200_nand->temp_data + msm7200_nand->data_position, data, size);

	msm7200_nand->data_position += size;
	msm7200_nand->data_position %= nand->page_size + (nand->page_size <= 512 ? 16 : 64);

	return ERROR_OK;
}

static int msm7200_nand_write(struct nand_device *nand, uint16_t data)
{
	struct target *target = nand->target;
	struct msm7200_nand_controller *msm7200_nand = nand->controller_priv;
	int result;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	LOG_DEBUG("MSM7200 NANDC: write %d bytes to buffer 0x%x", nand->bus_width / 8, msm7200_nand->data_position);

	if (nand->bus_width == 16)
	{
		target_buffer_set_u16(target, &msm7200_nand->temp_data[msm7200_nand->data_position], data);
	}
	else
	{
		msm7200_nand->temp_data[msm7200_nand->data_position] = (uint8_t)data;
	}

	msm7200_nand->data_position += nand->bus_width / 8;
	msm7200_nand->data_position %= nand->page_size + (nand->page_size <= 512 ? 16 : 64);

	return ERROR_OK;
}

static int msm7200_nand_reset(struct nand_device *nand)
{
	return ERROR_OK; // Dummy Reset Command
}

static int msm7200_nand_ready(struct nand_device *nand, int timeout)
{
	return msm7200_wait_timeout(nand, timeout);
}

NAND_DEVICE_COMMAND_HANDLER(msm7200_nand_device_command)
{
	struct msm7200_nand_controller *msm7200_nand;

	msm7200_nand = calloc(1, sizeof(struct msm7200_nand_controller));
	if (!msm7200_nand)
	{
		LOG_ERROR("no memory for nand controller");
		return ERROR_NAND_DEVICE_INVALID;
	}

	nand->controller_priv = msm7200_nand;

	msm7200_nand->base_offset = 0xa0a00000;
	msm7200_nand->skip_init = false;
	msm7200_nand->cfg1 = 0xffffffff;
	msm7200_nand->cfg2 = 0xffffffff;
	msm7200_nand->first_read = 0;
	msm7200_nand->prev_cfg1 = 0;
	msm7200_nand->prev_cfg2 = 0;
	msm7200_nand->prev_cfg1_f2 = 0;
	msm7200_nand->prev_cfg2_f2 = 0;
	msm7200_nand->init_done = 0;
	msm7200_nand->device_id = 0;
	msm7200_nand->bad_block_offset = 0xffffffff;

	return ERROR_OK;
}

static int msm7200_nand_init(struct nand_device *nand)
{
	struct msm7200_nand_controller *msm7200_nand = nand->controller_priv;
	struct target *target = nand->target;
	int autodetect = !nand->page_size;
	int bus_width = nand->bus_width ? nand->bus_width : 8;
	int page_size = nand->page_size ? nand->page_size : 512;
	int result;
	uint32_t temp;

	result = validate_target_state(nand);
	if (result != ERROR_OK)
		return result;

	if (bus_width != 8 && bus_width != 16)
	{
		LOG_ERROR("msm7200 nandc only supports 8 bit and 16-bit bus width, not %i", bus_width);
		return ERROR_NAND_OPERATION_NOT_SUPPORTED;
	}

	if (page_size != 512 && page_size != 2048)
	{
		if ((page_size < 1024) || (page_size > 4096))
		{
			LOG_ERROR("msm7200 nandc only supports small and large block NAND");
			return ERROR_NAND_OPERATION_NOT_SUPPORTED;
		}

		LOG_WARNING("BUG: extended IDCODE is null?");
		page_size = 2048;
	}

	/* inform calling code about selected bus width */
	nand->bus_width = bus_width;
	nand->page_size = page_size;

	/* configure nand controller */
	if (!msm7200_nand->init_done)
	{
		msm7200_nand->init_done = 1;

		result = target_read_u32(target, msm7200_nand->base_offset + MSM7200_REG_DEV0_CFG0, &msm7200_nand->prev_cfg1);
		if (result != ERROR_OK)
		{
			return ERROR_NAND_OPERATION_FAILED;
		}

		result = target_read_u32(target, msm7200_nand->base_offset + MSM7200_REG_DEV0_CFG1, &msm7200_nand->prev_cfg2);
		if (result != ERROR_OK)
		{
			return ERROR_NAND_OPERATION_FAILED;
		}

		result = target_read_u32(target, msm7200_nand->base_offset + MSM7200_REG_DEV1_CFG0, &msm7200_nand->prev_cfg1_f2);
		if (result != ERROR_OK)
		{
			return ERROR_NAND_OPERATION_FAILED;
		}

		result = target_read_u32(target, msm7200_nand->base_offset + MSM7200_REG_DEV1_CFG1, &msm7200_nand->prev_cfg2_f2);
		if (result != ERROR_OK)
		{
			return ERROR_NAND_OPERATION_FAILED;
		}

		if (!msm7200_nand->skip_init)
		{
			target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_DEV0_CFG0, 0xaad400da);
			target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_DEV0_CFG1, 0x44747c);
			target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_DEV_CMD_VLD, 0xd);
			target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_DEV_CMD0, 0x1080d060);
			target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_DEV_CMD1, 0xf00f3000);
			target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_DEV_CMD2, 0xf0ff7090);
			target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_DEV_CMD3, 0xf0ff7090);
			target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_DEV_CMD4, 0x800000);
			target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_DEV_CMD5, 0xf30094);
			target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_DEV_CMD6, 0x40e0);
			target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_FLASH_CHIP_SELECT, msm7200_nand->device_id);
		}

		result = msm7200_send_command(nand, MSM7200_CMD_RESET);
		if (result != ERROR_OK)
			return result;

		result = msm7200_send_command(nand, MSM7200_CMD_RESET_NAND);
		if (result != ERROR_OK)
			return result;

		target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_ADDR0, 0x0);
		target_write_u32(target, msm7200_nand->base_offset + MSM7200_REG_ADDR1, 0x0);

		result = msm7200_send_command(nand, (4 << MSM7200_NAND_FLASH_CMD_AUTO_DETECT_DATA_XFR_SIZE.bit_pos) | (1 << MSM7200_NAND_FLASH_CMD_AUTO_DETECT.bit_pos) | (1 << MSM7200_NAND_FLASH_CMD_LAST_PAGE.bit_pos) | (1 << MSM7200_NAND_FLASH_CMD_PAGE_ACC.bit_pos) | (MSM7200_NAND_FLASH_CMD_OP_CMD_PAGE_READ << MSM7200_NAND_FLASH_CMD_OP_CMD.bit_pos));
		if (result != ERROR_OK)
			return result;

		result = GET_BIT(target, msm7200_nand->base_offset + MSM7200_REG_READ_STATUS, MSM7200_NAND_FLASH_STATUS_OP_ERR, &temp);
		if (result != ERROR_OK)
			return result;

#ifndef DEBUG_MSM_NANDC
		if (temp)
		{
			LOG_ERROR("msm7200: autoprobe returned an error");
			return ERROR_NAND_OPERATION_FAILED;
		}
#endif

		result = GET_BIT(target, msm7200_nand->base_offset + MSM7200_REG_READ_STATUS, MSM7200_NAND_FLASH_STATUS_AUTO_DETECT_DONE, &temp);
		if (result != ERROR_OK)
			return result;

#ifndef DEBUG_MSM_NANDC
		if (!temp)
		{
			LOG_ERROR("msm7200: autoprobe done flag not set?");
			return ERROR_NAND_OPERATION_FAILED;
		}
#endif

		result = GET_BIT(target, msm7200_nand->base_offset + MSM7200_REG_READ_STATUS, MSM7200_NAND_FLASH_STATUS_FIELD_2KBYTE_DEVICE, &temp);
		if (result != ERROR_OK)
			return result;

#ifdef DEBUG_MSM_NANDC
		temp = DEBUG_MSM_NAND_SIZE;
#endif

		if (autodetect)
			nand->page_size = temp ? 2048 : 512;
	}

	if (msm7200_nand->bad_block_offset == 0xffffffff)
	{
		switch (nand->bus_width)
		{
		case 8:
			msm7200_nand->bad_block_offset = nand->page_size <= 512 ? 0x406 : 0x1d1;
			break;

		case 16:
			msm7200_nand->bad_block_offset = nand->page_size <= 512 ? 0x401 : 0x1d1;
		}
	}

	msm7200_nand->cfg1 = msm7200_nand->cfg1 != 0xffffffff ? msm7200_nand->cfg1 : 0xaad400da;
	msm7200_nand->cfg2 = msm7200_nand->cfg2 != 0xffffffff ? msm7200_nand->cfg2 : 0x44747c;

	msm7200_nand->cfg1 &= ~(MSM7200_NAND_DEV_CFG0_CW_PER_PAGE__8_CODEWORDS_PER_PAGE << MSM7200_NAND_DEV_CFG0_CW_PER_PAGE.bit_pos);
	msm7200_nand->cfg1 |= ((nand->page_size > 512 ? MSM7200_NAND_DEV_CFG0_CW_PER_PAGE__4_CODEWORDS_PER_PAGE : MSM7200_NAND_DEV_CFG0_CW_PER_PAGE__1_CODEWORD_PER_PAGE) << MSM7200_NAND_DEV_CFG0_CW_PER_PAGE.bit_pos);

	msm7200_nand->cfg2 &= ~((1 << MSM7200_NAND_DEV_CFG1_WIDE_FLASH.bit_pos) | (1 << MSM7200_NAND_DEV_CFG1_BAD_BLOCK_IN_SPARE_AREA.bit_pos) | (0x3ff << MSM7200_NAND_DEV_CFG1_BAD_BLOCK_BYTE_NUM.bit_pos));
	msm7200_nand->cfg2 |= (((nand->bus_width == 16 ? 1 : 0) << MSM7200_NAND_DEV_CFG1_WIDE_FLASH.bit_pos) | (msm7200_nand->bad_block_offset << MSM7200_NAND_DEV_CFG1_BAD_BLOCK_BYTE_NUM.bit_pos));

	return ERROR_OK;
}

/* Command handlers */

#define BOOL_SETTER_7200(name, setter, desc)                                   \
	COMMAND_HANDLER(name)                                                      \
	{                                                                          \
		struct nand_device *nand = NULL;                                       \
		struct msm7200_nand_controller *p = NULL;                              \
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

#define INT_SETTER_7200(name, setter, format, desc)                            \
	COMMAND_HANDLER(name)                                                      \
	{                                                                          \
		struct nand_device *nand = NULL;                                       \
		struct msm7200_nand_controller *p = NULL;                              \
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
                                                                               \
		if (CMD_ARGC > 1)                                                      \
			COMMAND_PARSE_NUMBER(uint, CMD_ARGV[1], (setter));                 \
                                                                               \
		command_print(CMD, desc " is " format, (setter));                      \
		return ERROR_OK;                                                       \
	}

INT_SETTER_7200(handle_msm7200_base_addr_command, p->base_offset, "0x%x", "base_addr")
BOOL_SETTER_7200(handle_msm7200_skip_init_command, p->skip_init, "skip_init")
INT_SETTER_7200(handle_msm7200_custom_cfg1_command, p->cfg1, "0x%x", "custom_cfg1")
INT_SETTER_7200(handle_msm7200_custom_cfg2_command, p->cfg2, "0x%x", "custom_cfg2")
INT_SETTER_7200(handle_msm7200_bad_block_offset_command, p->bad_block_offset, "0x%x", "bad_block_offset")
INT_SETTER_7200(handle_msm7200_device_id_command, p->device_id, "%u", "device_id")

static const struct command_registration msm7200_sub_command_handlers[] = {
	{
		.name = "base_addr",
		.handler = handle_msm7200_base_addr_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [base_addr]",
	},
	{
		.name = "skip_init",
		.handler = handle_msm7200_skip_init_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [skip_init]",
	},
	{
		.name = "custom_cfg1",
		.handler = handle_msm7200_custom_cfg1_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [custom_cfg1]",
	},
	{
		.name = "custom_cfg2",
		.handler = handle_msm7200_custom_cfg2_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [custom_cfg2]",
	},
	{
		.name = "bad_block_offset",
		.handler = handle_msm7200_bad_block_offset_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [bad_block_offset]",
	},
	{
		.name = "device_id",
		.handler = handle_msm7200_device_id_command,
		.mode = COMMAND_ANY,
		.help = "TODO",
		.usage = "[nand_id] [device_id]",
	},
	COMMAND_REGISTRATION_DONE};

static const struct command_registration msm7200_nand_commands[] = {
	{
		.name = "msm7200",
		.mode = COMMAND_ANY,
		.help = "MSM7200 NAND flash controller commands",
		.usage = "",
		.chain = msm7200_sub_command_handlers,
	},
	COMMAND_REGISTRATION_DONE};

struct nand_flash_controller msm7200_nand_controller = {
	.name = "msm7200",
	.command = msm7200_nand_command,
	.address = msm7200_nand_address,
	.read_data = msm7200_nand_read,
	.write_data = msm7200_nand_write,
	.write_page = msm7200_nand_fastwrite,
	.read_page = msm7200_nand_fastread,
	.read_block_data = msm7200_nand_read_data,
	.write_block_data = msm7200_nand_write_data,
	.nand_ready = msm7200_nand_ready,
	.reset = msm7200_nand_reset,
	.nand_device_command = msm7200_nand_device_command,
	.commands = msm7200_nand_commands,
	.init = msm7200_nand_init,
};