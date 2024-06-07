// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2024 Dumpit                                             *
 *                                                                         *
 ***************************************************************************/

/*
 * Bit Helpers
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imp.h"
#include "bitutils.h"
#include <target/arm.h>

/*  32 */

static int _get_bit32(struct target *target, uint32_t offset, uint32_t bit_position, uint32_t bit_mask, uint32_t *value)
{
	uint32_t temp = 0x0;
	int result;

	LOG_DEBUG("BITUTILS: ((read_u32(0x%x) >> %d) & %d)", offset, bit_position, bit_mask);

	result = target_read_u32(target, offset, &temp);
	if (result != ERROR_OK)
		return result;

	*value = (temp >> bit_position) & bit_mask;
	return ERROR_OK;
}

static int _set_bit32(struct target *target, uint32_t offset, uint32_t bit_position, uint32_t bit_mask, uint32_t value)
{
	uint32_t temp = 0x0;
	int result;

	LOG_DEBUG("BITUILS: ((read_u32(0x%x) & ~(%d << %d)) | ((%d & %d) << %d))", offset, bit_mask, bit_position, value, bit_mask, bit_position);

	result = target_read_u32(target, offset, &temp);
	if (result != ERROR_OK)
		return result;

	target_write_u32(target, offset, (temp & ~(bit_mask << bit_position)) | ((value & bit_mask) << bit_position));
	return ERROR_OK;
}

int GET_BIT32(struct target *target, uint32_t offset, struct bitmask bitmask, uint32_t *value)
{
	return _get_bit32(target, offset, bitmask.bit_pos, bitmask.bit_mask, value);
}

int SET_BIT32(struct target *target, uint32_t offset, struct bitmask bitmask, uint32_t value)
{
	return _set_bit32(target, offset, bitmask.bit_pos, bitmask.bit_mask, value);
}

/* 16 */

static int _get_bit16(struct target *target, uint32_t offset, uint32_t bit_position, uint32_t bit_mask, uint16_t *value)
{
	uint16_t temp = 0x0;
	int result;

	LOG_DEBUG("BITUTILS: ((read_u16(0x%x) >> %d) & %d)", offset, bit_position, bit_mask);

	result = target_read_u16(target, offset, &temp);
	if (result != ERROR_OK)
		return result;

	*value = (temp >> bit_position) & bit_mask;
	return ERROR_OK;
}

static int _set_bit16(struct target *target, uint32_t offset, uint32_t bit_position, uint32_t bit_mask, uint16_t value)
{
	uint16_t temp = 0x0;
	int result;

	LOG_DEBUG("BITUILS: ((read_u16(0x%x) & ~(%d << %d)) | ((%d & %d) << %d))", offset, bit_mask, bit_position, value, bit_mask, bit_position);

	result = target_read_u16(target, offset, &temp);
	if (result != ERROR_OK)
		return result;

	target_write_u16(target, offset, (temp & ~(bit_mask << bit_position)) | ((value & bit_mask) << bit_position));
	return ERROR_OK;
}

int GET_BIT16(struct target *target, uint32_t offset, struct bitmask bitmask, uint16_t *value)
{
	return _get_bit16(target, offset, bitmask.bit_pos, bitmask.bit_mask, value);
}

int SET_BIT16(struct target *target, uint32_t offset, struct bitmask bitmask, uint16_t value)
{
	return _set_bit16(target, offset, bitmask.bit_pos, bitmask.bit_mask, value);
}


/* 8 */

static int _get_bit8(struct target *target, uint32_t offset, uint32_t bit_position, uint32_t bit_mask, uint8_t *value)
{
	uint8_t temp = 0x0;
	int result;

	LOG_DEBUG("BITUTILS: ((read_u8(0x%x) >> %d) & %d)", offset, bit_position, bit_mask);

	result = target_read_u8(target, offset, &temp);
	if (result != ERROR_OK)
		return result;

	*value = (temp >> bit_position) & bit_mask;
	return ERROR_OK;
}

static int _set_bit8(struct target *target, uint32_t offset, uint32_t bit_position, uint32_t bit_mask, uint8_t value)
{
	uint8_t temp = 0x0;
	int result;

	LOG_DEBUG("BITUILS: ((read_u8(0x%x) & ~(%d << %d)) | ((%d & %d) << %d))", offset, bit_mask, bit_position, value, bit_mask, bit_position);

	result = target_read_u8(target, offset, &temp);
	if (result != ERROR_OK)
		return result;

	target_write_u8(target, offset, (temp & ~(bit_mask << bit_position)) | ((value & bit_mask) << bit_position));
	return ERROR_OK;
}

int GET_BIT8(struct target *target, uint32_t offset, struct bitmask bitmask, uint8_t *value)
{
	return _get_bit8(target, offset, bitmask.bit_pos, bitmask.bit_mask, value);
}

int SET_BIT8(struct target *target, uint32_t offset, struct bitmask bitmask, uint8_t value)
{
	return _set_bit8(target, offset, bitmask.bit_pos, bitmask.bit_mask, value);
}
