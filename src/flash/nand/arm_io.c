// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Copyright (C) 2009 by Marvell Semiconductors, Inc.
 * Written by Nicolas Pitre <nico at marvell.com>
 *
 * Copyright (C) 2009 by David Brownell
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "core.h"
#include "arm_io.h"
#include <helper/binarybuffer.h>
#include <target/arm.h>
#include <target/armv7m.h>
#include <target/algorithm.h>

/**
 * Copies code to a working area.  This will allocate room for the code plus the
 * additional amount requested if the working area pointer is null.
 *
 * @param target Pointer to the target to copy code to
 * @param code Pointer to the code area to be copied
 * @param code_size Size of the code being copied
 * @param additional Size of the additional area to be allocated in addition to
 *                   code
 * @param area Pointer to a pointer to a working area to copy code to
 * @return Success or failure of the operation
 */
static int arm_code_to_working_area(struct target *target,
									const uint32_t *code, unsigned code_size,
									unsigned additional, struct working_area **area)
{
	uint8_t code_buf[code_size];
	int retval;
	unsigned size = code_size + additional;

	/* REVISIT this assumes size doesn't ever change.
	 * That's usually correct; but there are boards with
	 * both large and small page chips, where it won't be...
	 */

	/* make sure we have a working area */
	if (!*area)
	{
		retval = target_alloc_working_area(target, size, area);
		if (retval != ERROR_OK)
		{
			LOG_DEBUG("%s: no %d byte buffer", __func__, (int)size);
			return ERROR_NAND_NO_BUFFER;
		}
	}

	/* buffer code in target endianness */
	target_buffer_set_u32_array(target, code_buf, code_size / 4, code);

	/* copy code to work area */
	retval = target_write_memory(target, (*area)->address,
								 4, code_size / 4, code_buf);

	return retval;
}

/**
 * ARM-specific bulk write from buffer to address of 8-bit wide NAND.
 * For now this supports ARMv4,ARMv5 and ARMv7-M cores.
 *
 * Enhancements to target_run_algorithm() could enable:
 *   - ARMv6 and ARMv7 cores in ARM mode
 *
 * Different code fragments could handle:
 *   - 16-bit wide data (needs different setup)
 *
 * @param nand Pointer to the arm_nand_data struct that defines the I/O
 * @param data Pointer to the data to be copied to flash
 * @param size Size of the data being copied
 * @return Success or failure of the operation
 */
int arm_nandwrite(struct arm_nand_data *nand, uint8_t *data, int size)
{
	struct target *target = nand->target;
	struct arm_algorithm armv4_5_algo;
	struct armv7m_algorithm armv7m_algo;
	void *arm_algo;
	struct arm *arm = target->arch_info;
	struct reg_param reg_params[5];
	uint32_t target_buf;
	uint32_t exit_var = 0;
	int retval;

	/* Inputs:
	 *  r0	NAND data address (byte wide)
	 *  r1	buffer address
	 *  r2	buffer length
	 *  r3  width size
	 *  r4  data read size
	 *
	 */
	static const uint32_t code_armv4_5[] = {
		/* Load */
		0xe3540010,
		0x0a000025,
		0xe3540008,
		0x0a000012,
		/* Load0 */
		0xe3530020,
		0x0a00000b,
		0xe3530010,
		0x0a000004,
		/* Load0-8 */
		0xe4d1a001,
		0xe5c0a000,
		0xe2522001,
		0x1afffffb,
		0xe1200070,
		/* Load0-16 */
		0xe0d1a0b2,
		0xe1c0a0b0,
		0xe2522002,
		0x1afffffb,
		0xe1200070,
		/* Load0-32 */
		0xe491a004,
		0xe580a000,
		0xe2522004,
		0x1afffffb,
		0xe1200070,
		/* Load8 */
		0xe3530020,
		0x0a000008,
		0xe3530010,
		0x0a000000,
		/* Load8-8 */
		0xeaffffeb,
		/* Load8-16 */
		0xe4d1a001,
		0xe20aa0ff,
		0xe1c0a0b0,
		0xe2522001,
		0x1afffffa,
		0xe1200070,
		/* Load8-32 */
		0xe4d1a001,
		0xe20aa0ff,
		0xe580a000,
		0xe2522001,
		0x1afffffa,
		0xe1200070,
		/* Load16 */
		0xe3530020,
		0x0a000003,
		0xe3530010,
		0x0a000000,
		/* Load16-8 */
		0xeaffffda,
		/* Load16-16 */
		0xeaffffde,
		/* Load16-32 */
		0xe3a0bcff,
		0xe38bb0ff,
		/* Load16-32Loop */
		0xe0d1a0b2,
		0xe00aa00b,
		0xe580a000,
		0xe2522002,
		0x1afffffa,
		0xe1200070,	
	};

	/* Inputs:
	 *  r0	NAND data address (byte wide)
	 *  r1	buffer address
	 *  r2	buffer length
	 *  r3  width size
	 *  r4  data read size
	 *
	 * see contrib/loaders/flash/armv7m_io.s for src
	 */
	static const uint32_t code_armv7m[] = {
		/* Load */
		0xd0312c10,
		0xd0182c08,
		/* Load0 */
		0xd00f2b20,
		0xd0062b10,
		/* Load0-8 */
		0xab01f811,
		0xa000f880,
		0xd1f93a01,
		/* Load0-16 */
		0xf831be00,
		0xf8a0ab02,
		0x3a02a000,
		0xbe00d1f9,
		/* Load0-32 */
		0xab04f851,
		0xa000f8c0,
		0xd1f93a04,
		/* Load8 */
		0x2b20be00,
		0x2b10d00b,
		/* Load8-8 */
		0xe7e5d000,
		/* Load8-16 */
		0xab01f811,
		0x0afff00a,
		0xa000f8a0,
		0xd1f73a01,
		/* Load8-32 */
		0xf811be00,
		0xf00aab01,
		0xf8c00aff,
		0x3a01a000,
		0xbe00d1f7,
		/* Load16 */
		0xd0032b20,
		0xd0002b10,
		/* Load16-8_16 */
		0xe7d4e7ce,
		/* Load16-32 */
		0x4b7ff44f,
		0x0bfff04b,
		0xab02f831,
		0x0a0bea0a,
		0xa000f8c0,
		0xd1f73a02,
		0xbf00be00
	};

	int target_code_size = 0;
	const uint32_t *target_code_src = NULL;

	/* set up algorithm */
	if (is_armv7m(target_to_armv7m(target)))
	{ /* armv7m target */
		armv7m_algo.common_magic = ARMV7M_COMMON_MAGIC;
		armv7m_algo.core_mode = ARM_MODE_THREAD;
		arm_algo = &armv7m_algo;
		target_code_size = sizeof(code_armv7m);
		target_code_src = code_armv7m;
	}
	else
	{
		armv4_5_algo.common_magic = ARM_COMMON_MAGIC;
		armv4_5_algo.core_mode = ARM_MODE_SVC;
		armv4_5_algo.core_state = ARM_STATE_ARM;
		arm_algo = &armv4_5_algo;
		target_code_size = sizeof(code_armv4_5);
		target_code_src = code_armv4_5;
	}

	if (nand->op != ARM_NAND_WRITE || !nand->copy_area)
	{
		retval = arm_code_to_working_area(target, target_code_src, target_code_size,
										  nand->chunk_size, &nand->copy_area);
		if (retval != ERROR_OK)
			return retval;
	}

	nand->op = ARM_NAND_WRITE;

	/* copy data to work area */
	target_buf = nand->copy_area->address + target_code_size;
	retval = target_write_buffer(target, target_buf, size, data);
	if (retval != ERROR_OK)
		return retval;

	/* set up parameters */
	init_reg_param(&reg_params[0], "r0", 32, PARAM_IN);
	init_reg_param(&reg_params[1], "r1", 32, PARAM_IN);
	init_reg_param(&reg_params[2], "r2", 32, PARAM_IN);
	init_reg_param(&reg_params[3], "r3", 32, PARAM_IN);
	init_reg_param(&reg_params[4], "r4", 32, PARAM_IN);

	buf_set_u32(reg_params[0].value, 0, 32, nand->data);
	buf_set_u32(reg_params[1].value, 0, 32, target_buf);
	buf_set_u32(reg_params[2].value, 0, 32, size);
	buf_set_u32(reg_params[3].value, 0, 32, nand->data_width);
	buf_set_u32(reg_params[4].value, 0, 32, nand->read_width);

	/* armv4 must exit using a hardware breakpoint */
	if (arm->arch == ARM_ARCH_V4)
		exit_var = nand->copy_area->address + target_code_size - 4;

	/* use alg to write data from work area to NAND chip */
	retval = target_run_algorithm(target, 0, NULL, 3, reg_params,
								  nand->copy_area->address, exit_var, 1000, arm_algo);
	if (retval != ERROR_OK)
		LOG_ERROR("error executing hosted NAND write");

	destroy_reg_param(&reg_params[0]);
	destroy_reg_param(&reg_params[1]);
	destroy_reg_param(&reg_params[2]);

	return retval;
}

/**
 * Uses an on-chip algorithm for an ARM device to read from a NAND device and
 * store the data into the host machine's memory.
 *
 * @param nand Pointer to the arm_nand_data struct that defines the I/O
 * @param data Pointer to the data buffer to store the read data
 * @param size Amount of data to be stored to the buffer.
 * @return Success or failure of the operation
 */
int arm_nandread(struct arm_nand_data *nand, uint8_t *data, uint32_t size)
{
	struct target *target = nand->target;
	struct arm_algorithm armv4_5_algo;
	struct armv7m_algorithm armv7m_algo;
	void *arm_algo;
	struct arm *arm = target->arch_info;
	struct reg_param reg_params[5];
	uint32_t target_buf;
	uint32_t exit_var = 0;
	int retval;

	/* Inputs:
	 *  r0	buffer address
	 *  r1	NAND data address (byte wide)
	 *  r2	buffer length
	 *  r3  width size 
	 *  r4  data write size
	 *
	 */
	static const uint32_t code_armv4_5[] = {
		/* Load */
		0xe3540010,
		0x0a000025,
		0xe3540008,
		0x0a000012,
		/* Load0 */
		0xe3530020,
		0x0a00000b,
		0xe3530010,
		0x0a000004,
		/* Load0-8 */
		0xe5d1a000,
		0xe4c0a001,
		0xe2522001,
		0x1afffffb,
		0xe1200070,
		/* Load0-16 */
		0xe1d1a0b0,
		0xe0c0a0b2,
		0xe2522002,
		0x1afffffb,
		0xe1200070,
		/* Load0-32 */
		0xe591a000,
		0xe480a004,
		0xe2522004,
		0x1afffffb,
		0xe1200070,
		/* Load8 */
		0xe3530020,
		0x0a000008,
		0xe3530010,
		0x0a000000,
		/* Load8-8 */
		0xeaffffeb,
		/* Load8-16 */
		0xe1d1a0b0,
		0xe20aa0ff,
		0xe4c0a001,
		0xe2522001,
		0x1afffffa,
		0xe1200070,
		/* Load8-32 */
		0xe591a000,
		0xe20aa0ff,
		0xe4c0a001,
		0xe2522001,
		0x1afffffa,
		0xe1200070,
		/* Load16 */
		0xe3530020,
		0x0a000003,
		0xe3530010,
		0x0a000000,
		/* Load16-8 */
		0xeaffffda,
		/* Load16-16 */
		0xeaffffde,
		/* Load16-32 */
		0xe3a0bcff,
		0xe38bb0ff,
		/* Load16-32Loop */
		0xe591a000,
		0xe00aa00b,
		0xe0c0a0b2,
		0xe2522002,
		0x1afffffa,
		0xe1200070,
	};

	/* Inputs:
	 *  r0	buffer address
	 *  r1	NAND data address (byte wide)
	 *  r2	buffer length
	 *  r3  width size 
	 *  r4  data write size
	 *
	 * see contrib/loaders/flash/armv7m_io.s for src
	 */
	static const uint32_t code_armv7m[] = {
		/* Load */
		0xd0312c10,
		0xd0182c08,
		/* Load0 */
		0xd00f2b20,
		0xd0062b10,
		/* Load0-8 */
		0xa000f891,
		0xab01f800,
		0xd1f93a01,
		/* Load0-16 */
		0xf8b1be00,		
		0xf820a000,
		0x3a02ab02,
		0xbe00d1f9,
		/* Load0-32 */
		0xa000f8d1,
		0xab04f840,
		0xd1f93a04,
		/* Load8 */
		0x2b20be00,		
		0x2b10d00b,
		/* Load8-8 */
		0xe7e5d000,
		/* Load8-16 */
		0xa000f8b1,
		0x0afff00a,
		0xab01f800,
		0xd1f73a01,
		/* Load8-32 */
		0xf8d1be00,
		0xf00aa000,
		0xf8000aff,
		0x3a01ab01,
		0xbe00d1f7,
		/* Load16 */
		0xd0032b20,
		0xd0002b10,
		/* Load16-8_16 */
		0xe7d4e7ce,
		/* Load16-32 */
		0x4b7ff44f,
		0x0bfff04b,
		0xa000f8d1,
		0x0a0bea0a,
		0xab02f820,
		0xd1f73a02,		
		0xbf00be00,
	};

	int target_code_size = 0;
	const uint32_t *target_code_src = NULL;

	/* set up algorithm */
	if (is_armv7m(target_to_armv7m(target)))
	{ /* armv7m target */
		armv7m_algo.common_magic = ARMV7M_COMMON_MAGIC;
		armv7m_algo.core_mode = ARM_MODE_THREAD;
		arm_algo = &armv7m_algo;
		target_code_size = sizeof(code_armv7m);
		target_code_src = code_armv7m;
	}
	else
	{
		armv4_5_algo.common_magic = ARM_COMMON_MAGIC;
		armv4_5_algo.core_mode = ARM_MODE_SVC;
		armv4_5_algo.core_state = ARM_STATE_ARM;
		arm_algo = &armv4_5_algo;
		target_code_size = sizeof(code_armv4_5);
		target_code_src = code_armv4_5;
	}

	/* create the copy area if not yet available */
	if (nand->op != ARM_NAND_READ || !nand->copy_area)
	{
		retval = arm_code_to_working_area(target, target_code_src, target_code_size,
										  nand->chunk_size, &nand->copy_area);
		if (retval != ERROR_OK)
			return retval;
	}

	nand->op = ARM_NAND_READ;
	target_buf = nand->copy_area->address + target_code_size;

	/* set up parameters */
	init_reg_param(&reg_params[0], "r0", 32, PARAM_IN);
	init_reg_param(&reg_params[1], "r1", 32, PARAM_IN);
	init_reg_param(&reg_params[2], "r2", 32, PARAM_IN);
	init_reg_param(&reg_params[3], "r3", 32, PARAM_IN);
	init_reg_param(&reg_params[4], "r4", 32, PARAM_IN);

	buf_set_u32(reg_params[0].value, 0, 32, target_buf);
	buf_set_u32(reg_params[1].value, 0, 32, nand->data);
	buf_set_u32(reg_params[2].value, 0, 32, size);
	buf_set_u32(reg_params[3].value, 0, 32, nand->data_width);
	buf_set_u32(reg_params[4].value, 0, 32, nand->read_width);

	/* armv4 must exit using a hardware breakpoint */
	if (arm->arch == ARM_ARCH_V4)
		exit_var = nand->copy_area->address + target_code_size - 4;

	/* use alg to write data from NAND chip to work area */
	retval = target_run_algorithm(target, 0, NULL, 3, reg_params,
								  nand->copy_area->address, exit_var, 1000, arm_algo);
	if (retval != ERROR_OK)
		LOG_ERROR("error executing hosted NAND read");

	destroy_reg_param(&reg_params[0]);
	destroy_reg_param(&reg_params[1]);
	destroy_reg_param(&reg_params[2]);

	/* read from work area to the host's memory */
	retval = target_read_buffer(target, target_buf, size, data);

	return retval;
}
