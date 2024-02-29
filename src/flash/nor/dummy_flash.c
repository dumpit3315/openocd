// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2007 by Pavel Chromy                                    *
 *   (c) 2024 Dumpit                                                       *
 *                                                                         *
 *   Creates a virtual NOR flash device for testing purposes.              *
 *                                                                         *
 *   chromy@asix.cz                                                        *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imp.h"

unsigned char dummy_flash_contents[0x400000];

struct dummy_flash_priv {	
	unsigned int buflen;
	unsigned int bufalign;
};

/* flash_bank dummy_flash 0 0 0 0 <target#> */
FLASH_BANK_COMMAND_HANDLER(dummy_flash_flash_bank_command)
{	
	struct dummy_flash_priv *dummy_flash;

	if (CMD_ARGC < 6)
		return ERROR_COMMAND_SYNTAX_ERROR;

	dummy_flash = bank->driver_priv = malloc(sizeof(struct dummy_flash_priv));	
	dummy_flash->buflen = 0;
	dummy_flash->bufalign = 1;

	return ERROR_OK;
}

static int dummy_flash_erase(struct flash_bank *bank, unsigned int first,
		unsigned int last)
{	
	unsigned int i;

	/* check preconditions */
	if (bank->num_sectors == 0)
		return ERROR_FLASH_BANK_NOT_PROBED;	

	LOG_INFO("Erasing block from %d to %d", first, last);

	for (i = 0; i < ((last + 1) - first); i++) {
		LOG_INFO("Erasing block %d", first + i);
		memset(dummy_flash_contents + ((first + i) * 512), 0xff, 512);
	}	

	return ERROR_OK;
}

static int dummy_flash_write(struct flash_bank *bank, const uint8_t *buffer, uint32_t offset, uint32_t count)
{
	struct dummy_flash_priv *dummy_flash = bank->driver_priv;	

	/* check preconditions */
	if (dummy_flash->buflen == 0 || dummy_flash->bufalign == 0)
		return ERROR_FLASH_BANK_NOT_PROBED;

	LOG_INFO("Writing %d bytes to 0x%x", count, offset);

	/* allocate buffer for max. dummy_flash buffer + overhead */
	memcpy(dummy_flash_contents + offset, buffer, count);

	/*
	for (i = 0; i<count; i++) {
		dummy_flash_contents[offset+i] = buffer[i];
	}*
	*/

	return ERROR_OK;
}

static int dummy_flash_read(struct flash_bank *bank, uint8_t *buffer, uint32_t offset, uint32_t count)
{	
	LOG_INFO("Reading %d bytes from 0x%x", count, offset);

	memcpy(buffer, dummy_flash_contents + offset, count);
	/*
	for (i = 0; i<count; i++) {
		buffer[i] = dummy_flash_contents[offset+i];
	}
	*/

	return ERROR_OK;
}

static int dummy_flash_probe(struct flash_bank *bank)
{
	struct dummy_flash_priv *dummy_flash = bank->driver_priv;
	int sectsize;

	bank->base = 0x0;
	bank->size = 0x400000;
	bank->num_sectors = 1;

	dummy_flash->buflen = 4096;
	dummy_flash->bufalign = 512;

	bank->sectors = realloc(bank->sectors, sizeof(struct flash_sector)*bank->num_sectors);
	if (bank->num_sectors == 0) {
		LOG_ERROR("number of sectors shall be non zero value");
		return ERROR_FLASH_BANK_INVALID;
	}
	if (bank->size % bank->num_sectors) {
		LOG_ERROR("bank size not divisible by number of sectors");
		return ERROR_FLASH_BANK_INVALID;
	}

	sectsize = bank->size / bank->num_sectors;
	for (unsigned int i = 0; i < bank->num_sectors; i++) {
		bank->sectors[i].offset = i * sectsize;
		bank->sectors[i].size = sectsize;
		bank->sectors[i].is_erased = -1;
		bank->sectors[i].is_protected = -1;
	}

	if (dummy_flash->bufalign == 0)
		dummy_flash->bufalign = 1;

	if (dummy_flash->buflen == 0) {
		LOG_ERROR("buflen shall be non zero value");
		return ERROR_FLASH_BANK_INVALID;
	}

	if ((dummy_flash->bufalign > dummy_flash->buflen) || (dummy_flash->buflen % dummy_flash->bufalign)) {
		LOG_ERROR("buflen is not multiple of bufalign");
		return ERROR_FLASH_BANK_INVALID;
	}

	if (dummy_flash->buflen % 4) {
		LOG_ERROR("buflen shall be divisible by 4");
		return ERROR_FLASH_BANK_INVALID;
	}

	return ERROR_OK;
}

static int dummy_flash_auto_probe(struct flash_bank *bank)
{
	struct dummy_flash_priv *dummy_flash = bank->driver_priv;

	if (dummy_flash->buflen == 0 || dummy_flash->bufalign == 0)
		return ERROR_FLASH_BANK_NOT_PROBED;

	return ERROR_OK;
}

const struct flash_driver dummy_flash_flash = {
	.name = "dummy_flash",
	.flash_bank_command = dummy_flash_flash_bank_command,
	.erase = dummy_flash_erase,
	.write = dummy_flash_write,
	.read = dummy_flash_read,
	.probe = dummy_flash_probe,
	.erase_check = default_flash_blank_check,
	.auto_probe = dummy_flash_auto_probe,
	.free_driver_priv = default_flash_free_driver_priv,
};
