#include <target/arm.h>

#ifndef OPENOCD_FLASH_BITUTILS
#define OPENOCD_FLASH_BITUTILS

struct bitmask {
    uint32_t bit_pos;
    uint32_t bit_mask;    
};

int GET_BIT8(struct target *target, uint32_t offset, struct bitmask bitmask, uint8_t *value);
int GET_BIT16(struct target *target, uint32_t offset, struct bitmask bitmask, uint16_t *value);
int GET_BIT32(struct target *target, uint32_t offset, struct bitmask bitmask, uint32_t *value);

int SET_BIT8(struct target *target, uint32_t offset, struct bitmask bitmask, uint8_t value);
int SET_BIT16(struct target *target, uint32_t offset, struct bitmask bitmask, uint16_t value);
int SET_BIT32(struct target *target, uint32_t offset, struct bitmask bitmask, uint32_t value);

#endif