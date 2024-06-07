#ifndef OPENOCD_FLASH_NAND_DEBUG_H
//#define NAND_CONTROLLER_DEBUG // Define to enable debug
#ifdef NAND_CONTROLLER_DEBUG
/* BCM2133 */
#define BCM2133_DEBUG_AXI
/* MSM */
#define DEBUG_MSM_NAND_SIZE 1
/* PXA */
#define DEBUG_PXA_NAND_SIZE 3
#endif
#endif