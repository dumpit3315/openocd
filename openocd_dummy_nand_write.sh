#!/bin/bash
src/openocd -d3 -c "adapter driver dummy; jtag_rclk 1; jtag newtap target cpu -irlen 4; target create target.cpu arm926ejs -endian little -chain-position target.cpu; gdb_port disabled; telnet_port pipe; nand device 0 dummy target.cpu; init" \
-c "halt; nand_dummy type 0 2; nand probe 0; nand write 0 2048_nand.bin 0x0 oob_raw; nand dump 0 test_nand_dump.bin 0x0 0x8000 oob_raw; shutdown"
