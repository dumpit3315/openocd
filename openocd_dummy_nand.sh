#!/bin/bash
src/openocd -d3 -c "adapter driver dummy; jtag_rclk 1; jtag newtap target cpu -irlen 4; target create target.cpu arm926ejs -endian little -chain-position target.cpu; gdb_port disabled; telnet_port pipe; nand device 0 dummy target.cpu; init" \
-c "halt; nand_dummy type 0 1; nand probe 0; nand dump 0 test 0x48000 0x1000 oob_raw; echo [nand info 0 0 8]; nand raw_access 0 enable; nand dump 0 tesst2 0x48000 0x1000 oob_raw; shutdown"
