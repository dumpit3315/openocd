#!/bin/bash
src/openocd -d3 -c "adapter driver dummy; jtag_rclk 1; jtag newtap target cpu -irlen 4; target create target.cpu arm926ejs -endian little -chain-position target.cpu; gdb_port disabled; telnet_port pipe; nand device 0 msm6250 target.cpu; init" \
-c "halt; nand probe 0; nand raw_access 0 1; nand write 0 test 0x0 oob_raw; shutdown"
