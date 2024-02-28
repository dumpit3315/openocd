#!/bin/bash
src/openocd -c "adapter driver dummy; jtag_rclk 1; jtag newtap target cpu -irlen 4; target create target.cpu arm926ejs -endian little -chain-position target.cpu; gdb_port disabled; telnet_port pipe; nand device 0 msm6800 target.cpu; init" \
-c "halt; nand probe 0"
