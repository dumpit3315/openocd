#!/bin/bash
src/openocd -c "adapter driver dummy; jtag_rclk 1; jtag newtap target cpu -irlen 4; target create target.cpu arm926ejs -endian little -chain-position target.cpu; gdb_port disabled; telnet_port pipe; flash bank target.nor dummy_flash 0 0 0 0 target.cpu; flash probe target.cfi; flash info target.cfi;"
