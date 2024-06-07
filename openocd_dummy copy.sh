#!/bin/bash
src/openocd -c "adapter driver dummy; jtag_rclk 1; jtag newtap target cpu -irlen 4; target create target.cpu arm926ejs -endian little -chain-position target.cpu; gdb_port disabled; telnet_port pipe; flash bank target.nor dummy_flash 0 0 0 0 target.cpu; init;" -c "halt; flash probe 0; set s [flash read_bank_memory 0 0x0 0x10000 0x200]; puts {ok}; shutdown;"
