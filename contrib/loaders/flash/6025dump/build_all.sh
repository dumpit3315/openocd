#!/bin/bash
make -B -f makefile
make -B -f makefile_0x12
make -B -f makefile_0x12_on_8mb

make -B -f makefile_read2
make -B -f makefile_0x12_read2
make -B -f makefile_0x12_on_8mb_read2