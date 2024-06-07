#!/bin/bash
set -e
arm-none-eabi-gcc armv7m_io.s -marm -march=armv5tej -nostartfiles && arm-none-eabi-objcopy -O binary a.out a.bin && arm-none-eabi-objdump -D a.out
arm-none-eabi-gcc armv7m_io.s -mthumb -march=armv7-m -nostartfiles -o a-m3.out && arm-none-eabi-objcopy -O binary a-m3.out a-m3.bin && arm-none-eabi-objdump -D a-m3.out