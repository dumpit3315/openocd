#!/usr/bin/env python
# Sample code for ARM of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    pass
    #print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))

# callback for tracing instructions
def hook_code(uc: Uc, address, size, user_data):    
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
    
    # cp = 15
    # is64 = 0
    # sec = 0
    # crn = 1
    # crm = 0
    # opc1 = 0
    # opc2 = 0
    # val = ??
   


# Test ARM
def test_arm():
    print("Emulate ARM code")
    try:
        # Initialize emulator in ARM mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        mu.ctl_exits_enabled(True)
        mu.ctl_set_exits([0])

        mu.mem_map(0x0, 32 * 1024 * 1024)

        # map 2MB memory for this emulation
        mu.mem_map(0x14000000, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(0x14000000, open("6025dump_ocl_emu.bin", "rb").read())              

        # initialize machine registers
        mu.reg_write(UC_ARM_REG_APSR, 0xFFFFFFFF) #All application flags turned on
   
        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing one instruction at ADDRESS with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)
        
        DEBUG = True
        
        def on_read(mu, access, address, size, value, data):
            if DEBUG:
                print("Read at", hex(address), size, mu.mem_read(address, size))

        def on_write(mu, access, address, size, value, data):
            if DEBUG:
                print("Write at", hex(address), size, hex(value))

        def on_error(mu, access, address, size, value, data):
            if DEBUG or True:
                print("Error at", hex(address), size, hex(value), "in", hex(mu.reg_read(UC_ARM_REG_PC)), "lr", hex(mu.reg_read(UC_ARM_REG_LR)))        

        mu.hook_add(UC_HOOK_MEM_READ, on_read)
        mu.hook_add(UC_HOOK_MEM_WRITE, on_write)
        mu.hook_add(UC_HOOK_MEM_INVALID, on_error)

        # emulate machine code in infinite time
        mu.emu_start(0x14000000, 0x1440000)

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        r0 = mu.reg_read(UC_ARM_REG_R0)
        r1 = mu.reg_read(UC_ARM_REG_R1)
        print(">>> R0 = 0x%x" %r0)
        print(">>> R1 = 0x%x" %r1)                

    except UcError as e:
        print("ERROR: %s" % e)

if __name__ == '__main__':
    test_arm()
