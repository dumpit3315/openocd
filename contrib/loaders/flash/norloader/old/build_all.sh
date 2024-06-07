#!/bin/bash
set -e
#make -B PROJECT=6000loader LDSCRIPT=6000dump_ram.ld 
#make -B PROJECT=6025loader LDSCRIPT=6025dump_ram.ld 
#make -B PROJECT=q6010loader LDSCRIPT=q6010dump_ram.ld 
#make -B PROJECT=q1110loader LDSCRIPT=q1110dump_ram.ld 
make -B PROJECT=anyloader LDSCRIPT=anydump_ram.ld 