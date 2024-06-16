#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./all')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./all', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process('./all')
r = start()
#========= exploit here ===================

f = fmtstr_payload(6, {})




#========= interactive ====================
r.interactive()
