from pwn import *

# To connect to tcp server
p = remote('140.113.207.240', 8831)

p.sendline("3735928495")# it is decimal of 0xdeadbeaf
p.sendline("YOUSHALLNOTPASS")
p.interactive()
