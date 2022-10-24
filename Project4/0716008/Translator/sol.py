from pwn import *
# context.arch = 'amd64'
# p = process('./shellcode')
# To connect to tcp server
p = remote('140.113.207.240', 8833)
#shellcode = asm(shellcraft.amd64.linux.sh())

# the code is the reverse order of ascii
p.sendline("n")
p.sendline("n")
p.sendline("<6A;")
p.interactive()
