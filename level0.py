from pwn import *

host = "vortex.labs.overthewire.org"
port = "5842"

nc = process(["nc", host, port])
to_send = 0
for i in range(4):
    s_uint = nc.recv(numb=4)
    log.info(f"uint: {s_uint}")
    uint = unpack(s_uint)
    log.info(f"uint: {uint}")
    to_send += uint

# input("Send")
nc.send(pack(to_send, 32))
creds = nc.recvall()
log.info(f"creds: {creds}")