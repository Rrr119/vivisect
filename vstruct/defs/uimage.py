'''
Parser objects for the U-Boot legacy uImage file format.

The legacy image format is a 64 byte big-endian header (see "struct
image_header" in the U-Boot sources) followed by an opaque payload.  The
payload may be uncompressed or compressed (gzip/lzma/...); only the header
fields are modeled here.
'''
import struct

import vstruct
from vstruct.primitives import *


IH_MAGIC = 0x27051956
IH_MAGIC_SIZE = 4
IH_NMLEN = 32
IH_HDR_SIZE = 64

# CPU/architecture codes (ih_arch)
IH_ARCH_INVALID = 0
IH_ARCH_ALPHA = 1
IH_ARCH_ARM = 2
IH_ARCH_I386 = 3
IH_ARCH_IA64 = 4
IH_ARCH_MIPS = 5
IH_ARCH_MIPS64 = 6
IH_ARCH_PPC = 7
IH_ARCH_S390 = 8
IH_ARCH_SH = 9
IH_ARCH_SPARC = 10
IH_ARCH_SPARC64 = 11
IH_ARCH_M68K = 12
IH_ARCH_MICROBLAZE = 14
IH_ARCH_NIOS2 = 15
IH_ARCH_BLACKFIN = 16
IH_ARCH_AVR32 = 17
IH_ARCH_ST200 = 18
IH_ARCH_SANDBOX = 19
IH_ARCH_NDS32 = 20
IH_ARCH_OPENRISC = 21
IH_ARCH_ARM64 = 22
IH_ARCH_ARC = 23
IH_ARCH_X86_64 = 24
IH_ARCH_XTENSA = 25
IH_ARCH_RISCV = 26

# Operating system codes (ih_os)
IH_OS_INVALID = 0
IH_OS_OPENBSD = 1
IH_OS_NETBSD = 2
IH_OS_FREEBSD = 3
IH_OS_4_4BSD = 4
IH_OS_LINUX = 5
IH_OS_SVR4 = 6
IH_OS_ESIX = 7
IH_OS_SOLARIS = 8
IH_OS_IRIX = 9
IH_OS_FREEBSD_OLD = 10
IH_OS_TRU64 = 11
IH_OS_PLAN9 = 12
IH_OS_VXWORKS = 13
IH_OS_LYNX = 14
IH_OS_PSOS = 15
IH_OS_QNX = 16
IH_OS_U_BOOT = 17
IH_OS_RTEMS = 18
IH_OS_ARTOS = 19
IH_OS_UNITY = 20
IH_OS_INTEGRITY = 21
IH_OS_OSE = 22
IH_OS_PLAN9_OLD = 23

# Image type codes (ih_type)
IH_TYPE_INVALID = 0
IH_TYPE_STANDALONE = 1
IH_TYPE_KERNEL = 2
IH_TYPE_RAMDISK = 3
IH_TYPE_MULTI = 4
IH_TYPE_FIRMWARE = 5
IH_TYPE_SCRIPT = 6
IH_TYPE_FILESYSTEM = 7
IH_TYPE_FLATDT = 8
IH_TYPE_KWBIMAGE = 9
IH_TYPE_IMXIMAGE = 10
IH_TYPE_UBLIMAGE = 11
IH_TYPE_OMAPIMAGE = 12
IH_TYPE_AISIMAGE = 13
IH_TYPE_KNOLOAD = 14

# Compression type codes (ih_comp)
IH_COMP_NONE = 0
IH_COMP_GZIP = 1
IH_COMP_BZIP2 = 2
IH_COMP_LZMA = 3
IH_COMP_LZO = 4
IH_COMP_LZ4 = 5
IH_COMP_ZSTD = 6


class UImageHeader(vstruct.VStruct):
    '''
    The 64 byte big-endian U-Boot legacy image header.
    '''

    def __init__(self):
        vstruct.VStruct.__init__(self, bigend=True)
        self.ih_magic = v_uint32(bigend=True)
        self.ih_hcrc = v_uint32(bigend=True)
        self.ih_time = v_uint32(bigend=True)
        self.ih_size = v_uint32(bigend=True)
        self.ih_load = v_uint32(bigend=True)
        self.ih_ep = v_uint32(bigend=True)
        self.ih_dcrc = v_uint32(bigend=True)
        self.ih_os = v_uint8(bigend=True)
        self.ih_arch = v_uint8(bigend=True)
        self.ih_type = v_uint8(bigend=True)
        self.ih_comp = v_uint8(bigend=True)
        self.ih_name = v_bytes(IH_NMLEN)

    def getImageName(self):
        return bytes(self.ih_name).split(b'\x00', 1)[0].decode('utf-8', 'replace')


def isUImage(bytez):
    '''
    Return True if the given bytes begin with a U-Boot legacy image header.
    '''
    if len(bytez) < IH_MAGIC_SIZE:
        return False
    return struct.unpack('>I', bytez[:IH_MAGIC_SIZE])[0] == IH_MAGIC
